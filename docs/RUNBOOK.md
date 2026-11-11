# Runbook

One section per alert in `deploy/monitoring/kevgate-rules.yaml`, then two playbooks. Alert
annotations link here by anchor. Commands assume namespace `kevgate` and a release named `kevgate`.

```bash
export NS=kevgate
alias k="kubectl -n $NS"
```

First look for any alert:

```bash
k get pods,svc,endpoints,pvc,networkpolicy
k describe pod -l app.kubernetes.io/name=kevgate | tail -40
k logs -l app.kubernetes.io/name=kevgate --tail=200      # JSON lines
k get events --sort-by=.lastTimestamp | tail -20
```

Logs are JSON, one object per line, with fields `ts`, `level`, `msg`, and for requests `method`, `path`, `route`, `status`, `latency_ms`, `request_id`, `key_id`. Headers and bodies are never logged. `| jq -c 'select(.level=="ERROR")'` works.

## KevgateHigh5xxRatio

Severity critical. More than 5% of requests failed with 5xx for 5 minutes.

1. Logs: `k logs -l app.kubernetes.io/name=kevgate --tail=500 | jq -c 'select(.status>=500)'`. Look for a repeating exception.
2. Storage: `k exec deploy/kevgate -- python -c "import os;s=os.statvfs('/data');print(s.f_bavail*s.f_frsize//2**20,'MiB free')"`. A full `/data` makes SQLite writes fail. A full volume is the most likely cause.
3. Readiness: `curl` through a port-forward (`k port-forward svc/kevgate 8000:8000`) to `/readyz`; the body says which check failed (`db`, `storage` or `kev`).
4. Recent change: `helm history kevgate -n $NS`.

Remediation: if the change is recent, `helm rollback kevgate <revision> -n $NS`. If the volume is
full, expand the PVC (needs a storage class that allows it) or restore from a copy of
`/data/kevgate.db`. A pod restart (`k rollout restart deploy/kevgate`) is acceptable once logs are
saved.

## KevgateNotReady

Severity critical. No pod is Ready, so the Service has no endpoints.

1. `k get pods` then `k describe pod <pod>`: look at probe failures and the last state.
2. `k logs <pod> --previous` if it is crash-looping. A prod start that cannot read the key file exits immediately with a config error.
3. `/readyz` failing `kev`: the KEV catalog did not load. Check `KEVGATE_KEV_PATH` and the optional ConfigMap (`k get cm`).
4. `/readyz` failing `db` or `storage`: check the PVC is `Bound`, the mount is writable by UID 10001 (`fsGroup`) and has free space (`storage` fails under 1 MiB free). `db` also fails if a write cannot be taken (read-only volume, lock held) or `PRAGMA quick_check` finds damage; restore from a copy of `/data/kevgate.db` in that case.
5. Pending pod: `k describe pod` shows scheduling or volume attach problems.

Remediation: fix the cause named above. If a bad Secret was mounted, correct it and
`k rollout restart deploy/kevgate`.

## KevgateScrapeMissing

Severity warning. Prometheus has no successful scrape of `job="kevgate"`.

1. Is the pod up? If not, the not-ready alert will usually fire too.
2. Is it the NetworkPolicy? With `networkPolicy.ingress.metrics.enabled=false` Prometheus cannot reach port 8000. Enable it and match `namespaceLabels` and `podLabels` to your Prometheus.
3. ServiceMonitor labels must match the Operator's selector (`release: kube-prometheus-stack` by default): `kubectl get servicemonitor -A`.

## KevgateKevCatalogEmpty

Severity critical. `kevgate_kev_entries` is 0 for 5 minutes. Every finding would be scored as not
exploited, which silently produces a wrong remediation queue.

1. `k logs -l app.kubernetes.io/name=kevgate | jq -c 'select(.msg|test("KEV"))'`.
2. Check the file: `k exec deploy/kevgate -- python -c "import json;print(len(json.load(open('/etc/kevgate/kev/known_exploited_vulnerabilities.json'))['vulnerabilities']))"` when a ConfigMap feed is used; the bundled snapshot is inside the package otherwise.
3. Re-supply the feed (`kevgate kev-refresh` run outside the pod, load the result into the ConfigMap), then `k rollout restart deploy/kevgate`.

## KevgateHighLatencyP95

Severity warning. p95 over 500 ms on a route for 10 minutes.

1. Which route? The alert label says. `/queue` cost grows with the number of findings; `/findings` with batch size.
2. CPU throttling: `k top pod`, compare with the 500m limit. Memory near 256Mi suggests swapping behaviour in the SQLite page cache.
3. Request rate: the dashboard "Request rate by status" panel. A traffic spike is also the rate-limit alert's job.

Remediation: raise limits, reduce batch size on the client, or plan the move to Postgres if the
data set has outgrown SQLite.

## KevgateAuthFailureSpike

Severity warning. More than 25 auth failures in 5 minutes for one `reason`.

| Reason | Meaning | First move |
|---|---|---|
| `missing` | no `Authorization` header | A misconfigured client or a scanner hitting the service. Usually benign. |
| `invalid` | key not in the key file | Key guessing, or a revoked key still deployed in a client. |
| `forbidden` | valid key, wrong scope | A client calling an endpoint it has no scope for. See the leak playbook. |

1. Pattern: every 401, 403 and throttled 429 is logged by `kevgate.auth` with the client address and never the key: `k logs -l app.kubernetes.io/name=kevgate --tail=2000 | jq -r 'select(.logger=="kevgate.auth") | "\(.reason) \(.client_ip) \(.key_id)"' | sort | uniq -c | sort -rn | head`. The address is the direct peer; behind a reverse proxy it is the proxy's address unless `KEVGATE_TRUSTED_PROXIES` lists it. `kevgate_auth_throttled_total` counts requests refused because a source exceeded `KEVGATE_AUTH_FAIL_LIMIT_PER_MIN`.
2. NetworkPolicy should already limit who can connect at all. A failure from an address that should not be able to connect means the policy is not enforced; check the CNI.
3. If the pattern is `invalid` from one source at a steady rate, treat it as probing and note the source.

## KevgateForbiddenScopeUse

Severity warning, fires on a single event. A valid key was used outside its scopes. Either a
client bug or someone exploring what a stolen key can do. Treat as a possible leak until the
client is identified: follow "Suspected API key leak" step 1.

## KevgateRateLimitSpike

Severity warning. Many 429 responses.

1. Is it one client? The `key_id` field on the 429 lines shows which key: `k logs -l app.kubernetes.io/name=kevgate --tail=2000 | jq -r 'select(.status==429) | .key_id' | sort | uniq -c`. A client in a retry loop is common.
2. Is the limit too low for legitimate use? `app.rateLimitPerMin` is per client; raise via `helm upgrade --reuse-values --set app.rateLimitPerMin=...` after checking the source is legitimate.
3. If the source is unknown, go to the leak playbook.

## Suspected API key leak

Use when a key appears in a repo, a log, a chat, a CI artifact, or the forbidden-scope alert
fires from an unexpected client.

1. **Scope the key.** The key id is the first field of its line in the key file. Which scopes? `findings:write` lets someone inject false findings that reorder the queue; `queue:read` exposes the remediation list, which is a map of the organisation's unpatched weaknesses.
2. **Contain.** Revoke now, investigate after:
   ```bash
   k get secret kevgate-api-keys -o jsonpath='{.data.api_keys}' | base64 -d > /tmp/keys.current
   grep -v '^<key_id>:' /tmp/keys.current > /tmp/keys.new          # remove the leaked line
   k create secret generic kevgate-api-keys --from-file=api_keys=/tmp/keys.new --dry-run=client -o yaml | k apply -f -
   k rollout restart deploy/kevgate                                  # key file is read at start
   shred -u /tmp/keys.current /tmp/keys.new
   ```
3. **Issue a replacement** for the legitimate client: `kevgate keygen --scope <scopes> --key-id <new-id>`. Give the client the key; add only the hash line to the Secret.
4. **Find the exposure window.** From the log: requests with that `key_id` between when it was created and when it was revoked, by `path` and `status`, and `POST /findings` volume. Failed requests log `client_ip` (see KevgateAuthFailureSpike); successful ones do not, so correlate timestamps with CNI or load balancer logs for the addresses that used the key successfully. Compare the queue with the last known good scanner import.
5. **Check data integrity.** If the leaked key had `findings:write`, look for findings you did not import. Re-import the last good scanner export into a clean database if in doubt (`kevgate import-csv`), because injected findings can bury real ones.
6. **Remove the source.** Delete the key from wherever it leaked (git history rewrite plus rotate, delete the log, purge the artifact). Rotation already happened; do the cleanup to stop the next leak.
7. **Write it up.** Root cause (why did a plaintext key leave the client?), time to revoke, data touched, fix. Add a gitleaks rule if the key format was missed.

Keys are stored as SHA-256 hashes, so a stolen Secret does not give the attacker usable keys.
That is why step 2 is a removal, not a hunt for plaintext.

## Pod compromise

Use when the exec, ephemeral container or privileged-pod Sigma rules fire without a matching
change ticket, or the pod shows unexpected processes or outbound traffic.

1. **Confirm and preserve.** Identify who and when from the audit event (`user.username`, `sourceIPs`, `requestReceivedTimestamp`). Do not delete the pod yet.
   ```bash
   k get pod <pod> -o yaml > pod-<ts>.yaml
   k logs <pod> --all-containers > pod-<ts>.log
   ```
2. **Isolate without destroying evidence.** Label the pod so it leaves the Service and add a deny-all policy, then keep it for forensics:
   ```bash
   k label pod <pod> app.kubernetes.io/instance=quarantine --overwrite
   k apply -f - <<'EOF'
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata: {name: quarantine-deny-all}
   spec:
     podSelector: {matchLabels: {app.kubernetes.io/instance: quarantine}}
     policyTypes: [Ingress, Egress]
   EOF
   ```
   The Deployment replaces the removed pod with a clean one. (The chart already denies egress except DNS, so exfiltration over the network is limited to DNS.)
3. **Assess what the pod could reach.** It has no service account token, no Kubernetes permissions, and a read-only root. Realistic exposure: the SQLite data on `/data`, the key-file hashes, and anything on the node reachable through a container escape. Check `k get pod <pod> -o jsonpath='{.spec.nodeName}'` and whether the node's other workloads need review.
4. **Treat secrets as exposed.** Hashes only are in the pod, but rotate all keys anyway (leak playbook steps 2 and 3) if the attacker had a shell: they could have captured plaintext keys from request headers in memory.
5. **Find how they got in.** Audit log for the user or token that issued the exec; check whether it is a human, a CI service account or a stolen token. Rotate that credential. Check for RBAC changes (`rolebindings` events are logged at RequestResponse).
6. **Recover.** Deploy a known-good image by digest (`helm upgrade --set image.digest=sha256:...`) after verifying its signature with `cosign verify` (see `docs/PIPELINE.md`). Restore `/data` from a backup taken before the incident if integrity is in doubt.
7. **Clean up.** Delete the quarantined pod and the quarantine policy once the evidence is copied off-cluster. Add or tighten the detection that was late.

Pointers: exec into the pod is MITRE ATT&CK T1609, escape to the host is T1611, secret
collection is T1552.007. The rules are in `deploy/detections/`.
