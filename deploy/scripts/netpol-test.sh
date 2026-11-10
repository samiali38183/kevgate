#!/usr/bin/env bash
# Prove the NetworkPolicy and Pod Security admission actually enforce, not just render.
#   1. a pod labelled kevgate-client=true reaches the service        (expect success)
#   2. an unlabelled pod in the same namespace cannot                (expect timeout)
#   3. the kevgate pod cannot open an outbound HTTPS connection      (expect failure, egress deny)
#   4. a privileged pod is rejected by PSS restricted admission      (expect Forbidden)
# Steps 3 and 4 also produce the audit events that deploy/scripts/audit-check.sh looks for.
# Requires a NetworkPolicy-enforcing CNI (Calico in CI).
set -euo pipefail

NS="${NS:-kevgate}"
SVC="${SVC:-kevgate}"
CURL_IMAGE="curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93"

client_pod() { # name labels-json
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: ${NS}
  labels: $2
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10002
    runAsGroup: 10002
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: curl
      image: ${CURL_IMAGE}
      args: ["-sS", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", "http://${SVC}.${NS}.svc:8000/healthz"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: ["ALL"]}
      resources:
        requests: {cpu: 10m, memory: 16Mi}
        limits: {cpu: 100m, memory: 32Mi}
EOF
}

wait_done() { # pod -> prints phase
  local phase=""
  for _ in $(seq 1 60); do
    phase="$(kubectl -n "${NS}" get pod "$1" -o jsonpath='{.status.phase}')"
    [[ "${phase}" == Succeeded || "${phase}" == Failed ]] && break
    sleep 2
  done
  echo "${phase}"
}

kubectl -n "${NS}" delete pod np-allowed np-denied --ignore-not-found --wait=true >/dev/null

client_pod np-allowed '{"kevgate-client": "true"}' | kubectl apply -f -
client_pod np-denied '{"app": "not-a-client"}' | kubectl apply -f -

allowed="$(wait_done np-allowed)"; denied="$(wait_done np-denied)"
echo "np-allowed: ${allowed} ($(kubectl -n "${NS}" logs np-allowed 2>/dev/null || true))"
echo "np-denied : ${denied} ($(kubectl -n "${NS}" logs np-denied 2>&1 | tail -n 1 || true))"
[[ "${allowed}" == Succeeded ]] || { echo "FAIL: labelled client could not reach kevgate"; exit 1; }
[[ "${denied}" == Failed ]]     || { echo "FAIL: unlabelled pod reached kevgate; NetworkPolicy not enforced"; exit 1; }
echo "ok   ingress: labelled client allowed, unlabelled pod blocked"

# Egress: the app container has python but no curl. The probe prints BLOCKED only when the
# connection attempt itself fails, so a broken exec cannot pass as "blocked".
pod="$(kubectl -n "${NS}" get pod -l app.kubernetes.io/name=kevgate -o jsonpath='{.items[0].metadata.name}')"
egress="$(kubectl -n "${NS}" exec "${pod}" -- python -c '
import socket
try:
    socket.create_connection(("1.1.1.1", 443), timeout=5)
    print("CONNECTED")
except OSError:
    print("BLOCKED")
')"
[[ "${egress}" == BLOCKED ]] || { echo "FAIL: egress probe returned '${egress}'"; exit 1; }
echo "ok   egress: kevgate pod cannot reach the internet on 443"

# Pod Security admission: privileged pod must be refused at the API server.
if out="$(kubectl -n "${NS}" run psa-probe --image="${CURL_IMAGE}" --restart=Never \
     --overrides='{"spec":{"containers":[{"name":"psa-probe","image":"'"${CURL_IMAGE}"'","securityContext":{"privileged":true}}]}}' 2>&1)"; then
  kubectl -n "${NS}" delete pod psa-probe --ignore-not-found >/dev/null
  echo "FAIL: privileged pod was admitted"; exit 1
fi
grep -qi 'forbidden' <<<"${out}" || { echo "FAIL: unexpected error: ${out}"; exit 1; }
echo "ok   admission: privileged pod rejected by PSS restricted"

kubectl -n "${NS}" delete pod np-allowed np-denied --ignore-not-found >/dev/null
echo "netpol-test: all checks passed"
