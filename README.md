# kevgate

[![ci](https://github.com/samiali38183/kevgate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/samiali38183/kevgate/actions/workflows/ci.yml)
[![security](https://github.com/samiali38183/kevgate/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/samiali38183/kevgate/actions/workflows/security.yml)
[![deploy-kind](https://github.com/samiali38183/kevgate/actions/workflows/deploy-kind.yml/badge.svg?branch=main)](https://github.com/samiali38183/kevgate/actions/workflows/deploy-kind.yml)
[![terraform](https://github.com/samiali38183/kevgate/actions/workflows/terraform.yml/badge.svg?branch=main)](https://github.com/samiali38183/kevgate/actions/workflows/terraform.yml)

kevgate is a small FastAPI service that takes scanner findings and returns a fix-first queue. A scanner export is usually sorted by CVSS, which puts a theoretical 9.8 above a 7.5 that attackers are using today. kevgate ranks by whether the CVE is in CISA's Known Exploited Vulnerabilities (KEV) catalog first, then asset criticality, EPSS and CVSS.

The ranking is the easy part. I wanted to see what it takes to run even a small security service properly, so most of the repository is the surrounding work: hashed API keys with scopes, rate limiting, a locked-down container, a Helm chart, a threat model, and a CI pipeline that scans the code and image and signs what it publishes. The same score is also used in [kevgate-admit](https://github.com/samiali38183/kevgate-admit), a Kubernetes admission webhook, and in [kev-risk-prioritization](https://github.com/samiali38183/kev-risk-prioritization), the standard-library case study of the idea.

![Two panels. Left: ranking weights read from the code, 0.40 for being in CISA's Known Exploited Vulnerabilities list, 0.25 asset importance, 0.20 exploit likelihood (EPSS), 0.20 severity (CVSS). Right: 12 checks all green on the latest main run, including 298 tests at 99.93% branch coverage, Semgrep, Bandit, gitleaks, pip-audit, checkov, Trivy, a kind cluster deploy with NetworkPolicy and Pod Security checks, and an OWASP ZAP scan.](docs/img/hero.png)

## Try it

```bash
python -m venv .venv && source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e ".[dev]" && pytest -q                    # 298 tests
KEVGATE_DB_PATH=./kevgate.db uvicorn kevgate.main:app --port 8000      # dev mode: auth off, a warning is logged
```

```
$ curl -s -X POST localhost:8000/findings -H 'Content-Type: application/json' -d '[
    {"cve":"CVE-2021-44228","asset":"web-01","acr":7,"cvss":10.0,"epss":0.97,"days_open":12},
    {"cve":"CVE-2023-99999","asset":"db-01","acr":8,"cvss":9.8,"epss":0.02,"days_open":30}]'
{"accepted":2}
$ curl -s 'localhost:8000/queue?limit=3'
[{"cve":"CVE-2021-44228","asset":"web-01",...,"kev":true,"risk":96.5},
 {"cve":"CVE-2023-99999","asset":"db-01",...,"kev":false,"risk":42.9}]
```

The log4j CVE is in the bundled sample KEV catalog, so it outranks a CVSS 9.8 on a more critical asset. The second CVE is made up. With `KEVGATE_ENV=prod` the service refuses to start without a key file.

## Real-data run

I ran Trivy on four old public container images (`vulnerables/web-dvwa`, `mysql:5.6`, `tomcat:8.5.50`, `httpd:2.4.49`) and loaded the result with the live KEV catalog and EPSS scores. The 1,112 findings include 10 on the KEV list. Sorted by CVSS alone, 0.9 of those 10 are expected in the top 50 (averaged over random tie orders); kevgate puts all 10 in the top 10. That is partly because KEV is a score input. It is also one run, and the weights are my own choice and have not been checked against remediation outcomes.

![Left: for each of the 10 exploited findings, the grey marker shows where a CVSS-only sort puts it, between about rank 2 and rank 610, and the red dot shows kevgate's rank, 1 to 10. Right: exploited findings found in the top 10, 25, 50 and 100 positions, CVSS only 0.15, 0.4, 0.86 and 1.75, kevgate 10 each.](docs/img/real-run.png)

The inputs are committed with hashes and sources, so the figure can be redrawn without a network:

```bash
pip install -e ".[dev]" matplotlib pillow
python scripts/real_run_analyze.py && python scripts/make_real_run.py
```

Method, per-ordering tables and the circularity of the run are in [docs/real-run](docs/real-run/README.md). The run added `kevgate import-trivy`, which loads a Trivy JSON report directly.

## What is in the repository

- `src/kevgate/`: the service (routes, auth, rate limiting, SQLite repository, CSV and Trivy importers, KEV refresh).
- `deploy/`, `infra/terraform/`: Helm chart, kind smoke tests, Prometheus rules, and Terraform for AWS resources.
- `docs/`: [reference](docs/REFERENCE.md) (scoring, API summary, configuration, security controls, test and scan results), [threat model](docs/THREAT_MODEL.md), [pipeline](docs/PIPELINE.md), [deployment](docs/DEPLOYMENT.md), [runbook](docs/RUNBOOK.md).

The `v0.1.1` image on GHCR is signed with cosign (keyless) and carries provenance and SBOM attestations; `gh attestation verify` passed from a machine outside the workflow.

## Design

- Request flow: `uvicorn kevgate.main:app` builds the app from environment variables (`src/kevgate/config.py`). Each request passes through two raw ASGI middlewares in `src/kevgate/middleware.py` (a body size limit of 1 MiB, then request id, security headers, one JSON access log line and HTTP metrics), then a per-route dependency in `src/kevgate/app.py` (`require(scope)`) that throttles sources with repeated auth failures, authenticates the bearer token, applies the rate limit, and checks the scope.
- Endpoints (`src/kevgate/app.py`): `POST /findings` (JSON, at most 1000 findings per request), `POST /findings/import` (CSV), `GET /queue`, `GET /findings/{cve}`, `DELETE /findings/{cve}`, `GET /stats`, plus `/healthz`, `/readyz` and `/metrics`. The OpenAPI docs are only served when `KEVGATE_ENV` is not `prod`.
- Scoring: `src/kevgate/scoring.py` computes `risk = 100 * (0.40*kev + 0.25*acr/8 + 0.20*epss + 0.20*cvss/10) / 1.05`, rounded to one decimal. `rank()` sorts by risk, then KEV first, then EPSS, then CVSS, then CVE and asset for a deterministic order. Scores are computed on read, not stored.
- Data sources: the KEV catalog is a local JSON file, by default the bundled `src/kevgate/data/kev_sample.json`. `kevgate kev-refresh` (`src/kevgate/kev.py`, `src/kevgate/cli.py`) downloads and validates the CISA feed; the API process itself makes no outbound calls. EPSS is supplied by the caller per finding, or for `kevgate import-trivy` from a FIRST `epss_scores` CSV (`src/kevgate/trivy_import.py`); CVEs missing from it score 0.
- Storage: one SQLite database behind `FindingRepository` in `src/kevgate/db.py`, a single connection guarded by a lock, WAL mode, append-only migrations tracked with `PRAGMA user_version`, and an upsert keyed on `(cve, asset)`. All SQL statements are literal constants.
- Authentication (`src/kevgate/auth.py`): keys are `kvg_` plus 32 random bytes; the key file holds `key_id:scopes:sha256hex`, compared with `hmac.compare_digest`. Scopes are `findings:write`, `queue:read` and `admin`. Without a key file the service runs in dev mode with every caller treated as admin and logs a warning; with `KEVGATE_ENV=prod` it refuses to start.
- Rate limiting (`src/kevgate/ratelimit.py`): an in-process token bucket per key id (per source IP when auth is off), 120 requests per minute by default, and a separate bucket for failed authentication attempts (20 per minute). `X-Forwarded-For` is honoured only from `KEVGATE_TRUSTED_PROXIES` (`src/kevgate/clientip.py`).
- Container (`Dockerfile`): two-stage build from a digest-pinned `python:3.12-slim` image, dependencies installed from `requirements.lock` with `--require-hashes`, pip removed from the runtime image, non-root UID/GID 10001, `/data` as the only writable path, `KEVGATE_ENV=prod` baked in.
- Deployment (`deploy/helm/kevgate/`): one-replica Deployment with `runAsNonRoot`, read-only root filesystem, all capabilities dropped, RuntimeDefault seccomp, no service-account token mount, startup/liveness/readiness probes, a NetworkPolicy restricting ingress to labelled client pods and egress to DNS (and optionally HTTPS for the KEV feed), and optional PVC, PDB, HPA and ServiceMonitor. `deploy/kind/` and `deploy/smoke.sh` run it on a kind cluster in CI; `deploy/monitoring/` holds Prometheus rules and a Grafana dashboard; `deploy/detections/` holds Sigma rules.
- Terraform (`infra/terraform/modules/kevgate/`): an ECR repository with lifecycle and repository policies, a KMS key, S3 buckets for reports and access logs (versioned, encrypted, public access blocked), and IAM roles for GitHub Actions via OIDC and for the workload. It is applied against LocalStack in CI (`infra/terraform/localstack/`); the `aws/` root is only formatted and validated there, never applied.

## Limits

It runs as one replica on SQLite, which is a limitation and not a production design; [DEPLOYMENT.md](docs/DEPLOYMENT.md) lists what would change. Kubernetes manifests are tested on a kind cluster in CI, and the Terraform is validated against LocalStack only. Nothing is deployed to a real AWS account, and the service does not call AWS.

## License

MIT
