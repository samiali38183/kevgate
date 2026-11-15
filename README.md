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

## Limits

It runs as one replica on SQLite, which is a limitation and not a production design; [DEPLOYMENT.md](docs/DEPLOYMENT.md) lists what would change. Kubernetes manifests are tested on a kind cluster in CI, and the Terraform is validated against LocalStack only. Nothing is deployed to a real AWS account, and the service does not call AWS.

## License

MIT
