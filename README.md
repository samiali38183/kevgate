# kevgate

A small vulnerability-intake service: scan findings go in, a remediation queue ranked by known
exploitation (CISA KEV), exploit likelihood (EPSS), severity (CVSS) and asset criticality comes out.

The service is deliberately simple. The point of this repo is shipping it the way a production
engineering org would: tested, containerized, deployed to Kubernetes, provisioned with Terraform,
gated by a security pipeline, observable, and threat-modeled.

## Architecture (target, end of M8)

```
 scanner export (CSV/JSON) ─► POST /findings ─┐
                                              ▼
                    ┌──────────── kevgate API (FastAPI, non-root container) ───────────┐
                    │ auth (hashed API keys) · validation · scoring · JSON logs · /metrics│
                    └───────────────┬───────────────────────────────┬──────────────────┘
                                    ▼                               ▼
                         Postgres or SQLite (M2+)        Prometheus ─► alert (M7)
 Kubernetes (kind, Helm chart, NetworkPolicy, RBAC) · Terraform (AWS/LocalStack: ECR, IAM, S3)
 CI: ruff · mypy · pytest · sinkline + Semgrep · pip-audit · Trivy · checkov · ZAP baseline
```

## Milestones
Each milestone lands as a pull request into `main` with a description, a self-review and green CI.

| # | Milestone | Spec |
|---|---|---|
| M1 | API core: findings in, ranked queue out, validation, tests | [milestones/M1.md](milestones/M1.md) |
| M2 | Auth (hashed scoped API keys), rate limiting, JSON logs, STRIDE threat model | written after M1 |
| M3 | Hardened Docker image + Trivy scan | written after M2 |
| M4 | Helm chart on kind: securityContext, limits, NetworkPolicy, RBAC | |
| M5 | GitHub Actions security pipeline + proof PR that the gate blocks a planted bug | |
| M6 | Terraform: ECR, least-privilege IAM, S3 (LocalStack first) | |
| M7 | Metrics + an alert that fires + incident write-up | |
| M8 | kubescape/kube-bench hardening + Sigma rules on K8s audit logs | |

## Status
M1 not started. See `SETUP.md` for tools.
