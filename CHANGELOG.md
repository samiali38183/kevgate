# Changelog

## 0.1.1 - 2026-11-11

Review round after 0.1.0. Every item was checked by running the tests or the workflow.

- Tests that kill six mutants the suite had missed (early-exit and non-constant-time key comparison, `BEGIN` instead of `BEGIN IMMEDIATE`, last-chunk-only body size count, CSV merge taking the minimum CVSS, upsert skipping EPSS). Tests 227 to 277, coverage 99.92% with branches.
- Auth-failure counters now exist at 0 from startup, so the alert sees the first event after a restart.
- `/readyz` also checks storage headroom, a rolled-back write and a cached integrity probe.
- Failed authentication is rate limited per source address before any key is checked, and logged with the client address and key id, never the key. `X-Forwarded-For` is honored only for peers listed in `KEVGATE_TRUSTED_PROXIES`.
- Hash-locked `requirements.lock` is committed and used by CI; Dependabot and a weekly freshness check cover it.
- A `terraform test` pins the GitHub OIDC trust policy to the exact repository and branch and runs in CI.
- Docs reworded, with a section on what is unused or unproven and what would change for production.

## 0.1.0 - 2026-11-10

First release: API, auth, rate limiting, JSON logs and metrics, hardened container, Helm chart, Terraform validated against LocalStack, and the GitHub Actions security pipeline. Release image signed with cosign (keyless) with SBOM and provenance attestations.
