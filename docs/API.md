# kevgate API reference

Base URL in the examples: `http://localhost:8000`. All request and response bodies are JSON unless noted.

## Conventions

Authentication: `Authorization: Bearer <key>` on every endpoint except `/healthz`, `/readyz` and `/metrics`. When the server runs in dev mode without a key file, auth is disabled and every caller is treated as `anonymous` with all scopes.

Order of checks on a protected endpoint:

1. No header, wrong scheme, or a token over 256 characters: `401` with `WWW-Authenticate: Bearer realm="kevgate"`.
2. Token does not match any stored hash: `401` with `error="invalid_token"`.
3. Rate limit exceeded for this key: `429` with `Retry-After: <seconds>`.
4. Key is valid but lacks the scope: `403`.

Body limits (all endpoints): more than 1 MiB, declared or streamed, returns `413`. A `Content-Length` that is not a number returns `400`.

Validation errors return `422` with this shape. Submitted values are never echoed back:

```json
{"detail": [{"loc": ["body", 0, "cvss"], "msg": "Input should be less than or equal to 10", "type": "less_than_equal"}]}
```

Every response carries `X-Request-ID` (your value if you send a valid one, `[A-Za-z0-9._-]{1,64}`, otherwise a generated one), plus `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin` and `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`.

## Finding object

| Field | Type | Rules |
|---|---|---|
| `cve` | string | `CVE-YYYY-NNNN...` (4 to 19 digits), case-insensitive, stored upper-case |
| `asset` | string | 1 to 128 characters, no control characters |
| `acr` | integer | 1 to 8, asset criticality |
| `cvss` | number | 0 to 10 |
| `epss` | number | 0 to 1 |
| `days_open` | integer | 0 to 36500 |

Types are strict: `"5"` is not accepted for `acr`, `true` is not an integer, NaN and infinity are rejected, and unknown fields are rejected.

Scored findings (queue items) add `kev` (boolean) and `risk` (0 to 100, one decimal).

## GET /healthz

No auth. Liveness only.

```bash
curl -s localhost:8000/healthz
```
```json
{"status": "ok"}
```

## GET /readyz

No auth. Checks that the database answers `SELECT 1` and that the KEV catalog loaded with at least one entry.

```json
{"status": "ready", "checks": {"db": "ok", "kev": "ok"}}
```

`503` with `"status": "not ready"` and the failing check set to `"fail"` otherwise.

## GET /metrics

No auth. Prometheus text exposition format. kevgate metrics:

| Metric | Type | Labels |
|---|---|---|
| `kevgate_http_requests_total` | counter | `method`, `route` (template such as `/findings/{cve}`, or `unmatched`), `status` |
| `kevgate_http_request_duration_seconds` | histogram | `method`, `route` |
| `kevgate_findings_ingested_total` | counter | `source` (`json` or `csv`) |
| `kevgate_auth_failures_total` | counter | `reason` (`missing`, `invalid`, `forbidden`) |
| `kevgate_rate_limited_total` | counter | |
| `kevgate_kev_entries` | gauge | |

Process and platform collectors are included as well.

## POST /findings

Scope `findings:write`. Body is a JSON array of 1 to 1000 finding objects. The whole batch is validated first and written in one transaction, so a single bad item means `422` and nothing is stored. Existing (cve, asset) pairs are updated in place.

```bash
curl -s -X POST localhost:8000/findings -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  -d '[{"cve":"CVE-2021-44228","asset":"web-01","acr":7,"cvss":10.0,"epss":0.97,"days_open":12}]'
```
```json
{"accepted": 1}
```

Status: `201`, `401`, `403`, `413`, `422`, `429`.

## POST /findings/import

Scope `findings:write`. Body is a CSV export sent with `Content-Type: text/csv` (also accepted: `application/csv`, `text/plain`). UTF-8, a leading BOM is fine.

Query: `default_acr` (1 to 8, default 4) is used when the file has no ACR column.

Recognised headers (case-insensitive, first non-empty wins):

| Field | Headers |
|---|---|
| cve (required) | `CVE`, `CVEs`. A cell may hold several IDs separated by commas or spaces. |
| asset (required) | `Host`, `Asset`, `Asset Name`, `DNS Name`, `NetBIOS Name`, `IP Address` |
| cvss (required) | `CVSS v3.0 Base Score`, `CVSS V3 Base Score`, `CVSS3 Base Score`, `CVSS v2.0 Base Score`, `CVSS V2 Base Score`, `CVSS Base Score`, `CVSS` |
| epss | `EPSS`, `EPSS Score` (default 0.0) |
| acr | `ACR`, `Asset Criticality Rating` (must be 1 to 8) |
| days_open | `Days Open`, `Age`, or computed from `First Discovered` / `First Seen` / `First Found` (ISO 8601 or `Apr 13, 2024 08:15:00 UTC`) |

Rules: rows without a CVE are informational and counted as skipped. A row with a CVE but a bad value fails the whole file with `422` and up to 20 row messages. Duplicate (cve, asset) pairs, such as the same plugin on several ports, are merged keeping the highest cvss, epss, acr and days_open. More than 1000 findings after merging returns `422`; use `kevgate import-csv` for large files.

```bash
curl -s -X POST 'localhost:8000/findings/import?default_acr=6' -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: text/csv' --data-binary @tests/fixtures/tenable_export.csv
```
```json
{"accepted": 5, "skipped": 2}
```

Row error example:

```json
{"detail": {"error": "1 invalid row(s); nothing imported", "rows": ["line 3: cvss 'eleven' is not a number"]}}
```

Status: `201`, `401`, `403`, `413`, `415`, `422`, `429`.

## GET /queue

Scope `queue:read`.

| Query | Default | Rules |
|---|---|---|
| `limit` | 10 | 1 to 100 |
| `kev_only` | false | only KEV findings |
| `asset` | none | exact asset name |

Ordering: `risk` desc, then KEV first, then `epss` desc, then `cvss` desc, then cve and asset ascending.

```bash
curl -s 'localhost:8000/queue?limit=2&kev_only=true' -H "Authorization: Bearer $KEY"
```
```json
[
  {"cve": "CVE-2021-44228", "asset": "web-01", "acr": 7, "cvss": 10.0, "epss": 0.97, "days_open": 12, "kev": true, "risk": 96.5},
  {"cve": "CVE-2021-44228", "asset": "10.0.0.5", "acr": 6, "cvss": 10.0, "epss": 0.97, "days_open": 1795, "kev": true, "risk": 93.5}
]
```

## GET /findings/{cve}

Scope `queue:read`. Every asset that has the CVE, scored and ranked. `404` if none, `422` if the path is not a CVE ID.

```bash
curl -s localhost:8000/findings/CVE-2021-34527 -H "Authorization: Bearer $KEY"
```
```json
[{"cve": "CVE-2021-34527", "asset": "dc-01", "acr": 6, "cvss": 8.8, "epss": 0.94, "days_open": 1952, "kev": true, "risk": 90.6}]
```

## DELETE /findings/{cve}?asset=

Scope `admin`. `asset` is required. `204` on success, `404` if that (cve, asset) pair does not exist.

```bash
curl -s -X DELETE 'localhost:8000/findings/CVE-2023-12345?asset=web-01' -H "Authorization: Bearer $ADMIN_KEY"
```

## GET /stats

Scope `queue:read`. Means are `null` when a group is empty. `top_assets` lists up to five assets by summed risk.

```json
{
  "total": 3,
  "kev": {"count": 2, "mean_cvss": 10.0, "mean_epss": 0.8, "mean_days_open": 20.0},
  "non_kev": {"count": 1, "mean_cvss": 4.0, "mean_epss": 0.1, "mean_days_open": 100.0},
  "top_assets": [
    {"asset": "web-01", "findings": 2, "kev_findings": 1, "total_risk": 113.6},
    {"asset": "fw-01", "findings": 1, "kev_findings": 1, "total_risk": 85.4}
  ]
}
```
