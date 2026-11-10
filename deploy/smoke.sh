#!/usr/bin/env bash
# Black-box smoke test against a running kevgate.
#
#   BASE_URL         default http://127.0.0.1:8000
#   KEVGATE_API_KEY  plaintext key with findings:write and queue:read (required)
#
# Exits non-zero on the first failed check. Needs curl and jq.
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
: "${KEVGATE_API_KEY:?set KEVGATE_API_KEY to a key with findings:write,queue:read}"

pass=0
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { pass=$((pass + 1)); echo "ok   $*"; }

# status METHOD PATH [curl args...] -> prints HTTP status, body goes to $BODY
BODY="$(mktemp)"
trap 'rm -f "${BODY}"' EXIT
status() {
  local method="$1" path="$2"; shift 2
  curl -sS -o "${BODY}" -w '%{http_code}' --max-time 10 -X "${method}" "$@" "${BASE_URL}${path}"
}
auth=(-H "Authorization: Bearer ${KEVGATE_API_KEY}")
json=(-H "Content-Type: application/json")

# 1. Probes, no auth.
[[ "$(status GET /healthz)" == 200 ]] || fail "/healthz not 200"
jq -e '.status == "ok"' "${BODY}" >/dev/null || fail "/healthz body: $(cat "${BODY}")"
ok "GET /healthz 200 {status: ok}"

[[ "$(status GET /readyz)" == 200 ]] || fail "/readyz not 200: $(cat "${BODY}")"
ok "GET /readyz 200"

# 2. Auth is enforced on the data endpoints.
[[ "$(status GET /queue)" == 401 ]] || fail "GET /queue without key should be 401"
ok "GET /queue without key -> 401"

[[ "$(status POST /findings "${json[@]}" --data '[]')" == 401 ]] || fail "POST /findings without key should be 401"
ok "POST /findings without key -> 401"

[[ "$(status GET /queue -H 'Authorization: Bearer not-a-real-key')" == 401 ]] || fail "bad key should be 401"
ok "GET /queue with wrong key -> 401"

# 3. Validation: one bad item rejects the whole batch.
bad='[{"cve":"not-a-cve","asset":"x","acr":5,"cvss":5.0,"epss":0.1,"days_open":1}]'
[[ "$(status POST /findings "${auth[@]}" "${json[@]}" --data "${bad}")" == 422 ]] || fail "invalid finding should be 422"
ok "POST /findings invalid body -> 422"

# 4. Ingest. Same asset criticality; the KEV finding has lower CVSS and EPSS but must rank first.
run="smoke-$(date +%s)-$$"
findings="$(jq -nc --arg a "${run}" '[
  {cve:"CVE-2021-44228", asset:($a+"-kev"),    acr:5, cvss:7.0, epss:0.30, days_open:3},
  {cve:"CVE-2099-0001",  asset:($a+"-nonkev"), acr:5, cvss:9.8, epss:0.90, days_open:3},
  {cve:"cve-2099-0002",  asset:($a+"-low"),    acr:1, cvss:2.0, epss:0.01, days_open:1}
]')"
[[ "$(status POST /findings "${auth[@]}" "${json[@]}" --data "${findings}")" == 201 ]] \
  || fail "POST /findings not 201: $(cat "${BODY}")"
jq -e '.accepted == 3' "${BODY}" >/dev/null || fail "expected accepted=3, got $(cat "${BODY}")"
ok "POST /findings -> 201 accepted=3"

# 5. Queue ordering.
[[ "$(status GET '/queue?limit=100' "${auth[@]}")" == 200 ]] || fail "GET /queue not 200: $(cat "${BODY}")"
jq -e '[.[].risk] as $r | $r == ($r | sort | reverse)' "${BODY}" >/dev/null \
  || fail "queue not sorted by risk desc"
ok "GET /queue sorted by risk descending"

pos() { jq --arg a "$1" '[.[].asset] | index($a)' "${BODY}"; }
kev_pos="$(pos "${run}-kev")"; nonkev_pos="$(pos "${run}-nonkev")"; low_pos="$(pos "${run}-low")"
[[ "${kev_pos}" != null && "${nonkev_pos}" != null && "${low_pos}" != null ]] || fail "smoke findings missing from queue"
(( kev_pos < nonkev_pos )) || fail "KEV finding (pos ${kev_pos}) should outrank non-KEV (pos ${nonkev_pos})"
(( nonkev_pos < low_pos )) || fail "high-risk finding should outrank low-risk finding"
ok "KEV finding outranks higher-CVSS non-KEV finding on same asset criticality"

jq -e --arg a "${run}-kev" '.[] | select(.asset == $a) | .kev == true and (.risk >= 0 and .risk <= 100)' "${BODY}" >/dev/null \
  || fail "KEV item missing kev=true or risk out of range"
jq -e --arg a "${run}-low" '.[] | select(.asset == $a) | .cve == "CVE-2099-0002"' "${BODY}" >/dev/null \
  || fail "CVE id was not normalised to upper case"
ok "queue items carry kev flag, bounded risk, upper-case CVE"

[[ "$(status GET '/queue?limit=0' "${auth[@]}")" == 422 ]] || fail "limit=0 should be 422"
ok "GET /queue?limit=0 -> 422"

# 6. Metrics exposed in Prometheus text format.
[[ "$(status GET /metrics)" == 200 ]] || fail "/metrics not 200"
grep -q '^# HELP' "${BODY}" || fail "/metrics is not Prometheus exposition format"
ok "GET /metrics 200 (Prometheus format)"

echo "smoke: ${pass} checks passed against ${BASE_URL}"
