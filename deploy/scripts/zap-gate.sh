#!/usr/bin/env bash
# Fail when a ZAP JSON report contains an alert of risk Medium or higher that is not IGNOREd in
# deploy/zap/rules.tsv. ZAP riskcode: 0 info, 1 low, 2 medium, 3 high.
#
# Why a separate gate: zap-baseline.py only distinguishes WARN and FAIL per rule id and its exit
# code is coarse. This makes the policy explicit: medium and above fails, everything else is
# reported in the artifact.
#
# Usage: zap-gate.sh REPORT.json [RULES.tsv]
set -euo pipefail

REPORT="${1:?usage: zap-gate.sh REPORT.json [RULES.tsv]}"
RULES="${2:-$(dirname "${BASH_SOURCE[0]}")/../zap/rules.tsv}"

ignored="$(awk -F'\t' '!/^#/ && $2 == "IGNORE" {print $1}' "${RULES}" | jq -R . | jq -sc .)"

findings="$(jq -c --argjson ignored "${ignored}" '
  [ .site[]?.alerts[]?
    | select((.riskcode | tonumber) >= 2)
    | select(.pluginid as $id | ($ignored | index($id)) | not)
    | {pluginid, name, risk: .riskdesc, instances: (.instances | length)} ]' "${REPORT}")"

total="$(jq '[.site[]?.alerts[]?] | length' "${REPORT}")"
echo "zap-gate: ${total} alert type(s) in report, ignored rule ids: ${ignored}"

if [[ "$(jq 'length' <<<"${findings}")" -gt 0 ]]; then
  echo "zap-gate: FAIL, medium or higher alerts:" >&2
  jq -r '.[] | "  [\(.pluginid)] \(.name) (\(.risk)), \(.instances) instance(s)"' <<<"${findings}" >&2
  exit 1
fi
echo "zap-gate: no medium or higher alerts"
