#!/usr/bin/env bash
# Generate a throwaway API key for CI with the image's own `kevgate keygen`, then:
#   $OUT_DIR/api_key   plaintext key (mode 0600), used by smoke.sh and ZAP
#   $OUT_DIR/api_keys  hashed line key_id:scopes:hash, stored in the Kubernetes Secret
# Nothing is committed: every CI run gets a fresh key that dies with the runner.
#
# Usage: gen-api-key.sh IMAGE [OUT_DIR]
#
# `kevgate keygen` prints two labelled lines on stdout ("key:  <plaintext>", "line: <key_id:scopes:hash>")
# and a reminder on stderr. A JSON object {"key": ..., "line": ...} is also accepted in case the
# output format changes. The hash line is identified by the scope it contains.
set -euo pipefail

IMAGE="${1:?usage: gen-api-key.sh IMAGE [OUT_DIR]}"
OUT_DIR="${2:-${RUNNER_TEMP:-/tmp}/kevgate-keys}"
SCOPES=(findings:write queue:read)
KEY_ID="${KEY_ID:-ci-smoke}"

umask 077
mkdir -p "${OUT_DIR}"

raw="$(docker run --rm --network none --read-only --user 10001:10001 --cap-drop ALL \
  --security-opt no-new-privileges "${IMAGE}" kevgate keygen --key-id "${KEY_ID}" "${SCOPES[@]/#/--scope=}" 2>/dev/null)"

key=""; line=""
if jq -e 'type == "object"' >/dev/null 2>&1 <<<"${raw}"; then
  key="$(jq -r '.key // .api_key // empty' <<<"${raw}")"
  line="$(jq -r '.line // .hash_line // .entry // empty' <<<"${raw}")"
else
  strip_label() { sed -E 's/^[[:space:]]*[A-Za-z][A-Za-z _-]*:[[:space:]]+//; s/[[:space:]]+$//'; }
  line="$(grep -F "${SCOPES[0]}" <<<"${raw}" | tail -n 1 | strip_label)"
  key="$(grep -vF "${SCOPES[0]}" <<<"${raw}" | grep -v '^[[:space:]]*$' | head -n 1 | strip_label)"
fi

if [[ -z "${key}" || -z "${line}" || "${key}" == "${line}" ]]; then
  echo "gen-api-key.sh: could not parse keygen output ($(wc -l <<<"${raw}") lines, not shown)" >&2
  exit 1
fi

# Keep the key out of CI logs from here on.
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  echo "::add-mask::${key}"
fi

printf '%s' "${key}" > "${OUT_DIR}/api_key"
printf '%s\n' "${line}" > "${OUT_DIR}/api_keys"
echo "gen-api-key.sh: wrote ${OUT_DIR}/api_key and ${OUT_DIR}/api_keys (key id: ${line%%:*})"
