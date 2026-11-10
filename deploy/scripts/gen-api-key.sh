#!/usr/bin/env bash
# Generate a throwaway API key for CI with the image's own `kevgate keygen`, then:
#   $OUT_DIR/api_key   plaintext key (mode 0600), used by smoke.sh and ZAP
#   $OUT_DIR/api_keys  hashed line key_id:scopes:hash, stored in the Kubernetes Secret
# Nothing is committed: every CI run gets a fresh key that dies with the runner.
#
# Usage: gen-api-key.sh IMAGE [OUT_DIR]
#
# Output contract expected from `kevgate keygen --scope ...`:
#   either JSON {"key": "...", "line": "key_id:scopes:hash"}
#   or plain text with the plaintext key and the hash line on separate lines (labels like
#   "key: " are tolerated). The hash line is the one that contains the requested scopes.
set -euo pipefail

IMAGE="${1:?usage: gen-api-key.sh IMAGE [OUT_DIR]}"
OUT_DIR="${2:-${RUNNER_TEMP:-/tmp}/kevgate-keys}"
SCOPES="findings:write,queue:read"

umask 077
mkdir -p "${OUT_DIR}"

raw="$(docker run --rm --network none --read-only --user 10001:10001 --cap-drop ALL \
  --security-opt no-new-privileges "${IMAGE}" kevgate keygen --scope "${SCOPES}")"

key=""; line=""
if jq -e 'type == "object"' >/dev/null 2>&1 <<<"${raw}"; then
  key="$(jq -r '.key // .api_key // empty' <<<"${raw}")"
  line="$(jq -r '.line // .hash_line // .entry // empty' <<<"${raw}")"
else
  strip_label() { sed -E 's/^[[:space:]]*[A-Za-z][A-Za-z _-]*:[[:space:]]+//; s/[[:space:]]+$//'; }
  line="$(grep -F "${SCOPES%%,*}" <<<"${raw}" | tail -n 1 | strip_label)"
  key="$(grep -vF "${SCOPES%%,*}" <<<"${raw}" | grep -v '^[[:space:]]*$' | head -n 1 | strip_label)"
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
