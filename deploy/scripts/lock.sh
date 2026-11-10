#!/usr/bin/env bash
# Produce requirements.lock (runtime dependencies, exact versions, sha256 hashes) from pyproject.toml.
#
# If a committed requirements.lock exists it is used as-is and only checked for hashes. Otherwise one
# is generated with a pinned pip-tools. CI always uploads the lock it used, so pip-audit, the image
# build and the SBOM all describe the same dependency set.
#
# Run on Linux with the same Python minor version as the image (3.12): markers and wheels differ
# per platform, so a lock compiled on Windows is not valid for the container.
set -euo pipefail

PIP_TOOLS_VERSION="7.6.2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK="${ROOT}/requirements.lock"

if [[ -f "${LOCK}" ]]; then
  echo "lock.sh: using committed ${LOCK}"
else
  echo "lock.sh: no committed lock, compiling from pyproject.toml with pip-tools ${PIP_TOOLS_VERSION}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT
  python3 -m venv "${tmp}/venv"
  "${tmp}/venv/bin/pip" install --quiet --disable-pip-version-check "pip-tools==${PIP_TOOLS_VERSION}"
  (cd "${ROOT}" && "${tmp}/venv/bin/pip-compile" \
      --quiet \
      --generate-hashes \
      --allow-unsafe \
      --strip-extras \
      --no-emit-index-url \
      --output-file "${LOCK}" \
      pyproject.toml)
fi

# Every pinned requirement must be followed by at least one --hash, or --require-hashes fails late.
missing="$(awk '
  /^[A-Za-z0-9_.\[\]-]+==/ { if (pending) print pending; pending=$1; next }
  /--hash=sha256:/            { pending=""; next }
  END                         { if (pending) print pending }
' "${LOCK}")"
if [[ -n "${missing}" ]]; then
  echo "lock.sh: entries without hashes:" >&2
  echo "${missing}" >&2
  exit 1
fi
echo "lock.sh: $(grep -cE '^[A-Za-z0-9_.-]+==' "${LOCK}") pinned packages, all hashed"
