#!/usr/bin/env bash
# Produce requirements.lock (runtime dependencies, exact versions, sha256 hashes) from pyproject.toml.
#
# requirements.lock is committed. By default this script uses it as-is and only checks that every
# pin carries a hash, so CI, the image build and the SBOM all see the same dependency set.
#
# Refresh it (the only supported way to change it):
#     bash deploy/scripts/lock.sh refresh
# then review the diff and commit it in a pull request. The weekly lock-freshness workflow runs
# the same command and goes red when the committed file is behind what pip-compile would pick now.
# Other arguments: `compile-to FILE` writes a fresh compile to FILE and leaves the lock alone.
#
# Run on Linux with the same Python minor version as the image (3.12): markers and wheels differ
# per platform, so a lock compiled on Windows is not valid for the container.
set -euo pipefail

PIP_TOOLS_VERSION="7.6.2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK="${ROOT}/requirements.lock"
MODE="${1:-use}"
case "${MODE}" in
  use | refresh) ;;
  compile-to)
    LOCK="${2:?usage: lock.sh compile-to FILE}"
    MODE="refresh"
    ;;
  *)
    echo "usage: lock.sh [refresh | compile-to FILE]" >&2
    exit 2
    ;;
esac

if [[ "${MODE}" == "use" && -f "${LOCK}" ]]; then
  echo "lock.sh: using committed ${LOCK}"
else
  echo "lock.sh: compiling ${LOCK} from pyproject.toml with pip-tools ${PIP_TOOLS_VERSION}"
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
