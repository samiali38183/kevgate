#!/usr/bin/env bash
# Compare the base image digest pinned in the Dockerfile with what the tag resolves to upstream today.
# Drift is not a failure (the pin is doing its job); it is a signal to bump the pin deliberately so
# OS security fixes are picked up. Prints a GitHub warning annotation when the digests differ.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ref="$(sed -nE 's/^ARG PYTHON_IMAGE=(.+)$/\1/p' "${ROOT}/Dockerfile")"
tag_part="${ref%@*}"          # python:3.12.16-slim-trixie
pinned="${ref#*@}"            # sha256:...
repo="library/${tag_part%%:*}"
tag="${tag_part#*:}"

token="$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
current="$(curl -fsSI \
  -H "Authorization: Bearer ${token}" \
  -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json' \
  "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"

echo "pinned : ${tag_part}@${pinned}"
echo "current: ${tag_part}@${current}"
if [[ -z "${current}" ]]; then
  echo "::warning title=Base image::could not resolve ${tag_part} upstream"
elif [[ "${current}" != "${pinned}" ]]; then
  echo "::warning title=Base image drift::${tag_part} upstream is ${current}; Dockerfile pins ${pinned}. Bump the pin."
else
  echo "base image pin is current"
fi
