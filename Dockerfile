# kevgate container image
#
# Base image is pinned by tag AND manifest-list digest. The tag is for humans, the digest is what
# the builder actually resolves, so a re-pushed tag upstream cannot change what we build.
# deploy/scripts/check-base-digest.sh (run in security.yml) reports when upstream has moved so the
# pin gets bumped on purpose, not by accident.
#   python:3.12.16-slim-trixie, resolved 2026-11-10 via registry-1.docker.io/v2/library/python/manifests
ARG PYTHON_IMAGE=python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

########################################################################################
# Stage 1: builder. Installs locked, hash-verified dependencies plus the kevgate wheel into
# a self-contained virtualenv at /opt/venv. Compilers or build caches never reach runtime.
########################################################################################
# checkov:skip=CKV_DOCKER_7: false positive, FROM uses an ARG that pins tag and sha256 digest (see top of file)
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

# Dependencies first so this layer is cached until the lock changes.
# --require-hashes: every artifact must match the sha256 recorded in requirements.lock.
COPY requirements.lock ./
RUN pip install --require-hashes --no-deps -r requirements.lock

# Then the application itself, as a wheel, without touching the resolver (--no-deps).
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-deps --wheel-dir /wheels . \
 && pip install --no-deps --no-index /wheels/*.whl \
 && pip uninstall --yes pip \
 && find /opt/venv -name '__pycache__' -type d -prune -exec rm -rf {} + \
 && python -m compileall -q /opt/venv/lib

########################################################################################
# Stage 2: runtime. Same base, no build tooling, no pip, non-root, read-only-root friendly.
########################################################################################
FROM ${PYTHON_IMAGE} AS runtime

ARG VERSION=dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="kevgate" \
      org.opencontainers.image.description="Vulnerability intake service ranking findings by CISA KEV, EPSS, CVSS and asset criticality" \
      org.opencontainers.image.source="https://github.com/samiali38183/kevgate" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KEVGATE_ENV=prod \
    KEVGATE_DB_PATH=/data/kevgate.db

# - Pending Debian security updates are applied on top of the pinned base, so a CVE fixed in the
#   archive is not carried until the next upstream rebuild of the python image. apt lists and
#   caches are removed in the same layer. The CI Trivy gate (HIGH/CRITICAL with a fix) proves it.
# - Fixed non-root identity (UID/GID 10001) so Kubernetes runAsUser and file ownership agree.
# - /data is the only writable path the app needs; everything else can be mounted read-only.
# - pip is removed from the system interpreter: it is not needed at runtime and is a frequent
#   source of scanner findings and a convenient tool for an attacker.
# checkov:skip=CKV_DOCKER_9: apt-get is used only to apply Debian security updates, see comment above
RUN apt-get update \
 && apt-get upgrade --yes --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
 && groupadd --system --gid 10001 kevgate \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin kevgate \
 && mkdir -p /data \
 && chown 10001:10001 /data \
 && chmod 0700 /data \
 && python -m pip uninstall --yes pip \
 && rm -rf /root/.cache /tmp/*

# Code is owned by root and not writable by the app user.
COPY --from=builder /opt/venv /opt/venv

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000

# Exec-form healthcheck through the interpreter that is already present, so it does not depend on
# curl or a shell. Kubernetes ignores HEALTHCHECK and uses the probes in the Helm chart instead.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]

# Exec form, so the process is PID 1 and gets SIGTERM directly. `kevgate serve` wraps uvicorn with
# JSON logging and no access log or Server header; equivalent to
# `uvicorn kevgate.main:app --host 0.0.0.0 --port 8000` from the app contract.
CMD ["kevgate", "serve", "--host", "0.0.0.0", "--port", "8000"]
