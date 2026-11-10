#!/usr/bin/env bash
# Install pinned CLI tools on a linux/amd64 CI runner, verifying each download against a sha256 that
# is committed here (taken from the upstream release checksum files, see docs/TOOLING.md).
#
# Why not marketplace actions for these? A pinned binary plus a committed checksum is the smallest
# trust surface: no extra JavaScript runs with the job token, and a re-tagged upstream release fails
# the checksum instead of silently changing what runs.
#
# Usage: deploy/scripts/install-tools.sh kind kubectl helm ...
set -euo pipefail

BIN_DIR="${TOOLS_BIN_DIR:-${RUNNER_TEMP:-/tmp}/kevgate-tools/bin}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${BIN_DIR}"

KIND_VERSION=v0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KUBECTL_VERSION=v1.37.2
KUBECTL_SHA256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
HELM_VERSION=v4.3.1
HELM_SHA256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b
KUBECONFORM_VERSION=v0.8.0
KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
TRIVY_VERSION=0.76.2
TRIVY_SHA256=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
KUBESCAPE_VERSION=4.0.20
KUBESCAPE_SHA256=25649b3e1212a86bbd467d3e73812218459455c335fad7aaed7fe458782355c5
PROMETHEUS_VERSION=3.16.0
PROMETHEUS_SHA256=68727009472a2c02e1ff7f062fd5b3e637285bffc8fc2d340c76fb449d6e0f34
TFLINT_VERSION=v0.66.0
TFLINT_SHA256=22be11cadc25cd02401e94c0ccc91aa63467debb8485c2a755d98f4c0a9d1e2e
ACTIONLINT_VERSION=1.7.12
ACTIONLINT_SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8

fetch() { # url sha256 dest
  local url="$1" sum="$2" dest="$3"
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "${dest}" "${url}"
  echo "${sum}  ${dest}" | sha256sum --check --strict --quiet
}

install_one() {
  case "$1" in
    kind)
      fetch "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64" "${KIND_SHA256}" "${WORK}/kind"
      install -m 0755 "${WORK}/kind" "${BIN_DIR}/kind" ;;
    kubectl)
      fetch "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" "${KUBECTL_SHA256}" "${WORK}/kubectl"
      install -m 0755 "${WORK}/kubectl" "${BIN_DIR}/kubectl" ;;
    helm)
      fetch "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" "${HELM_SHA256}" "${WORK}/helm.tgz"
      tar -xzf "${WORK}/helm.tgz" -C "${WORK}" linux-amd64/helm
      install -m 0755 "${WORK}/linux-amd64/helm" "${BIN_DIR}/helm" ;;
    kubeconform)
      fetch "https://github.com/yannh/kubeconform/releases/download/${KUBECONFORM_VERSION}/kubeconform-linux-amd64.tar.gz" "${KUBECONFORM_SHA256}" "${WORK}/kc.tgz"
      tar -xzf "${WORK}/kc.tgz" -C "${WORK}" kubeconform
      install -m 0755 "${WORK}/kubeconform" "${BIN_DIR}/kubeconform" ;;
    trivy)
      fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "${TRIVY_SHA256}" "${WORK}/trivy.tgz"
      tar -xzf "${WORK}/trivy.tgz" -C "${WORK}" trivy
      install -m 0755 "${WORK}/trivy" "${BIN_DIR}/trivy" ;;
    gitleaks)
      fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "${GITLEAKS_SHA256}" "${WORK}/gitleaks.tgz"
      tar -xzf "${WORK}/gitleaks.tgz" -C "${WORK}" gitleaks
      install -m 0755 "${WORK}/gitleaks" "${BIN_DIR}/gitleaks" ;;
    kubescape)
      fetch "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_linux_amd64" "${KUBESCAPE_SHA256}" "${WORK}/kubescape"
      install -m 0755 "${WORK}/kubescape" "${BIN_DIR}/kubescape" ;;
    promtool)
      fetch "https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz" "${PROMETHEUS_SHA256}" "${WORK}/prom.tgz"
      tar -xzf "${WORK}/prom.tgz" -C "${WORK}" "prometheus-${PROMETHEUS_VERSION}.linux-amd64/promtool"
      install -m 0755 "${WORK}/prometheus-${PROMETHEUS_VERSION}.linux-amd64/promtool" "${BIN_DIR}/promtool" ;;
    tflint)
      fetch "https://github.com/terraform-linters/tflint/releases/download/${TFLINT_VERSION}/tflint_linux_amd64.zip" "${TFLINT_SHA256}" "${WORK}/tflint.zip"
      unzip -q -o "${WORK}/tflint.zip" tflint -d "${WORK}"
      install -m 0755 "${WORK}/tflint" "${BIN_DIR}/tflint" ;;
    actionlint)
      fetch "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz" "${ACTIONLINT_SHA256}" "${WORK}/al.tgz"
      tar -xzf "${WORK}/al.tgz" -C "${WORK}" actionlint
      install -m 0755 "${WORK}/actionlint" "${BIN_DIR}/actionlint" ;;
    *)
      echo "install-tools.sh: unknown tool '$1'" >&2
      exit 2 ;;
  esac
  echo "installed $1"
}

for tool in "$@"; do
  install_one "${tool}"
done

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${BIN_DIR}" >> "${GITHUB_PATH}"
fi
