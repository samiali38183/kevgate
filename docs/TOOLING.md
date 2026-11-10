# Tooling

Two sets of tools: the ones I installed on my Windows machine for static validation, and the ones
CI installs on Linux runners. Everything is pinned. Local installs are user-level binaries in
`C:/Users/samis/bin`. Each download was checked against the checksum the project publishes.

## Local (Windows, amd64), verified 2026-11-10

| Tool | Version | SHA256 of the downloaded artifact | Checksum source |
|---|---|---|---|
| kubectl | v1.37.2 | `1691938f7de0e931969f9968c3601cf32d6b0d573573afb4ce471f3d28f51984` (kubectl.exe) | dl.k8s.io `.sha256` |
| helm | v4.3.1 | `fcfd7b796dcf0f225abc40b5636a3b01f55f3de2fb1dfb18475df94e62c14112` (zip) | get.helm.sh `.sha256sum` |
| kind | v0.33.0 | `4b22adaa135368c5a465d56bbd8e520cbea87272a06ca00b6078e7b81515c9fc` | release `.sha256sum` |
| terraform | 1.17.1 | `a3b71365cff94c0f978cf75d86addb075ea1bb6409055ea0ab359bf057d7898a` (zip) | releases.hashicorp.com SHA256SUMS |
| trivy | 0.76.2 | `691f737a7e5566a673c3a74dab9160552ec32101e953b659e5c77443d16dddb6` (zip) | release `checksums.txt` |
| kubeconform | v0.8.0 | `e3f56102bcf4f50b034a567e2482a1c5330799983ddd655952310211aef73d93` (zip) | release `CHECKSUMS` |
| actionlint | 1.7.12 | `6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9` (zip) | release checksums file |
| tflint | v0.66.0 | `e3acd1d89c735ce6e09108c9277f26076ebeb385c1f77a73c1cbf1826ed626a7` (zip) | release `checksums.txt` |
| promtool (Prometheus) | 3.16.0 | `89c03c2f24400fb58668440b6d7226f68564acda27d657e77acfbda42be32cb3` (zip) | release `sha256sums.txt` |
| shellcheck | v0.11.0 | `8a4e35ab0b331c85d73567b12f2a444df187f483e5079ceffa6bda1faa2e740e` (zip) | none published; matches the digest GitHub records for the release asset |

Python tools, each in its own virtualenv under `C:/Users/samis/code/.tools`:

| Tool | Version |
|---|---|
| checkov | 3.4.3 |
| sigma-cli | 4.0.0 (pySigma 2.1.0, Splunk backend 3.0.0 used to check rules convert) |

Not installed locally: Docker, so no image build, no kind cluster, no LocalStack, no Semgrep,
Bandit, pip-audit, gitleaks, kubescape or ZAP runs here. Those run in CI.

## CI (Linux amd64)

`deploy/scripts/install-tools.sh` installs the Linux builds with the versions and sha256 values
committed in that file, so a replaced upstream asset fails the job instead of running.

| Tool | Version | Linux sha256 (pinned in the script) |
|---|---|---|
| kind | v0.33.0 | `aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d` |
| kubectl | v1.37.2 | `c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4` |
| helm | v4.3.1 | `0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b` |
| kubeconform | v0.8.0 | `9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883` |
| trivy | 0.76.2 | `bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf` |
| gitleaks | 8.30.1 | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| kubescape | 4.0.20 | `25649b3e1212a86bbd467d3e73812218459455c335fad7aaed7fe458782355c5` |
| promtool | 3.16.0 | `68727009472a2c02e1ff7f062fd5b3e637285bffc8fc2d340c76fb449d6e0f34` |
| tflint | v0.66.0 | `22be11cadc25cd02401e94c0ccc91aa63467debb8485c2a755d98f4c0a9d1e2e` |
| actionlint | 1.7.12 | `8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8` |

Pip-installed in CI with exact versions: semgrep 1.185.0, bandit 1.9.4, pip-audit 2.10.1,
checkov 3.4.3, sigma-cli 4.0.0, pip-tools 7.6.2.

Pinned images and manifests:

| Item | Pin |
|---|---|
| python base image | `python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b` |
| kind node image | `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5` |
| Calico manifest | v3.33.0, sha256 `2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5` |
| ZAP | `zaproxy/zap-stable:2.17.0@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af` |
| LocalStack | `localstack/localstack:4.14.0@sha256:3ebc37595918b8accb852f8048fef2aff047d465167edd655528065b07bc364a` |
| curl test image | `curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93` |

GitHub Actions are pinned by full commit SHA with the release tag in a trailing comment. Resolved
with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` (annotated tags dereferenced to the commit).

## Updating pins

1. Look up the new version and its published checksum.
2. Update the value in `install-tools.sh` (or the workflow, Dockerfile or kind config).
3. Run the same local validation (see `docs/PIPELINE.md`) and let CI confirm.
