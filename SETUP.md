# Setup

## Now (M1, Python only)
```bash
cd ~/code/kevgate
python -m venv .venv && source .venv/Scripts/activate
pip install -e ".[dev]"
pytest -q          # M1 tests fail until you implement src/kevgate
```

## Before M3 (needs admin, ~45 min). Run in an admin PowerShell:
```powershell
winget install -e --id Docker.DockerDesktop      # choose WSL2 backend, then reboot
winget install -e --id Kubernetes.kind
winget install -e --id Kubernetes.kubectl
winget install -e --id Helm.Helm
winget install -e --id Hashicorp.Terraform
winget install -e --id AquaSecurity.Trivy
```
Check: `docker run --rm hello-world`, `kind create cluster`, `kubectl get nodes`.
