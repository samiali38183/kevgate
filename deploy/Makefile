# Deployment targets for kevgate. Run from the repo root:  make -f deploy/Makefile <target>
# Needs docker, kind, kubectl, helm (and kubeconform/terraform/tflint/checkov for the lint targets).
# The same steps run in .github/workflows/deploy-kind.yml; this file is the local equivalent.

SHELL        := bash
.SHELLFLAGS  := -euo pipefail -c
.DEFAULT_GOAL := help

ROOT         := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
CLUSTER      ?= kevgate
NS           ?= kevgate
RELEASE      ?= kevgate
IMAGE        ?= kevgate:ci
CHART        := $(ROOT)/deploy/helm/kevgate
KEY_DIR      ?= /tmp/kevgate-local/keys
PORT         ?= 18000
K8S_VERSION  ?= 1.37.0
CALICO_URL   := https://raw.githubusercontent.com/projectcalico/calico/v3.33.0/manifests/calico.yaml
CALICO_SHA256 := 2de8f47595fb9c41b3f47d7b767a1f8e72ecf84057af834738ff12689a234da5
CRD_SCHEMAS  := https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json

.PHONY: help
help: ## List targets
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

# ---- image -------------------------------------------------------------------------------------
.PHONY: docker-lock docker-build
docker-lock: ## Generate requirements.lock (hashes) if none is committed
	bash $(ROOT)/deploy/scripts/lock.sh

docker-build: docker-lock ## Build the runtime image as $(IMAGE)
	docker build --pull=false -t $(IMAGE) \
	  --build-arg VERSION=$$(git -C $(ROOT) describe --tags --always) \
	  --build-arg VCS_REF=$$(git -C $(ROOT) rev-parse HEAD) $(ROOT)

# ---- kind ----------------------------------------------------------------------------------------
.PHONY: kind-up kind-load kind-down
kind-up: ## Create kind cluster with Calico (NetworkPolicy) and audit logging
	cd $(ROOT) && kind create cluster --name $(CLUSTER) --config deploy/kind/kind-config.yaml --wait 0s
	curl -fsSL -o /tmp/calico.yaml $(CALICO_URL)
	echo "$(CALICO_SHA256)  /tmp/calico.yaml" | sha256sum --check --strict
	kubectl apply -f /tmp/calico.yaml
	kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
	kubectl -n kube-system rollout status deployment/calico-kube-controllers --timeout=300s
	kubectl wait --for=condition=Ready nodes --all --timeout=180s

kind-load: ## Side-load $(IMAGE) into the kind node
	kind load docker-image $(IMAGE) --name $(CLUSTER)

kind-down: ## Delete the kind cluster
	kind delete cluster --name $(CLUSTER)

# ---- helm ----------------------------------------------------------------------------------------
.PHONY: helm-lint helm-template helm-secret helm-install helm-uninstall
helm-lint: ## helm lint (strict) with default, kind and all-features values
	helm lint $(CHART) --strict
	helm lint $(CHART) --strict -f $(CHART)/ci/kind-values.yaml
	helm lint $(CHART) --strict -f $(CHART)/ci/all-features-values.yaml

helm-template: ## Render and validate with kubeconform -strict
	for v in "" "-f $(CHART)/ci/kind-values.yaml" "-f $(CHART)/ci/all-features-values.yaml"; do \
	  helm template $(RELEASE) $(CHART) -n $(NS) $$v \
	  | kubeconform -strict -summary -kubernetes-version $(K8S_VERSION) \
	      -schema-location default -schema-location '$(CRD_SCHEMAS)' - ; \
	done

helm-secret: ## Generate a fresh API key and store its hash in the cluster Secret
	kubectl apply -f $(ROOT)/deploy/kind/namespace.yaml
	bash $(ROOT)/deploy/scripts/gen-api-key.sh $(IMAGE) $(KEY_DIR)
	kubectl -n $(NS) create secret generic kevgate-api-keys \
	  --from-file=api_keys=$(KEY_DIR)/api_keys --dry-run=client -o yaml | kubectl apply -f -

helm-install: helm-secret ## Install or upgrade the chart with kind values and wait for rollout
	helm upgrade --install $(RELEASE) $(CHART) -n $(NS) -f $(CHART)/ci/kind-values.yaml \
	  --wait --timeout 180s
	kubectl -n $(NS) rollout status deployment/$(RELEASE) --timeout=120s

helm-uninstall: ## Remove the release (PVC is kept by resource policy)
	helm uninstall $(RELEASE) -n $(NS)

# ---- tests ---------------------------------------------------------------------------------------
.PHONY: smoke kind-netpol kind-audit
smoke: ## Port-forward and run deploy/smoke.sh
	kubectl -n $(NS) port-forward svc/$(RELEASE) $(PORT):8000 >/tmp/kevgate-pf.log 2>&1 & pf=$$!; \
	trap 'kill $$pf' EXIT; \
	for i in $$(seq 1 30); do curl -fsS http://127.0.0.1:$(PORT)/healthz >/dev/null 2>&1 && break; sleep 1; done; \
	BASE_URL=http://127.0.0.1:$(PORT) KEVGATE_API_KEY="$$(cat $(KEY_DIR)/api_key)" bash $(ROOT)/deploy/smoke.sh

kind-netpol: ## Prove NetworkPolicy, egress deny and PSS admission enforce
	NS=$(NS) SVC=$(RELEASE) bash $(ROOT)/deploy/scripts/netpol-test.sh

kind-audit: ## Check audit log for the events the Sigma rules target
	NS=$(NS) KIND_NODE=$(CLUSTER)-control-plane bash $(ROOT)/deploy/scripts/audit-check.sh /tmp/kevgate-local/audit

# ---- terraform -----------------------------------------------------------------------------------
.PHONY: tf-fmt tf-validate tf-lint
TF_DIRS := $(ROOT)/infra/terraform/aws $(ROOT)/infra/terraform/localstack

tf-fmt: ## terraform fmt -check -recursive
	terraform -chdir=$(ROOT)/infra/terraform fmt -check -recursive -diff

tf-validate: ## init -backend=false and validate each root module
	for d in $(TF_DIRS); do terraform -chdir=$$d init -backend=false -input=false >/dev/null && terraform -chdir=$$d validate; done

tf-lint: ## tflint on each root module and the shared module
	for d in $(TF_DIRS) $(ROOT)/infra/terraform/modules/kevgate; do \
	  tflint --chdir=$$d --config=$(ROOT)/infra/terraform/.tflint.hcl --init >/dev/null && tflint --chdir=$$d --config=$(ROOT)/infra/terraform/.tflint.hcl; done
