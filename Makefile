VERSION        ?= 0.1.0
IMG            ?= ghcr.io/wscoble/egress-range-controller:$(VERSION)
CONTROLLER_GEN ?= $(shell pwd)/bin/controller-gen
CONTROLLER_GEN_VERSION ?= v0.23.0
CHART          := charts/egress-range-controller
CRD            := config/crd/bases/egress.greybeard.support_egressranges.yaml

.PHONY: all build test vet fmt generate manifests check-generated helm-lint kustomize-build lint \
        deploy-bundle image-tarball docker-build dry-run clean

all: build test

build: ## Build the controller binary for the host
	CGO_ENABLED=0 go build -trimpath -o bin/egress-range-controller ./cmd

test: ## Unit tests (fake clock, fake DNS/HTTP, controller-runtime fake client)
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

$(CONTROLLER_GEN):
	GOBIN=$(shell pwd)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

generate: $(CONTROLLER_GEN) ## Regenerate deepcopy code and the CRD (also copied into the chart)
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/...
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=config/crd/bases
	cp $(CRD) $(CHART)/crds/

manifests: generate deploy-bundle

check-generated: manifests ## Fail if generated files are out of date
	git diff --exit-code -- api config charts deploy

helm-lint:
	helm lint $(CHART)
	helm lint $(CHART) -f $(CHART)/examples/proton-values.yaml
	helm template egress-range-controller $(CHART) -n mail -f $(CHART)/examples/proton-values.yaml --include-crds >/dev/null

kustomize-build:
	kustomize build config/default >/dev/null
	kustomize build config/overlays/proton-example >/dev/null
	kustomize build config/overlays/static-example >/dev/null

lint: vet helm-lint kustomize-build
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

deploy-bundle: ## Regenerate deploy/all.yaml
	./hack/deploy-bundle.sh

image-tarball: ## Multi-arch image tarballs in dist/ without a container runtime (needs crane)
	VERSION=$(VERSION) ./hack/build-image-tarball.sh

docker-build: ## Multi-arch image with docker buildx (pushes nothing unless you add --push)
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMG) .

dry-run: build ## Fetch once with the built-in Proton example and print the decision (no cluster access)
	./bin/egress-range-controller --dry-run-fetch

clean:
	rm -rf bin/egress-range-controller dist/
