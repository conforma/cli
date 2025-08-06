MAKEFLAGS+=-j --no-print-directory
VERSION_FILE=./VERSION
VERSION:=$$(hack/derive-version.sh)
# a list of "dist/ec_{platform}_{arch}" that we support
ALL_SUPPORTED_OS_ARCH:=$(shell go tool dist list -json|jq -r '.[] | select((.FirstClass == true or .GOARCH == "ppc64le") and .GOARCH != "386") | "dist/ec_\(.GOOS)_\(.GOARCH)"')
# a list of image_* targets that we do not support
UNSUPPORTED_OS_ARCH_IMG:=image_windows_amd64 image_darwin_amd64 image_darwin_arm64 image_linux_arm
# a list of image_* targets that we do support generated from
# ALL_SUPPORTED_OS_ARCH by replacing "dist/ec_" with "image_"
ALL_SUPPORTED_IMG_OS_ARCH:=$(filter-out $(UNSUPPORTED_OS_ARCH_IMG),$(subst dist/ec_,image_,$(ALL_SUPPORTED_OS_ARCH)))
_SHELL := bash
SHELL=$(if $@,$(info ❱ [1m$@[0m))$(_SHELL)
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
COPY:=The Conforma Contributors
COSIGN_VERSION=$(shell go list -f '{{.Version}}' -m github.com/sigstore/cosign/v2)

##@ Information

.PHONY: help
help: ## Display this help
	@awk 'function ww(s) {\
		if (length(s) < 59) {\
			return s;\
		}\
		else {\
			r="";\
			l="";\
			split(s, arr, " ");\
			for (w in arr) {\
				if (length(l " " arr[w]) > 59) {\
					r=r l "\n                     ";\
					l="";\
				}\
				l=l " " arr[w];\
			}\
			r=r l;\
			return r;\
		}\
	} BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[^: (]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", "make " $$1, ww($$2) } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Building

.PHONY: generate
generate: ## Code-generate files
	go generate ./...

# Set DEBUG_BUILD=1 to build a binary with gdb/dlv debugging support
BUILD_GC_FLAGS=$(if $(DEBUG_BUILD),-gcflags="-N -l",)
BUILD_TRIMPATH=$(if $(DEBUG_BUILD),,-trimpath)
BUILD_LD_FLAGS=$(if $(DEBUG_BUILD),,-s -w)
BUILD_BIN_SUFFIX=$(if $(DEBUG_BUILD),_debug,)

.PHONY: $(ALL_SUPPORTED_OS_ARCH)
$(ALL_SUPPORTED_OS_ARCH): generate ## Build binaries for specific platform/architecture, e.g. make dist/ec_linux_amd64
	@GOOS=$(word 2,$(subst _, ,$(notdir $@))); \
	GOARCH=$(word 3,$(subst _, ,$(notdir $@))); \
	GOOS=$${GOOS} GOARCH=$${GOARCH} CGO_ENABLED=0 go build $(BUILD_TRIMPATH) $(BUILD_GC_FLAGS) -ldflags="$(BUILD_LD_FLAGS) -X github.com/conforma/cli/internal/version.Version=$(VERSION)" -o dist/ec_$${GOOS}_$${GOARCH}$(BUILD_BIN_SUFFIX); \
	sha256sum -b dist/ec_$${GOOS}_$${GOARCH}$(BUILD_BIN_SUFFIX) > dist/ec_$${GOOS}_$${GOARCH}$(BUILD_BIN_SUFFIX).sha256

.PHONY: dist
dist: $(ALL_SUPPORTED_OS_ARCH) ## Build binaries for all supported operating systems and architectures

# Dockerfile.dist is used by the Konflux build pipeline where it's built using
# buildah not podman. This is for testing that build locally.
.PHONY: dist-container
dist-container: clean
	buildah bud --file Dockerfile.dist \
	  --tag dist-container \
	  --platform $(BUILD_LOCAL_PLATFORM) \
	  --build-arg BUILD_SUFFIX=local \
	  --build-arg BUILD_LIST=$(BUILD_LOCAL_ARCH) \
	  .

# For local debugging of the above
dist-container-run:
	podman run --rm -it --entrypoint=/bin/bash dist-container

BUILD_LOCAL_PLATFORM:=$(shell go env GOOS)/$(shell go env GOARCH)
BUILD_LOCAL_ARCH:=$(shell go env GOOS)_$(shell go env GOARCH)
.PHONY: build
build: dist/ec_$(BUILD_LOCAL_ARCH) ## Build the ec binary for the current platform
	@ln -sf ec_$(BUILD_LOCAL_ARCH)$(BUILD_BIN_SUFFIX) dist/ec$(BUILD_BIN_SUFFIX)

BUILD_IMG_ARCH:=$(shell podman version -f {{.Server.OsArch}} | awk -F/ '{print $$1}')_$(shell podman version -f {{.Server.OsArch}} | awk -F/ '{print $$2}')
.PHONY: build-for-test
build-for-test: dist/ec_$(BUILD_IMG_ARCH)

# Assume `DEBUG_BUILD=1 make build` was run already
debug-run:
	dlv exec dist/ec_$(BUILD_LOCAL_ARCH)_debug # ...params here as required

.PHONY: clean
clean: ## Delete build output
	@rm -f dist/*

##@ Testing

# Declutter the output by grepping out the files where there are no
# tests at all, or no tests matching the specified tag
TEST_OUTPUT_FILTER=grep -vE '0.0% of statements|\[no test files\]'

.PHONY: test
test: ## Run all unit tests
	@echo "Unit tests:"
	@set -o pipefail && go test -race -covermode=atomic -coverprofile=coverage-unit.out -timeout 1s -tags=unit ./... | $(TEST_OUTPUT_FILTER)
	@echo "Integration tests:"
	@set -o pipefail && go test -race -covermode=atomic -coverprofile=coverage-integration.out -timeout 15s -tags=integration ./... | $(TEST_OUTPUT_FILTER)
# Given the nature of generative tests the test timeout is increased from 500ms
# to 30s to accommodate many samples being generated and test cases being run.
	@echo "Generative tests:"
	@set -o pipefail && go test -race -covermode=atomic -coverprofile=coverage-generative.out -timeout 30s -tags=generative ./... | $(TEST_OUTPUT_FILTER)

ACCEPTANCE_TIMEOUT:=20m
.ONESHELL:
.SHELLFLAGS=-e -c
.PHONY: acceptance

acceptance: ## Run all acceptance tests
	@ACCEPTANCE_WORKDIR="$$(mktemp -d)"; \
	cleanup() { \
		cp "$${ACCEPTANCE_WORKDIR}"/features/__snapshots__/* "$(ROOT_DIR)"/features/__snapshots__/; \
	}; \
	trap cleanup EXIT; \
	cp -R . "$$ACCEPTANCE_WORKDIR"; \
	cd "$$ACCEPTANCE_WORKDIR" && \
	go run acceptance/coverage/coverage.go && \
	$(MAKE) build && \
	export COVERAGE_FILEPATH="$$ACCEPTANCE_WORKDIR"; \
	export COVERAGE_FILENAME="-acceptance"; \
	cd acceptance && go test -coverprofile "$$ACCEPTANCE_WORKDIR/coverage-acceptance.out" -timeout $(ACCEPTANCE_TIMEOUT) ./... && \
	go run -modfile "$$ACCEPTANCE_WORKDIR/tools/go.mod" github.com/wadey/gocovmerge "$$ACCEPTANCE_WORKDIR/coverage-acceptance.out" > "$(ROOT_DIR)/coverage-acceptance.out"

acceptance-sealights: ## Run all acceptance tests with sealights integration
	@ACCEPTANCE_WORKDIR="$$(mktemp -d)"; \
	cleanup() { \
		cp "$${ACCEPTANCE_WORKDIR}"/features/__snapshots__/* "$(ROOT_DIR)"/features/__snapshots__/; \
	}; \
	trap cleanup EXIT; \
	cp -R . "$$ACCEPTANCE_WORKDIR"; \
	cd "$$ACCEPTANCE_WORKDIR" && \
	$(MAKE) build && \
	export COVERAGE_FILEPATH="$$ACCEPTANCE_WORKDIR"; \
	export COVERAGE_FILENAME="-acceptance"; \
	cd acceptance && SEALIGHTS_LOG_LEVEL=none go run -modfile "$$ACCEPTANCE_WORKDIR/tools/go.mod" gotest.tools/gotestsum --junitfile "$(ROOT_DIR)/junit-acceptance.xml" -- -parallel 1 -timeout $(ACCEPTANCE_TIMEOUT) ./...

# Add @focus above the feature you're hacking on to use this
# (Mainly for use with the feature-% target below)
.PHONY: focus-acceptance
focus-acceptance: build ## Run acceptance tests with @focus tag
	@cd acceptance && go test . -args -tags=@focus

# Uses sed hackery to insert a @focus tag and then remove it afterwards.
# (There might be a nicer way to run all scenarios in a single feature.)
# The `|| true` here is so the @focus tag still gets removed after a failure.
feature_%: ## Run acceptance tests for a single feature file, e.g. make feature_validate_image
	@echo "Testing feature '$*'"
	@sed -i '1i@focus' features/$*.feature
	@$(MAKE) focus-acceptance || true
	@sed -i '1d' features/$*.feature

# (Replace spaces with underscores in the scenario name.)
scenario_%: build ## Run acceptance tests for a single scenario, e.g. make scenario_inline_policy
	@cd acceptance && go test -test.run 'TestFeatures/$*'

benchmark/%/data.tar.gz:
	@cd benchmark/$*
	@./prepare_data.sh

.PHONY: benchmark_%
benchmark_%: benchmark/%/data.tar.gz
	@cd benchmark/$*
	@go run .

.PHONY: benchmark_data
benchmark_data: benchmark/simple/data.tar.gz ## Prepare data for benchmark

.PHONY: benchmark
benchmark: benchmark_simple ## Run benchmarks

.PHONY: ci
ci: test lint-fix acceptance ## Run the usual required CI tasks

##@ Linters

LICENSE_IGNORE=\
-ignore 'dist/cli-reference/*.yaml' \
-ignore 'acceptance/examples/*.yaml' \
-ignore 'configs/*/*.yaml' \
-ignore 'node_modules/**' \
-ignore 'hack/**/charts/**' \
-ignore '.tekton/*.yaml' \
-ignore '.ec/**'

LINT_TO_GITHUB_ANNOTATIONS='map(map(.)[])[][] as $$d | $$d.posn | split(":") as $$posn | "::warning file=\($$posn[0]),line=\($$posn[1]),col=\($$posn[2])::\($$d.message)"'

.PHONY: lint
lint: tekton-lint go-mod-lint ## Run linter
# addlicense doesn't give us a nice explanation so we prefix it with one
	@go run -modfile tools/go.mod github.com/google/addlicense -c '$(COPY)' -y '' -s -check $(LICENSE_IGNORE) . | sed 's/^/Missing license header in: /g'
# piping to sed above looses the exit code, luckily addlicense is fast so we invoke it for the second time to exit 1 in case of issues
	@go run -modfile tools/go.mod github.com/google/addlicense -c '$(COPY)' -y '' -s -check $(LICENSE_IGNORE) . >/dev/null 2>&1
	@go run -modfile tools/go.mod github.com/golangci/golangci-lint/cmd/golangci-lint run --sort-results $(if $(GITHUB_ACTIONS), --timeout=10m0s)
	@(cd acceptance && go run -modfile ../tools/go.mod github.com/golangci/golangci-lint/cmd/golangci-lint run --path-prefix acceptance --sort-results $(if $(GITHUB_ACTIONS), --timeout=10m0s))

.PHONY: lint-fix
lint-fix: ## Fix linting issues automagically
	@go run -modfile tools/go.mod github.com/google/addlicense -c '$(COPY)' -y '' -s $(LICENSE_IGNORE) .
	@go run -modfile tools/go.mod github.com/golangci/golangci-lint/cmd/golangci-lint run --fix
	@(cd acceptance && go run -modfile ../tools/go.mod github.com/golangci/golangci-lint/cmd/golangci-lint run --path-prefix acceptance --fix)
# We don't apply the fixes from the internal (error handling) linter.
# TODO: fix the outstanding error handling lint issues and enable the fixer
#	@go run -modfile tools/go.mod ./internal/lint -fix $$(go list ./... | grep -v '/acceptance/')
	@go run -modfile tools/go.mod github.com/daixiang0/gci write -s standard -s default -s "prefix(github.com/conforma/cli)" .

node_modules: package-lock.json
	@npm ci

TEKTON_LINT_TO_GITHUB_ANNOTATIONS='.[] | "::error file=\(.path),line=\(.loc.startLine),endLine=\(.loc.endLine),col=\(.loc.startColumn),endColumn=\(.loc.endColumn)::\(.message)"'
# wildcard matches `tasks/<task_name>/<version>/*.yaml`
tekton-lint: node_modules $(wildcard tasks/*/*/*.yaml) ## Run tekton-lint for 'tasks' subdirectory.
# We execute tekton-lint for all yaml files contained within the tasks subdirectory, it's smart enough to ignore non-Tekton yaml files.
# All warnings are currently considered errors.
# When running on GitHub Actions, reformat to annotations
	@npm exec tekton-lint -- --max-warnings=0 --format=$(if $(GITHUB_ACTIONS),json,stylish) $(filter-out node_modules,$^)$(if $(GITHUB_ACTIONS), | jq -r $(TEKTON_LINT_TO_GITHUB_ANNOTATIONS))

.PHONY: go-mod-lint
go-mod-lint:
	@echo "Scanning for go.mod files and performing tidy..."
	@find . -name "go.mod" -execdir go mod tidy >/dev/null 2>&1 \;
	@echo "Checking for modified go.mod or go.sum files..."
	@if git status --porcelain | grep -q -e "go.mod" -e "go.sum"; then \
		echo "Ensure the following go.mod or go.sum files are added to the git commit:"; \
		git status --porcelain | grep -e "go.mod" -e "go.sum"; \
	else \
		echo "No go.mod or go.sum files need to be added to the git commit."; \
	fi

##@ Pushing images

IMAGE_TAG ?= latest
IMAGE_REPO ?= quay.io/conforma/cli
.PHONY: build-image
build-image: image_$(BUILD_IMG_ARCH) ## Build container image with ec

.PHONY: push-image
push-image: push_image_$(BUILD_IMG_ARCH) ## Push ec container image to default location

.PHONY: build-snapshot-image
build-snapshot-image: push-image ## Build the ec image and tag it with "snapshot"
	@podman tag $(IMAGE_REPO):$(IMAGE_TAG) $(IMAGE_REPO):snapshot

.PHONY: push-snapshot-image
push-snapshot-image: build-snapshot-image ## Push the ec image with the "snapshot" tag
	@podman push $(PODMAN_OPTS) $(IMAGE_REPO):snapshot

.PHONY: $(ALL_SUPPORTED_IMG_OS_ARCH)
# Targets are in the form of "image_{platform}_{arch}", we set
# TARGETOS={platform}, and TARGETARCH={arch}.
$(ALL_SUPPORTED_IMG_OS_ARCH): TARGETOS=$(word 2,$(subst _, ,$@))
$(ALL_SUPPORTED_IMG_OS_ARCH): TARGETARCH=$(word 3,$(subst _, ,$@))
$(ALL_SUPPORTED_IMG_OS_ARCH):
	@podman build -t $(IMAGE_REPO):$(IMAGE_TAG)-$(TARGETOS)-$(TARGETARCH) -f Dockerfile --platform $(TARGETOS)/$(TARGETARCH) --volume "$$(go env GOCACHE)":/go/cache:Z --volume "$$(go env GOMODCACHE)":/go/mod:Z --env GOCACHE=/go/cache --env GOMODCACHE=/go/mod

# Currently it shows the following:
#  image_linux_amd64
#  image_linux_arm64
#  image_linux_ppc64le
show-supported-builds:
	@for b in $(ALL_SUPPORTED_IMG_OS_ARCH); do echo $$b; done

.PHONY: $(subst image_,push_image_,$(ALL_SUPPORTED_IMG_OS_ARCH))
# Ref: https://www.gnu.org/software/make/manual/make.html#Secondary-Expansion
.SECONDEXPANSION:
# Targets are in the form of "push_image_{platform}_{arch}", we set
# TARGETOS={platform}, and TARGETARCH={arch}. This target depends on the
# "image_{platform}_{arch}" target
$(subst image_,push_image_,$(ALL_SUPPORTED_IMG_OS_ARCH)): TARGETOS=$(word 3,$(subst _, ,$@))
$(subst image_,push_image_,$(ALL_SUPPORTED_IMG_OS_ARCH)): TARGETARCH=$(word 4,$(subst _, ,$@))
$(subst image_,push_image_,$(ALL_SUPPORTED_IMG_OS_ARCH)): image_$$(TARGETOS)_$$(TARGETARCH)
	@podman push $(PODMAN_OPTS) $(IMAGE_REPO):$(IMAGE_TAG)-$(TARGETOS)-$(TARGETARCH)

.PHONY: dist-image
# Depends on targets in the form of "image_{platform}_{arch}"
dist-image: $(ALL_SUPPORTED_IMG_OS_ARCH) ## Build images for all supported platforms/architectures

.PHONY: dist-image-push
ALL_IMAGE_REFS:=$(subst image-,$(IMAGE_REPO):$(IMAGE_TAG)-,$(subst _,-,$(ALL_SUPPORTED_IMG_OS_ARCH)))

dist-image-push: dist-image $(subst image_,push_image_,$(ALL_SUPPORTED_IMG_OS_ARCH)) ## Push images and multi-arch manifest
	@# Push each single-arch image
	@for img in $(ALL_IMAGE_REFS); do \
	  podman push $(PODMAN_OPTS) $$img; \
	done

	@# Recreate the manifest
	@podman manifest rm $(IMAGE_REPO):$(IMAGE_TAG) 2>/dev/null || true
	@podman manifest create $(IMAGE_REPO):$(IMAGE_TAG)

	@# Add each image with the correct os/arch
	@for img in $(ALL_IMAGE_REFS); do \
	  TAG=$${img##*:}; \
	  TARGETOS=$$(echo "$$TAG" | rev | cut -d- -f2 | rev); \
	  TARGETARCH=$$(echo "$$TAG" | rev | cut -d- -f1 | rev); \
	  podman manifest add $(IMAGE_REPO):$(IMAGE_TAG) $(PODMAN_OPTS) "$$img" \
	    --os "$$TARGETOS" --arch "$$TARGETARCH"; \
	done

	@# Push the manifest
	@podman manifest push $(IMAGE_REPO):$(IMAGE_TAG) $(IMAGE_REPO):$(IMAGE_TAG)

ifdef ADD_IMAGE_TAG
	@# Also push any additional tags (like “snapshot”)
	@for tag in $(ADD_IMAGE_TAG); do \
	  podman manifest push $(IMAGE_REPO):$(IMAGE_TAG) $(IMAGE_REPO):$$tag; \
	done
endif

verify-image:
	@podman run --rm $(IMAGE_REPO):$(IMAGE_TAG) version

.PHONY: dev
dev: REGISTRY_PORT=5000
dev: IMAGE_REPO=localhost:$(REGISTRY_PORT)/ec
dev: PODMAN_OPTS=--tls-verify=false
dev: TASK_REPO=localhost:$(REGISTRY_PORT)/ec-task-bundle
dev: SKOPEO_ARGS=--src-tls-verify=false --dest-tls-verify=false
dev: TASKS:=$(shell T=$$(mktemp) && yq e ".spec.steps[].image? = \"localhost:$(REGISTRY_PORT)/ec\"" \
    tasks/verify-enterprise-contract/*/verify-enterprise-contract.yaml \
    tasks/verify-conforma-konflux-ta/*/verify-conforma-konflux-ta.yaml \
    | yq 'select(. != null)' > "$${T}" && echo "$${T}")
dev: push-image task-bundle ## Push the ec and v-e-c Task Bundle to the kind cluster setup via hack/setup-dev-environment.sh
	@rm "$(TASKS)"

TASK_TAG ?= latest
TASK_REPO ?= quay.io/enterprise-contract/ec-task-bundle
TASKS ?= tasks/verify-enterprise-contract/0.1/verify-enterprise-contract.yaml,tasks/verify-conforma-konflux-ta/0.1/verify-conforma-konflux-ta.yaml
ifneq (,$(findstring localhost:,$(TASK_REPO)))
SKOPEO_ARGS=--src-tls-verify=false --dest-tls-verify=false
endif
.PHONY: task-bundle
task-bundle: ## Push the Tekton Task bundle to an image repository
	@go run -modfile tools/go.mod github.com/tektoncd/cli/cmd/tkn bundle push $(TASK_REPO):$(TASK_TAG) $(addprefix -f ,$(TASKS)) --annotate org.opencontainers.image.revision="$(TASK_TAG)"

.PHONY: task-bundle-snapshot
task-bundle-snapshot: task-bundle ## Push task bundle and then tag with "snapshot"
	@skopeo copy "docker://$(TASK_REPO):$(TASK_TAG)" "docker://$(TASK_REPO):snapshot" $(SKOPEO_ARGS)
	echo Tagged $(TASK_REPO):$(TASK_TAG) with snapshot tag
ifdef ADD_TASK_TAG
	@for tag in $(ADD_TASK_TAG); do
	  @skopeo copy "docker://$(TASK_REPO):$(TASK_TAG)" "docker://$(TASK_REPO):$${tag}"
	done
endif

# Useful to compare the `ec test` command source with the `conftest test`
# command source. They should be almost identical.
ifndef DIFF_TOOL
  # I like to use vimdiff for this
  DIFF_TOOL=diff --color=always
endif
.PHONY: conftest-test-cmd-diff
conftest-test-cmd-diff:
	@CONFTEST_VER=$$( go list -m -f '{{ .Version }}' github.com/open-policy-agent/conftest ) && \
	$(DIFF_TOOL) \
	  <(curl -s https://raw.githubusercontent.com/open-policy-agent/conftest/$${CONFTEST_VER}/internal/commands/test.go) \
	  cmd/test/test.go

# Useful while hacking on build numbers and versions
debug-version:
	@echo $(VERSION)

# It's not so hard to do this by hand, but let's save some typing
bump-minor-version:
	@yq ". + 0.1" -i $(VERSION_FILE) && \
	  git add $(VERSION_FILE) && \
	  git commit $(VERSION_FILE) \
	    -m "Bump minor version to $$(cat $(VERSION_FILE))" \
	    -m 'Commit generated with `make bump-minor-version`'

##@ CRD Management

# CRD-related variables
CRD_ROOT = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CONTROLLER_GEN = go run -modfile $(CRD_ROOT)tools/crd/go.mod sigs.k8s.io/controller-tools/cmd/controller-gen
KUSTOMIZE = go run -modfile $(CRD_ROOT)tools/crd/go.mod sigs.k8s.io/kustomize/kustomize/v5
ENVTEST = go run -modfile $(CRD_ROOT)tools/crd/go.mod sigs.k8s.io/controller-runtime/tools/setup-envtest
CRD_DEF = ./api/v1alpha1

CRD_GEN_DEPS=\
 api/v1alpha1/enterprisecontractpolicy_types.go \
 api/v1alpha1/groupversion_info.go \
 tools/crd/go.sum

config/crd/bases/%.yaml: $(CRD_GEN_DEPS)
	$(CONTROLLER_GEN) rbac:roleName=enterprise-contract-role crd webhook paths=./api/... output:crd:artifacts:config=config/crd/bases
	yq -i 'del(.metadata.annotations["controller-gen.kubebuilder.io/version"])' $@

api/config/%.yaml: config/crd/bases/%.yaml
	@mkdir -p api/config
	@cp $< $@

.PHONY: crd-manifests
crd-manifests: api/config/appstudio.redhat.com_enterprisecontractpolicies.yaml ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.

.PHONY: crd-generate
crd-generate: $(CRD_GEN_DEPS) ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths=./api/...
	cd api && go generate ./...

.PHONY: crd-docs
crd-docs: $(wildcard $(CRD_DEF)/*.go) ## Generate CRD documentation
	@go run -modfile tools/crd/go.mod github.com/elastic/crd-ref-docs --max-depth 50 --config=docs/crd/config.yaml --source-path=$(CRD_DEF) --templates-dir=docs/crd/templates --output-path=docs/modules/ROOT/pages/crd-reference.adoc

.PHONY: crd-test
crd-test: crd-manifests crd-generate ## Run CRD tests.
	KUBEBUILDER_ASSETS="$$($(ENVTEST) use $(ENVTEST_K8S_VERSION) -p path)" go test ./... -coverprofile crd_cover.out
	cd api && go test ./... -coverprofile ../api_cover.out
	cd ../schema && go test ./... -coverprofile ../schema_cover.out

.PHONY: crd-export-schema
crd-export-schema: crd-generate ## Export the CRD schema to the schema directory as a json-store.org schema.
	@mkdir -p dist
	cp api/v1alpha1/policy_spec.json dist/

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: crd-install
crd-install: crd-manifests ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: crd-uninstall
crd-uninstall: crd-manifests ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -
