# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.PHONY: clean
clean: ## Clean builds
	rm -rf ${BUILD_DIR}/

.PHONY: clear
clear: ## Clear the working area and the project
	rm -rf bin/ vendor/

.PHONY: build
build: ## Build a binary
ifneq (${IGNORE_GOLANG_VERSION_REQ}, 1)
	@printf "${GOLANG_VERSION}\n$$(go version | awk '{sub(/^go/, "", $$3);print $$3}')" | sort -t '.' -k 1,1 -k 2,2 -k 3,3 -g | head -1 | grep -q -E "^${GOLANG_VERSION}$$" || (printf "Required Go version is ${GOLANG_VERSION}\nInstalled: `go version`" && exit 1)
endif
	go build ${GOARGS} -tags "${GOTAGS}" -ldflags "${LDFLAGS}" ${BUILD_PACKAGE}

.PHONY: docker-build
docker-build: ## Builds go binary in docker image
	docker run -it -v $(PWD):/go/src/${PACKAGE} -w /go/src/${PACKAGE} golang:${GOLANG_VERSION}-alpine go build -o ${BINARY_NAME}_linux ${BUILD_PACKAGE}

.PHONY: debug
debug: GOARGS += -gcflags "-N -l"
debug: BINARY_NAME := ${BINARY_NAME}-debug
debug: build ## Builds binary package

.PHONY: debug-docker
debug-docker: debug ## Builds binary package
	docker build -t ghcr.io/banzaicloud/${BINARY_NAME}:debug -f Dockerfile.dev .

bin/golangci-lint: bin/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} bin/golangci-lint
bin/golangci-lint-${GOLANGCI_VERSION}:
	@mkdir -p bin
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | bash -s -- -b ./bin/ v${GOLANGCI_VERSION}
	@mv bin/golangci-lint $@

.PHONY: lint
lint: bin/golangci-lint ## Run linter
	bin/golangci-lint run

.PHONY: lint-sdk
lint-sdk: bin/golangci-lint ## Run linter
	cd pkg/sdk && ../../bin/golangci-lint run

.PHONY: fix
fix: bin/golangci-lint ## Fix lint violations
	bin/golangci-lint run --fix

.PHONY: fix-sdk
fix-sdk: bin/golangci-lint ## Fix lint violations
	cd pkg/sdk && ../../bin/golangci-lint run --fix

bin/licensei: bin/licensei-${LICENSEI_VERSION}
	@ln -sf licensei-${LICENSEI_VERSION} bin/licensei
bin/licensei-${LICENSEI_VERSION}:
	@mkdir -p bin
	curl -sfL https://raw.githubusercontent.com/goph/licensei/master/install.sh | bash -s v${LICENSEI_VERSION}
	@mv bin/licensei $@

.PHONY: license-check
license-check: bin/licensei ## Run license check
	bin/licensei check
	bin/licensei header

.PHONY: license-cache
license-cache: bin/licensei ## Generate license cache
	bin/licensei cache

.PHONY: check
check: lint lint-sdk test-integration test-sdk-integration ## Run tests and linters

bin/gotestsum: bin/gotestsum-${GOTESTSUM_VERSION}
	@ln -sf gotestsum-${GOTESTSUM_VERSION} bin/gotestsum
bin/gotestsum-${GOTESTSUM_VERSION}:
	@mkdir -p bin
	curl -L https://github.com/gotestyourself/gotestsum/releases/download/v${GOTESTSUM_VERSION}/gotestsum_${GOTESTSUM_VERSION}_${OS}_amd64.tar.gz | tar -zOxf - gotestsum > ./bin/gotestsum-${GOTESTSUM_VERSION} && chmod +x ./bin/gotestsum-${GOTESTSUM_VERSION}

TEST_PKGS ?= ./...
TEST_REPORT_NAME ?= results.xml
.PHONY: test
test: TEST_REPORT ?= main
test: TEST_FORMAT ?= short
test: SHELL = /bin/bash
test: bin/gotestsum ## Run tests
	@mkdir -p ${BUILD_DIR}/test_results/${TEST_REPORT}
	bin/gotestsum --no-summary=skipped --junitfile ${BUILD_DIR}/test_results/${TEST_REPORT}/${TEST_REPORT_NAME} --format ${TEST_FORMAT} -- $(filter-out -v,${GOARGS}) $(if ${TEST_PKGS},${TEST_PKGS},./...)

test-sdk: TEST_REPORT ?= sdk
test-sdk: TEST_FORMAT ?= short
test-sdk: SHELL = /bin/bash
test-sdk: bin/gotestsum ## Run SDK tests
	@mkdir -p ${BUILD_DIR}/test_results/${TEST_REPORT}
	cd pkg/sdk && ../../bin/gotestsum --no-summary=skipped --junitfile ../../${BUILD_DIR}/test_results/${TEST_REPORT}/${TEST_REPORT_NAME} --format ${TEST_FORMAT} -- $(filter-out -v,${GOARGS}) $(if ${TEST_PKGS},${TEST_PKGS},./...)

.PHONY: test-all
test-all: ## Run all tests
	@${MAKE} GOARGS="${GOARGS} -run .\*" TEST_REPORT=all test

.PHONY: test-integration
test-integration: ## Run integration tests
	@${MAKE} GOARGS="${GOARGS} -tags=integration" TEST_REPORT=integration test

.PHONY: test-sdk-integration
test-sdk-integration: ## Run integration tests in sdk package
	@${MAKE} GOARGS="${GOARGS} -tags=integration" TEST_REPORT=integration test-sdk

bin/jq: bin/jq-${JQ_VERSION}
	@ln -sf jq-${JQ_VERSION} bin/jq
bin/jq-${JQ_VERSION}:
	@mkdir -p bin
ifeq (${OS}, Darwin)
	curl -L https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-osx-amd64 > ./bin/jq-${JQ_VERSION} && chmod +x ./bin/jq-${JQ_VERSION}
endif
ifeq (${OS}, Linux)
	curl -L https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-linux64 > ./bin/jq-${JQ_VERSION} && chmod +x ./bin/jq-${JQ_VERSION}
endif

.PHONY: list
list: ## List all make targets
	@$(MAKE) -pRrn : -f $(MAKEFILE_LIST) 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | sort

.PHONY: help
.DEFAULT_GOAL := help
help:
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Variable outputting/exporting rules
var-%: ; @echo $($*)
varexport-%: ; @echo $*=$($*)


.PHONY: generate-code
generate-code: ## Regenerate clientset, deepcopy funcs, listers and informers
	./hack/update-codegen.sh v${CODE_GENERATOR_VERSION}

bin/controller-gen-${CONTROLLER_GEN_VERSION}:
	set -ex ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	GOBIN=$(PWD)/bin/controller-gen-${CONTROLLER_GEN_VERSION} go get sigs.k8s.io/controller-tools/cmd/controller-gen@${CONTROLLER_GEN_VERSION} ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR

bin/controller-gen: bin/controller-gen-${CONTROLLER_GEN_VERSION}
	ln -sf controller-gen-${CONTROLLER_GEN_VERSION}/controller-gen bin/controller-gen

.PHONY: generate-crds
generate-crds: bin/controller-gen ## Regenerate CRDs in the Helm chart and examples
	bin/controller-gen crd:maxDescLen=0,preserveUnknownFields=false paths=./operator/... output:crd:artifacts:config=./operator/deploy/
	cp operator/deploy/vault.banzaicloud.com_vaults.yaml charts/vault-operator/crds/crd.yaml
	cp operator/deploy/vault.banzaicloud.com_vaults.yaml operator/deploy/crd.yaml
	rm operator/deploy/vault.banzaicloud.com_vaults.yaml
