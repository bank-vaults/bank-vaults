# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

export PATH := $(abspath bin/):${PATH}

CONTAINER_IMAGE_REF = ghcr.io/bank-vaults/bank-vaults:dev

# Dependency versions
GOLANGCI_VERSION = 1.53.3
LICENSEI_VERSION = 0.8.0

.PHONY: build
build: ## Build binary
	@mkdir -p build
	go build -race -o build/ ./cmd/bank-vaults

.PHONY: lint
lint: lint-go lint-docker lint-yaml
lint: ## Run linters

.PHONY: lint-go
lint-go:
	golangci-lint run $(if ${CI},--out-format github-actions,)

.PHONY: lint-docker
lint-docker:
	hadolint Dockerfile

.PHONY: lint-yaml
lint-yaml:
	yamllint $(if ${CI},-f github,) --no-warnings .

.PHONY: fmt
fmt: ## Format code
	golangci-lint run --fix

.PHONY: license-check
license-check: ## Run license check
	licensei check
	licensei header

deps: bin/golangci-lint bin/licensei
deps: ## Install dependencies

bin/golangci-lint:
	@mkdir -p bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | bash -s -- v${GOLANGCI_VERSION}

bin/licensei:
	@mkdir -p bin
	curl -sfL https://raw.githubusercontent.com/goph/licensei/master/install.sh | bash -s -- v${LICENSEI_VERSION}





















OS = $(shell uname)

DOCKER_BUILD_EXTRA_ARGS ?=
# Export HOST_NETWORK=1 if you want to build the docker images with host network (useful when using some VPNs)
ifeq (${HOST_NETWORK}, 1)
	DOCKER_BUILD_EXTRA_ARGS += --network host
endif

# Project variables
PACKAGE = github.com/bank-vaults/bank-vaults
BINARY_NAME ?= bank-vaults
DOCKER_REGISTRY ?= ghcr.io/bank-vaults
DOCKER_IMAGE = ${DOCKER_REGISTRY}/bank-vaults
WEBHOOK_DOCKER_IMAGE = ${DOCKER_REGISTRY}/vault-secrets-webhook

# Build variables
BUILD_DIR ?= build
BUILD_PACKAGE = ${PACKAGE}/cmd/...
VERSION ?= $(shell echo `git symbolic-ref -q --short HEAD || git describe --tags --exact-match` | tr '[/]' '-')
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_DATE ?= $(shell date +%FT%T%z)
LDFLAGS += -X main.version=${VERSION} -X main.commitHash=${COMMIT_HASH} -X main.buildDate=${BUILD_DATE}
export CGO_ENABLED ?= 1
export GOOS = $(shell go env GOOS)
ifeq (${VERBOSE}, 1)
	GOARGS += -v
endif

# Docker variables
DOCKER_TAG ?= ${VERSION}

# Dependency versions
GOTESTSUM_VERSION = 0.4.0

GOLANG_VERSION = 1.19.2


.PHONY: docker
docker: ## Build a Docker image
	docker build ${DOCKER_BUILD_EXTRA_ARGS} -t ${DOCKER_IMAGE}:${DOCKER_TAG} -f Dockerfile .
ifeq (${DOCKER_LATEST}, 1)
	docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:latest
endif

.PHONY: image
image: ## Build an OCI image with buildah
	buildah bud -t ${DOCKER_IMAGE}:${DOCKER_TAG} -f Dockerfile .
ifeq (${IMAGE_LATEST}, 1)
	buildah tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:latest
endif

.PHONY: docker-push
docker-push: ## Push a Docker image
	docker push ${DOCKER_IMAGE}:${DOCKER_TAG}
ifeq (${DOCKER_LATEST}, 1)
	docker push ${DOCKER_IMAGE}:latest
endif

.PHONY: test-%
test-%: ## Run a specific test suite
	@${MAKE} VERBOSE=0 GOTAGS=$* test


release-%: ## Release a new version
	git tag -m 'Release $*' $*

	@echo "Version updated to $*!"
	@echo
	@echo "To push the changes execute the following:"
	@echo
	@echo "git push; git push origin $*"

.PHONY: patch
patch: ## Release a new patch version
	@${MAKE} release-$(shell git describe --abbrev=0 --tags | awk -F'[ .]' '{print $$1"."$$2"."$$3+1}')

.PHONY: minor
minor: ## Release a new minor version
	@${MAKE} release-$(shell git describe --abbrev=0 --tags | awk -F'[ .]' '{print $$1"."$$2+1".0"}')

.PHONY: major
major: ## Release a new major version
	@${MAKE} release-$(shell git describe --abbrev=0 --tags | awk -F'[ .]' '{print $$1+1".0.0"}')

.PHONY: clean
clean: ## Clean builds
	rm -rf ${BUILD_DIR}/

.PHONY: clear
clear: ## Clear the working area and the project
	rm -rf bin/ vendor/


.PHONY: docker-build
docker-build: ## Builds go binary in docker image
	docker run -it -v $(PWD):/go/src/${PACKAGE} -w /go/src/${PACKAGE} golang:${GOLANG_VERSION}-alpine go build -o ${BINARY_NAME}_linux ${BUILD_PACKAGE}

.PHONY: debug
debug: GOARGS += -gcflags "-N -l"
debug: BINARY_NAME := ${BINARY_NAME}-debug
debug: build ## Builds binary package

.PHONY: debug-docker
debug-docker: debug ## Builds binary package
	docker build -t ghcr.io/bank-vaults/${BINARY_NAME}:debug -f Dockerfile.dev .

.PHONY: check
check: test-integration ## Run tests and linters

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

.PHONY: test-all
test-all: ## Run all tests
	@${MAKE} GOARGS="${GOARGS} -run .\*" TEST_REPORT=all test

.PHONY: test-integration
test-integration: ## Run integration tests
	@${MAKE} GOARGS="${GOARGS} -tags=integration" TEST_REPORT=integration test

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
