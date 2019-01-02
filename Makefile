# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

# Project variables
PACKAGE = github.com/banzaicloud/bank-vaults
BINARY_NAME ?= bank-vaults
DOCKER_IMAGE = banzaicloud/bank-vaults
OPERATOR_DOCKER_IMAGE = banzaicloud/vault-operator

# Build variables
BUILD_DIR ?= build
BUILD_PACKAGE = ${PACKAGE}/cmd/...
VERSION ?= $(shell git symbolic-ref -q --short HEAD || git describe --tags --exact-match)
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_DATE ?= $(shell date +%FT%T%z)
LDFLAGS += -X main.version=${VERSION} -X main.commitHash=${COMMIT_HASH} -X main.buildDate=${BUILD_DATE}
export CGO_ENABLED ?= 0
export GOOS = $(shell go env GOOS)
ifeq (${VERBOSE}, 1)
	GOARGS += -v
endif

# Docker variables
DOCKER_TAG ?= ${VERSION}

# Dependency versions
DEP_VERSION = 0.5.0
GOLANGCI_VERSION = 1.12.2
LICENSEI_VERSION = 0.0.7

GOLANG_VERSION = 1.11

## include "generic" targets
include main-targets.mk

.PHONY: up
up: vendor ## Set up the development environment


.PHONY: down
down: clean ## Destroy the development environment


.PHONY: reset
reset: down up ## Reset the development environment


.PHONY: build-release
build-release: LDFLAGS += -w
build-release: build ## Build a binary without debug information

.PHONY: build-debug
build-debug: GOARGS += -gcflags "all=-N -l"
build-debug: BINARY_NAME_SUFFIX += debug
build-debug: build ## Build a binary with remote debugging capabilities

.PHONY: docker
docker: ## Build a Docker image
	docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} -f Dockerfile .
ifeq (${DOCKER_LATEST}, 1)
	docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:latest
endif

.PHONY: docker-push
docker-push: ## Push a Docker image
	docker push ${DOCKER_IMAGE}:${DOCKER_TAG}
ifeq (${DOCKER_LATEST}, 1)
	docker push ${DOCKER_IMAGE}:latest
endif

.PHONY: docker-operator
docker-operator: ## Build a Docker image for the Operator
	docker build -t ${OPERATOR_DOCKER_IMAGE}:${DOCKER_TAG} -f Dockerfile.operator .
ifeq (${DOCKER_LATEST}, 1)
	docker tag ${OPERATOR_DOCKER_IMAGE}:${DOCKER_TAG} ${OPERATOR_DOCKER_IMAGE}:latest
endif

.PHONY: docker-operator-push
docker-operator-push: ## Push a Docker image for the Operator
	docker push ${OPERATOR_DOCKER_IMAGE}:${DOCKER_TAG}
ifeq (${DOCKER_LATEST}, 1)
	docker push ${OPERATOR_DOCKER_IMAGE}:latest
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

