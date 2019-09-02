# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

OS = $(shell uname)

# Project variables
PACKAGE = github.com/banzaicloud/bank-vaults
BINARY_NAME ?= bank-vaults
DOCKER_REGISTRY ?= banzaicloud
DOCKER_IMAGE = ${DOCKER_REGISTRY}/bank-vaults
WEBHOOK_DOCKER_IMAGE = ${DOCKER_REGISTRY}/vault-secrets-webhook
OPERATOR_DOCKER_IMAGE = ${DOCKER_REGISTRY}/vault-operator
VAULT_ENV_DOCKER_IMAGE = ${DOCKER_REGISTRY}/vault-env

# Build variables
BUILD_DIR ?= build
BUILD_PACKAGE = ${PACKAGE}/cmd/...
VERSION ?= $(shell echo `git symbolic-ref -q --short HEAD || git describe --tags --exact-match` | tr '[/]' '-')
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
GOTESTSUM_VERSION = 0.3.2
GOLANGCI_VERSION = 1.12.2
LICENSEI_VERSION = 0.1.0

GOLANG_VERSION = 1.12
GOPROXY ?= ""

## include "generic" targets
include main-targets.mk

.PHONY: up
up: ## Set up the development environment

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
	docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} --build-arg GOPROXY=${GOPROXY} -f Dockerfile .
ifeq (${DOCKER_LATEST}, 1)
	docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:latest
endif

.PHONY: docker-webhook
docker-webhook: ## Build a Docker-webhook image
	docker build -t ${WEBHOOK_DOCKER_IMAGE}:${DOCKER_TAG} --build-arg GOPROXY=${GOPROXY} -f Dockerfile.webhook .
ifeq (${DOCKER_LATEST}, 1)
	docker tag ${WEBHOOK_DOCKER_IMAGE}:${DOCKER_TAG} ${WEBHOOK_DOCKER_IMAGE}:latest
endif

.PHONY: docker-vault-env
docker-vault-env: ## Build a Docker-vault-env image
	docker build -t ${VAULT_ENV_DOCKER_IMAGE}:${DOCKER_TAG} --build-arg GOPROXY=${GOPROXY} -f Dockerfile.vault-env .
ifeq (${DOCKER_LATEST}, 1)
	docker tag ${VAULT_ENV_DOCKER_IMAGE}:${DOCKER_TAG} ${VAULT_ENV_DOCKER_IMAGE}:latest
endif

.PHONY: docker-push
docker-push: ## Push a Docker image
	docker push ${DOCKER_IMAGE}:${DOCKER_TAG}
ifeq (${DOCKER_LATEST}, 1)
	docker push ${DOCKER_IMAGE}:latest
endif

.PHONY: docker-operator
docker-operator: ## Build a Docker image for the Operator
	docker build -t ${OPERATOR_DOCKER_IMAGE}:${DOCKER_TAG} --build-arg GOPROXY=${GOPROXY} -f Dockerfile.operator .
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

.PHONY: operator-up
operator-up:
	kubectl apply -f operator/deploy/crd.yaml
	kubectl apply -f operator/deploy/rbac.yaml
	OPERATOR_NAME=vault-dev go run operator/cmd/manager/main.go -verbose

.PHONY: operator-down
operator-down:
	kubectl delete -f operator/deploy/crd.yaml
	kubectl delete -f operator/deploy/rbac.yaml

.PHONY: webhook-run
webhook-run: ## Install the webhook chart and run the webhook locally
	helm upgrade --install vault-secrets-webhook charts/vault-secrets-webhook --namespace vault-infra --set replicaCount=0
	go run ./cmd/vault-secrets-webhook

.PHONY: webhook-forward ## Run kurun to port-forward the local webhook into Kubernetes
webhook-forward:
	kurun port-forward localhost:8443 --namespace vault-infra --servicename vault-secrets-webhook --tlssecret vault-secrets-webhook

.PHONY: webhook-up ## Run the webhook and `kurun port-forward` in foreground. Use with make -j.
webhook-up: webhook-run webhook-forward
