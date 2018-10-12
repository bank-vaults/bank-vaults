REGISTRY := banzaicloud
IMAGE_NAME := bank-vaults
IMAGE_NAME_OPERATOR := vault-operator
IMAGE_TAG := $(shell git rev-parse --abbrev-ref HEAD)

GOPATH ?= /tmp/go

GOFILES_NOVENDOR = $(shell find . -type f -name '*.go' -not -path "./vendor/*")
PKGS=$(shell go list ./... | grep -v /vendor)


CI_COMMIT_TAG ?= unknown
CI_COMMIT_SHA ?= unknown

help:
	# all 		- runs verify, build and docker_build targets
	# test 		- runs go_test target
	# build 	- runs go_build target
	# verify 	- verifies generated files & scripts

# Util targets
##############
.PHONY: all build verify

all: verify build docker_build

build: go_build

verify: go_verify

.PHONY: list
list:
	@$(MAKE) -pRrn : -f $(MAKEFILE_LIST) 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | sort

# Docker targets
################
docker_build:
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) .

docker_push: docker_build
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

docker_build_operator:
	docker build -t $(REGISTRY)/$(IMAGE_NAME_OPERATOR):$(IMAGE_TAG) -f Dockerfile.operator .

docker_push_operator: docker_build_operator
	docker push $(REGISTRY)/$(IMAGE_NAME_OPERATOR):$(IMAGE_TAG)

# Go targets
#################
go_verify: go_fmt go_vet go_lint check-misspell go_test

go_build:
	go build -a -tags netgo -ldflags '-w -X main.version=$(CI_COMMIT_TAG) -X main.commit=$(CI_COMMIT_SHA) -X main.date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)' ./cmd/...

go_test:
	go test $$(go list ./... | grep -v '/vendor/')

go_fmt:
	@set -e; \
	GO_FMT=$$(git ls-files *.go | grep -v 'vendor/' | xargs gofmt -d); \
	if [ -n "$${GO_FMT}" ] ; then \
		echo "Please run go fmt"; \
		echo "$$GO_FMT"; \
		exit 1; \
	fi

go_vet:
	go vet $$(go list ./... | grep -v '/vendor/')

go_lint: install-golint
	golint -min_confidence 0.9 -set_exit_status $(PKGS)

install-golint:
	GOLINT_CMD=$(shell command -v golint 2> /dev/null)
ifndef GOLINT_CMD
	go get golang.org/x/lint/golint
endif

check-misspell: install-misspell
	PKGS="${GOFILES_NOVENDOR}" MISSPELL="misspell" ./scripts/misspell-check.sh

misspell: install-misspell
	misspell -w ${GOFILES_NOVENDOR}

install-misspell:
	MISSPELL_CMD=$(shell command -v misspell 2> /dev/null)
ifndef MISSPELL_CMD
	go get -u github.com/client9/misspell/cmd/misspell
endif

clean-vendor:
	find ./vendor -type l | xargs rm -rf

# Vendoring and Licensing targets
#################################

LICENSEI_VERSION = 0.0.7
bin/licensei: ## Install license checker
	@mkdir -p ./bin/
	curl -sfL https://raw.githubusercontent.com/goph/licensei/master/install.sh | bash -s v${LICENSEI_VERSION}

.PHONY: license-check
license-check: bin/licensei ## Run license check
	@bin/licensei check

.PHONY: license-cache
license-cache: bin/licensei ## Generate license cache
	@bin/licensei cache

DEP_VERSION = 0.5.0
bin/dep:
	@mkdir -p ./bin/
	@curl https://raw.githubusercontent.com/golang/dep/master/install.sh | INSTALL_DIRECTORY=./bin DEP_RELEASE_TAG=v${DEP_VERSION} sh

.PHONY: vendor
vendor: bin/dep ## Install dependencies
	bin/dep ensure -v -vendor-only
