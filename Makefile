REGISTRY := banzaicloud
IMAGE_NAME := bank-vaults
BUILD_TAG := build
IMAGE_TAGS := $(shell git rev-parse --abbrev-ref HEAD)

BUILD_IMAGE_NAME := golang:1.10

GOPATH ?= /tmp/go

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

.builder_image:
	docker pull ${BUILD_IMAGE_NAME}

# Builder image targets
#######################
docker_%: .builder_image
	docker run -it \
		-v ${GOPATH}/src:/go/src \
		-v $(shell pwd):/go/src/${GO_PKG} \
		-w /go/src/${GO_PKG} \
		-e GOPATH=/go \
		${BUILD_IMAGE_NAME} \
		/bin/sh -c "make $*"

# Docker targets
################
docker_build:
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(BUILD_TAG) .

docker_push: docker_build
	set -e; \
		for tag in $(IMAGE_TAGS); do \
		docker tag $(REGISTRY)/$(IMAGE_NAME):$(BUILD_TAG) $(REGISTRY)/$(IMAGE_NAME):$${tag} ; \
		docker push $(REGISTRY)/$(IMAGE_NAME):$${tag}; \
	done

# Go targets
#################
go_verify: go_fmt go_vet go_test

go_build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w -X main.version=$(CI_COMMIT_TAG) -X main.commit=$(CI_COMMIT_SHA) -X main.date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)' -o bank-vaults_linux_amd64 ./cmd/bank-vaults

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
