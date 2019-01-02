# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html


.PHONY: clean
clean: ## Clean the working area and the project
	rm -rf bin/ ${BUILD_DIR}/ vendor/
	rm -rf ${BINARY_NAME}

bin/dep: bin/dep-${DEP_VERSION}
	@ln -sf dep-${DEP_VERSION} bin/dep
bin/dep-${DEP_VERSION}:
	@mkdir -p bin
	curl https://raw.githubusercontent.com/golang/dep/master/install.sh | INSTALL_DIRECTORY=bin DEP_RELEASE_TAG=v${DEP_VERSION} sh
	@mv bin/dep $@

.PHONY: vendor
vendor: bin/dep ## Install dependencies
	bin/dep ensure -v -vendor-only

.PHONY: build
build: GOARGS += -tags "${GOTAGS}" -ldflags "${LDFLAGS}"
build: ## Build a binary
ifneq (${IGNORE_GOLANG_VERSION_REQ}, 1)
	@printf "${GOLANG_VERSION}\n$$(go version | awk '{sub(/^go/, "", $$3);print $$3}')" | sort -t '.' -k 1,1 -k 2,2 -k 3,3 -g | head -1 | grep -q -E "^${GOLANG_VERSION}$$" || (printf "Required Go version is ${GOLANG_VERSION}\nInstalled: `go version`" && exit 1)
endif
	go build ${GOARGS} ${BUILD_PACKAGE}

.PHONY: docker-build
docker-build: ## Builds go binary in docker image
	docker run -it -v $(PWD):/go/src/${PACKAGE} -w /go/src/${PACKAGE} golang:${GOLANG_VERSION}-alpine go build -o ${BINARY_NAME}_linux ${BUILD_PACKAGE}

.PHONY: debug
debug: GOARGS += -gcflags "-N -l"
debug: BINARY_NAME := ${BINARY_NAME}-debug
debug: build ## Builds binary package

.PHONY: debug-docker
debug-docker: debug ## Builds binary package
	docker build -t banzaicloud/${BINARY_NAME}:debug -f Dockerfile.dev .

.PHONY: check
check: test lint ## Run tests and linters

bin/golangci-lint: bin/golangci-lint-${GOLANGCI_VERSION}
	@ln -sf golangci-lint-${GOLANGCI_VERSION} bin/golangci-lint
bin/golangci-lint-${GOLANGCI_VERSION}:
	@mkdir -p bin
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | bash -s -- -b ./bin v${GOLANGCI_VERSION}
	@mv bin/golangci-lint $@

.PHONY: lint
lint: bin/golangci-lint ## Run linter
	@bin/golangci-lint run -v

.PHONY: fmt
fmt:
	@gofmt -s -w ${GOFILES_NOVENDOR}

bin/misspell: bin/misspell-${MISSPELL_VERSION}
	@ln -sf misspell-${MISSPELL_VERSION} bin/misspell
bin/misspell-${MISSPELL_VERSION}:
	@mkdir -p bin
	curl -sfL https://git.io/misspell | bash -s -- -b ./bin/ v${MISSPELL_VERSION}
	@mv bin/misspell $@

.PHONY: misspell
misspell: bin/misspell ## Fix spelling mistakes
	misspell -w ${GOFILES_NOVENDOR}

bin/licensei: bin/licensei-${LICENSEI_VERSION}
	@ln -sf licensei-${LICENSEI_VERSION} bin/licensei
bin/licensei-${LICENSEI_VERSION}:
	@mkdir -p bin
	curl -sfL https://raw.githubusercontent.com/goph/licensei/master/install.sh | bash -s v${LICENSEI_VERSION}
	@mv bin/licensei $@

.PHONY: license-check
license-check: bin/licensei ## Run license check
	bin/licensei check
	./scripts/check-header.sh

.PHONY: license-cache
license-cache: bin/licensei ## Generate license cache
	bin/licensei cache

.PHONY: test
test:
	set -oe pipefail; go list ./... | xargs -n1 go test ${GOARGS} -v -parallel 1 2>&1 | tee test.txt

bin/go-junit-report:
	@mkdir -p bin
	GOBIN=${PWD}/bin/ go get -u github.com/jstemmer/go-junit-report

.PHONY: junit-report
junit-report: bin/go-junit-report # Generate test reports
	@mkdir -p build
	cat test.txt | bin/go-junit-report > build/report.xml

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
