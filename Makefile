# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

export PATH := $(abspath bin/):${PATH}

##@ General

# Targets commented with ## will be visible in "make help" info.
# Comments marked with ##@ will be used as categories for a group of targets.

.PHONY: help
default: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: up
up: ## Start development environment
	docker compose up -d

.PHONY: stop
stop: ## Stop development environment
	docker compose stop

.PHONY: down
down: ## Destroy development environment
	docker compose down -v

##@ Build

.PHONY: build
build: ## Build binary
	@mkdir -p build
	go build -race -o build/ ./cmd/bank-vaults

.PHONY: container-image
container-image: ## Build container image
	docker build .

.PHONY: binary-snapshot
binary-snapshot: ## Build binary snapshot
	VERSION=v${GORELEASER_VERSION} ${GORELEASER_BIN} release --clean --skip=publish --snapshot

.PHONY: artifacts
artifacts: container-image binary-snapshot
artifacts: ## Build artifacts

##@ Checks

.PHONY: check
check: test test-integration lint ## Run tests and linters

.PHONY: test
test: ## Run tests
	go test -race -v ./...

.PHONY: test-integration
test-integration: ## Run integration tests
	go test -race -v -tags=integration ./...

.PHONY: lint
lint: lint-go lint-docker lint-yaml
lint: ## Run linters

.PHONY: lint-go
lint-go:
	$(GOLANGCI_LINT_BIN) run $(if ${CI},--out-format colored-line-number,)

.PHONY: lint-docker
lint-docker:
	hadolint Dockerfile

.PHONY: lint-yaml
lint-yaml:
	yamllint $(if ${CI},-f github,) --no-warnings .

.PHONY: fmt
fmt: ## Format code
	$(GOLANGCI_LINT_BIN) run --fix

.PHONY: license-check
license-check: ## Run license check
	$(LICENSEI_BIN) check
	$(LICENSEI_BIN) header

##@ Autogeneration

.PHONY: generate
generate: gen-docs
generate: ## Run generation jobs

.PHONY: gen-docs
gen-docs: ## Generate CLI documentation
	@mkdir -p "build/docs"
	go run -tags=gen_docs ./cmd/bank-vaults gen-docs "build/docs"

##@ Dependencies

deps: bin/golangci-lint bin/licensei bin/cosign bin/goreleaser
deps: ## Install dependencies

# Dependency versions
GOLANGCI_VERSION = 1.59.1
LICENSEI_VERSION = 0.9.0
COSIGN_VERSION = 2.2.4
GORELEASER_VERSION = 2.0.0

# Dependency binaries
GOLANGCI_LINT_BIN := golangci-lint
LICENSEI_BIN := licensei
COSIGN_BIN := cosign
GORELEASER_BIN := goreleaser

# TODO: add support for hadolint and yamllint dependencies
HADOLINT_BIN := hadolint
YAMLLINT_BIN := yamllint

# If we have "bin" dir, use those binaries instead
ifneq ($(wildcard ./bin/.),)
	GOLANGCI_LINT_BIN := bin/$(GOLANGCI_LINT_BIN)
	LICENSEI_BIN := bin/$(LICENSEI_BIN)
	COSIGN_BIN := bin/$(COSIGN_BIN)
	GORELEASER_BIN := bin/$(GORELEASER_BIN)
endif

bin/golangci-lint:
	@mkdir -p bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | bash -s -- v${GOLANGCI_VERSION}

bin/licensei:
	@mkdir -p bin
	curl -sfL https://raw.githubusercontent.com/goph/licensei/master/install.sh | bash -s -- v${LICENSEI_VERSION}

bin/cosign:
	@mkdir -p bin
	@OS=$$(uname -s); \
	case $$OS in \
		"Linux") \
			curl -sSfL https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64 -o bin/cosign; \
			;; \
		"Darwin") \
			curl -sSfL https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-darwin-arm64 -o bin/cosign; \
			;; \
		*) \
			echo "Unsupported OS: $$OS"; \
			exit 1; \
			;; \
	esac
	@chmod +x bin/cosign

bin/goreleaser:
	@mkdir -p bin
	curl -sfL https://goreleaser.com/static/run -o bin/goreleaser
	@chmod +x bin/goreleaser
