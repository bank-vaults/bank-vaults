# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

TEST?=$$(go list ./... | grep -v /vendor/ | grep -v /integ)
VETARGS?=-asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr
EXTERNAL_TOOLS=\
	github.com/elazarl/go-bindata-assetfs/... \
	github.com/hashicorp/go-bindata/... \
	github.com/mitchellh/gox \
	github.com/kardianos/govendor \
	github.com/client9/misspell/cmd/misspell
BUILD_TAGS?=vault
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)

GO_VERSION_MIN=1.10

default: dev

# bin generates the releasable binaries for Vault
bin: prep
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS) ui' sh -c "'$(CURDIR)/scripts/build.sh'"

# dev creates binaries for testing Vault locally. These are put
# into ./bin/ as well as $GOPATH/bin
dev: prep
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
dev-ui: prep
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS) ui' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
dev-dynamic: prep
	@CGO_ENABLED=1 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

# test runs the unit tests and vets the code
test: prep
	@CGO_ENABLED=0 \
	VAULT_ADDR= \
	VAULT_TOKEN= \
	VAULT_DEV_ROOT_TOKEN_ID= \
	VAULT_ACC= \
	go test -tags='$(BUILD_TAGS)' $(TEST) $(TESTARGS) -timeout=20m -parallel=20

testcompile: prep
	@for pkg in $(TEST) ; do \
		go test -v -c -tags='$(BUILD_TAGS)' $$pkg -parallel=4 ; \
	done

# testacc runs acceptance tests
testacc: prep
	@if [ "$(TEST)" = "./..." ]; then \
		echo "ERROR: Set TEST to a specific package"; \
		exit 1; \
	fi
	VAULT_ACC=1 go test -tags='$(BUILD_TAGS)' $(TEST) -v $(TESTARGS) -timeout 45m

# testrace runs the race checker
testrace: prep
	@CGO_ENABLED=1 \
	VAULT_ADDR= \
	VAULT_TOKEN= \
	VAULT_DEV_ROOT_TOKEN_ID= \
	VAULT_ACC= \
	go test -tags='$(BUILD_TAGS)' -race $(TEST) $(TESTARGS) -timeout=45m -parallel=20

cover:
	./scripts/coverage.sh --html

# vet runs the Go source code static analysis tool `vet` to find
# any common errors.
vet:
	@go list -f '{{.Dir}}' ./... | grep -v /vendor/ \
		| grep -v '.*github.com/hashicorp/vault$$' \
		| xargs go tool vet ; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Vet found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi

# prep runs `go generate` to build the dynamically generated
# source files.
prep: fmtcheck
	@sh -c "'$(CURDIR)/scripts/goversioncheck.sh' '$(GO_VERSION_MIN)'"
	go generate $(go list ./... | grep -v /vendor/)
	@if [ -d .git/hooks ]; then cp .hooks/* .git/hooks/; fi

# bootstrap the build by downloading additional tools
bootstrap:
	@for tool in  $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		go get -u $$tool; \
	done

update-plugins:
	grep vault-plugin- vendor/vendor.json | cut -d '"' -f 4 | xargs govendor fetch

static-assets:
	@echo "--> Generating static assets"
	@go-bindata-assetfs -o bindata_assetfs.go -pkg http -prefix pkg -modtime 1480000000 ./pkg/web_ui/...
	@mv bindata_assetfs.go http
	@$(MAKE) -f $(THIS_FILE) fmt

test-ember:
	@echo "--> Installing JavaScript assets"
	@cd ui && yarn install && bower install && yarn install phantomjs-prebuilt
	@echo "--> Running ember tests"
	@cd ui && node_modules/phantomjs-prebuilt/bin/phantomjs --version
	@cd ui && npm test

ember-dist:
	@echo "--> Installing JavaScript assets"
	@cd ui && yarn install && bower install --allow-root
	@cd ui && npm rebuild node-sass
	@echo "--> Building Ember application"
	@cd ui && npm run build
	@rm -rf ui/if-you-need-to-delete-this-open-an-issue-async-disk-cache

static-dist: ember-dist static-assets

proto:
	protoc -I helper/forwarding -I vault -I ../../.. vault/*.proto --go_out=plugins=grpc:vault
	protoc -I helper/storagepacker helper/storagepacker/types.proto --go_out=plugins=grpc:helper/storagepacker
	protoc -I helper/forwarding -I vault -I ../../.. helper/forwarding/types.proto --go_out=plugins=grpc:helper/forwarding
	protoc -I physical physical/types.proto --go_out=plugins=grpc:physical
	protoc -I helper/identity -I ../../.. helper/identity/types.proto --go_out=plugins=grpc:helper/identity
	protoc  builtin/logical/database/dbplugin/*.proto --go_out=plugins=grpc:.
	protoc  logical/plugin/pb/*.proto --go_out=plugins=grpc:.
	sed -i -e 's/Idp/IDP/' -e 's/Url/URL/' -e 's/Id/ID/' -e 's/EntityId/EntityID/' -e 's/Api/API/' -e 's/Qr/QR/' -e 's/protobuf:"/sentinel:"" protobuf:"/' helper/identity/types.pb.go helper/storagepacker/types.pb.go logical/plugin/pb/backend.pb.go
	sed -i -e 's/Iv/IV/' -e 's/Hmac/HMAC/' physical/types.pb.go

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

fmt:
	gofmt -w $(GOFMT_FILES)

spellcheck:
	@echo "==> Spell checking website..."
	@misspell -error -source=text website/source

mysql-database-plugin:
	@CGO_ENABLED=0 go build -o bin/mysql-database-plugin ./plugins/database/mysql/mysql-database-plugin

mysql-legacy-database-plugin:
	@CGO_ENABLED=0 go build -o bin/mysql-legacy-database-plugin ./plugins/database/mysql/mysql-legacy-database-plugin

cassandra-database-plugin:
	@CGO_ENABLED=0 go build -o bin/cassandra-database-plugin ./plugins/database/cassandra/cassandra-database-plugin

postgresql-database-plugin:
	@CGO_ENABLED=0 go build -o bin/postgresql-database-plugin ./plugins/database/postgresql/postgresql-database-plugin

mssql-database-plugin:
	@CGO_ENABLED=0 go build -o bin/mssql-database-plugin ./plugins/database/mssql/mssql-database-plugin

hana-database-plugin:
	@CGO_ENABLED=0 go build -o bin/hana-database-plugin ./plugins/database/hana/hana-database-plugin

mongodb-database-plugin:
	@CGO_ENABLED=0 go build -o bin/mongodb-database-plugin ./plugins/database/mongodb/mongodb-database-plugin

.PHONY: bin default prep test vet bootstrap fmt fmtcheck mysql-database-plugin mysql-legacy-database-plugin cassandra-database-plugin postgresql-database-plugin mssql-database-plugin hana-database-plugin mongodb-database-plugin static-assets ember-dist static-dist
