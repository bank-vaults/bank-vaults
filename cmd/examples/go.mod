module github.com/banzaicloud/bank-vaults/cmd/examples

go 1.13

replace github.com/banzaicloud/bank-vaults => ./../..

replace github.com/banzaicloud/bank-vaults/pkg/sdk => ./../../pkg/sdk

require (
	github.com/banzaicloud/bank-vaults/pkg/sdk v0.2.1
	github.com/hashicorp/vault/api v1.0.4
	github.com/sirupsen/logrus v1.6.0
	logur.dev/adapter/logrus v0.5.0
)
