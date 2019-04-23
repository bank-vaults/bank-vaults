# Getting and Installing

```bash
go get github.com/banzaicloud/bank-vaults/cmd/bank-vaults
go get github.com/banzaicloud/bank-vaults/cmd/vault-env
```

If compilation is failed, you should try to enable go modules:
```shell
GOPATH=/tmp/gopath-for-bank-vaults GO111MODULE=on go get github.com/banzaicloud/bank-vaults/cmd/bank-vaults
GOPATH=/tmp/gopath-for-bank-vaults GO111MODULE=on go get github.com/banzaicloud/bank-vaults/cmd/vault-env
```

or

```bash
docker pull banzaicloud/bank-vaults
docker pull banzaicloud/vault-operator
docker pull banzaicloud/vault-env
```
