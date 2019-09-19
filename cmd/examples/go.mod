module github.com/banzaicloud/bank-vaults/cmd/examples

go 1.13

replace github.com/banzaicloud/bank-vaults => ./../..

replace k8s.io/api => k8s.io/api v0.0.0-20181213150558-05914d821849

replace k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20181127025237-2b1284ed4c93

replace k8s.io/client-go => k8s.io/client-go v10.0.0+incompatible

require github.com/banzaicloud/bank-vaults/pkg/sdk v0.1.3
