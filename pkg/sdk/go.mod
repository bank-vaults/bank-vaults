module github.com/banzaicloud/bank-vaults/pkg/sdk

go 1.12

require (
	github.com/fsnotify/fsnotify v1.4.7
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/json-iterator/go v1.1.7
	github.com/mitchellh/mapstructure v1.1.2
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.0
	github.com/spf13/viper v1.4.0
	golang.org/x/crypto v0.0.0-20190325154230-a5d413f7728c // indirect
	golang.org/x/oauth2 v0.0.0-20190226205417-e64efc72b421 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-20190820101039-d651a1528133 // indirect
	k8s.io/apimachinery v0.0.0-20190823012420-8ca64af22337 // indirect
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog v0.4.0 // indirect
	sigs.k8s.io/yaml v1.1.0 // indirect
)

replace k8s.io/api => k8s.io/api v0.0.0-20181213150558-05914d821849

replace k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20181127025237-2b1284ed4c93

replace k8s.io/client-go => k8s.io/client-go v2.0.0-alpha.0.0.20181213151034-8d9ed539ba31+incompatible
