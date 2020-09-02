module github.com/banzaicloud/bank-vaults/pkg/sdk

go 1.13

require (
	emperror.dev/errors v0.7.0
	github.com/fsnotify/fsnotify v1.4.9
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/json-iterator/go v1.1.10
	github.com/mitchellh/mapstructure v1.1.2
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cast v1.3.0
	github.com/spf13/viper v1.7.0
	k8s.io/api v0.18.6
	k8s.io/client-go v0.18.6
	sigs.k8s.io/controller-runtime v0.6.2
)
