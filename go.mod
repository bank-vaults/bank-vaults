module github.com/banzaicloud/bank-vaults

require (
	cloud.google.com/go v0.65.0
	cloud.google.com/go/storage v1.10.0
	emperror.dev/errors v0.8.0
	github.com/Azure/azure-pipeline-go v0.2.2 // indirect
	github.com/Azure/azure-sdk-for-go v46.4.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.11
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.3
	github.com/Azure/go-autorest/autorest/to v0.3.1-0.20191028180845-3492b2aff503 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.1-0.20191028180845-3492b2aff503 // indirect
	github.com/Masterminds/semver/v3 v3.1.0
	github.com/Masterminds/sprig/v3 v3.1.0
	github.com/Microsoft/hcsshim v0.8.10 // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.193
	github.com/aliyun/aliyun-oss-go-sdk v2.0.4+incompatible
	github.com/aws/aws-sdk-go v1.35.5
	github.com/baiyubin/aliyun-sts-go-sdk v0.0.0-20180326062324-cfa1a18b161f // indirect
	github.com/banzaicloud/bank-vaults/pkg/sdk v0.2.1
	github.com/banzaicloud/k8s-objectmatcher v1.5.0
	github.com/containerd/containerd v1.3.4 // indirect
	github.com/containerd/continuity v0.0.0-20201119173150-04c754faca46 // indirect
	github.com/coreos/etcd-operator v0.9.4
	github.com/docker/docker v17.12.0-ce-rc1.0.20200706150819-a40b877fbb9e+incompatible
	github.com/frankban/quicktest v1.4.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9
	github.com/go-logr/logr v0.2.1 // indirect
	github.com/go-logr/zapr v0.2.0 // indirect
	github.com/go-openapi/spec v0.19.8 // indirect
	github.com/go-openapi/swag v0.19.10 // indirect
	github.com/golang/snappy v0.0.2 // indirect
	github.com/google/go-cmp v0.5.2
	github.com/google/go-containerregistry v0.4.0
	github.com/google/go-containerregistry/pkg/authn/k8schain v0.0.0-20210113221012-4eb508cda163
	github.com/gopherjs/gopherjs v0.0.0-20191106031601-ce3c9ade29de // indirect
	github.com/hashicorp/go-multierror v1.1.0 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/imdario/mergo v0.3.9
	github.com/jpillora/backoff v1.0.0
	github.com/json-iterator/go v1.1.10
	github.com/kr/pretty v0.2.1 // indirect
	github.com/mailru/easyjson v0.7.1 // indirect
	github.com/mattn/go-ieproxy v0.0.0-20191113090002-7c0f6868bffe // indirect
	github.com/miekg/pkcs11 v1.0.3
	github.com/mitchellh/mapstructure v1.2.2
	github.com/onsi/ginkgo v1.14.0 // indirect
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pelletier/go-toml v1.4.0 // indirect
	github.com/pierrec/lz4 v2.2.5+incompatible // indirect
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.43.0
	github.com/prometheus/client_golang v1.8.0
	github.com/satori/go.uuid v1.2.1-0.20181028125025-b2ce2384e17b // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/slok/kubewebhook v0.11.0
	github.com/smartystreets/assertions v1.0.1 // indirect
	github.com/spf13/cast v1.3.1
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	go.uber.org/zap v1.14.1 // indirect
	gocloud.dev v0.19.1-0.20200414210820-bb59d59f26d5
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	golang.org/x/tools v0.0.0-20201008025239-9df69603baec // indirect
	google.golang.org/api v0.32.0
	google.golang.org/genproto v0.0.0-20200904004341-0bd0a958aa1d
	google.golang.org/grpc v1.32.0 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
	k8s.io/api v0.19.3
	k8s.io/apiextensions-apiserver v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v0.19.3
	k8s.io/code-generator v0.20.1
	k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73
	logur.dev/adapter/logrus v0.5.0
	sigs.k8s.io/controller-runtime v0.6.2
)

replace (
	github.com/banzaicloud/bank-vaults/pkg/sdk => ./pkg/sdk
	google.golang.org/grpc => google.golang.org/grpc v1.29.1
)

go 1.15
