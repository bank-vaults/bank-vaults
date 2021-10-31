module github.com/banzaicloud/bank-vaults

require (
	cloud.google.com/go v0.78.0
	cloud.google.com/go/storage v1.10.0
	emperror.dev/errors v0.8.0
	github.com/Azure/azure-sdk-for-go v46.4.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.12
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.3
	github.com/Masterminds/semver/v3 v3.1.0
	github.com/Masterminds/sprig/v3 v3.1.0
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.193
	github.com/aliyun/aliyun-oss-go-sdk v2.0.4+incompatible
	github.com/aws/aws-sdk-go v1.35.24
	github.com/baiyubin/aliyun-sts-go-sdk v0.0.0-20180326062324-cfa1a18b161f // indirect
	github.com/banzaicloud/bank-vaults/pkg/sdk v0.0.0
	github.com/banzaicloud/k8s-objectmatcher v1.5.0
	github.com/coreos/etcd-operator v0.9.4
	github.com/cristalhq/jwt/v3 v3.0.14
	github.com/fsnotify/fsnotify v1.4.9
	github.com/google/go-cmp v0.5.5
	github.com/google/go-containerregistry v0.5.1
	github.com/google/go-containerregistry/pkg/authn/k8schain v0.0.0-20210521160948-0233fcda5d53
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.3.0
	github.com/hashicorp/vault/sdk v0.3.0
	github.com/imdario/mergo v0.3.12
	github.com/jpillora/backoff v1.0.0
	github.com/json-iterator/go v1.1.11
	github.com/miekg/pkcs11 v1.0.3
	github.com/mitchellh/mapstructure v1.4.2
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.43.0
	github.com/prometheus/client_golang v1.11.0
	github.com/sirupsen/logrus v1.8.1
	github.com/slok/kubewebhook/v2 v2.1.0
	github.com/spf13/cast v1.3.1
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	gocloud.dev v0.19.1-0.20200414210820-bb59d59f26d5
	golang.org/x/oauth2 v0.0.0-20210427180440-81ed05c6b58c
	google.golang.org/api v0.40.0
	google.golang.org/genproto v0.0.0-20210224155714-063164c882e6
	k8s.io/api v0.21.1
	k8s.io/apiextensions-apiserver v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.21.1
	k8s.io/code-generator v0.21.1
	k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7
	k8s.io/utils v0.0.0-20210527160623-6fdb442a123b
	logur.dev/adapter/logrus v0.5.0
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/banzaicloud/bank-vaults/pkg/sdk => ./pkg/sdk
	google.golang.org/grpc => google.golang.org/grpc v1.29.1
)

go 1.15
