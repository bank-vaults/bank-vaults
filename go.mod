module github.com/banzaicloud/bank-vaults

require (
	cloud.google.com/go v0.46.3
	cloud.google.com/go/storage v1.0.0
	emperror.dev/errors v0.7.0
	github.com/Azure/azure-sdk-for-go v30.1.0+incompatible
	github.com/Azure/go-autorest/autorest v0.9.2
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.1
	github.com/Azure/go-autorest/autorest/to v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/Masterminds/semver/v3 v3.1.0
	github.com/Masterminds/sprig/v3 v3.1.0
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.193
	github.com/aliyun/aliyun-oss-go-sdk v0.0.0-20171213061034-52de7239022c
	github.com/aws/aws-sdk-go v1.30.7
	github.com/baiyubin/aliyun-sts-go-sdk v0.0.0-20180326062324-cfa1a18b161f // indirect
	github.com/banzaicloud/bank-vaults/pkg/sdk v0.2.1
	github.com/banzaicloud/k8s-objectmatcher v1.3.2
	github.com/coreos/etcd-operator v0.9.4
	github.com/coreos/prometheus-operator v0.29.0
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/frankban/quicktest v1.4.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9
	github.com/google/go-cmp v0.4.0
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/heroku/docker-registry-client v0.0.0-20181004091502-47ecf50fd8d4
	github.com/imdario/mergo v0.3.9
	github.com/jpillora/backoff v0.0.0-20180909062703-3050d21c67d7
	github.com/json-iterator/go v1.1.10
	github.com/miekg/pkcs11 v1.0.3
	github.com/mitchellh/mapstructure v1.1.2
	github.com/opencontainers/image-spec v1.0.1
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pierrec/lz4 v2.2.5+incompatible // indirect
	github.com/prometheus/client_golang v1.5.1
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/slok/kubewebhook v0.9.1
	github.com/spf13/cast v1.3.1
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	gocloud.dev v0.19.1-0.20200414210820-bb59d59f26d5
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	google.golang.org/api v0.13.0
	google.golang.org/genproto v0.0.0-20191108220845-16a3f7862a1a
	k8s.io/api v0.18.6
	k8s.io/apimachinery v0.18.6
	k8s.io/client-go v0.18.6
	k8s.io/code-generator v0.18.6
	k8s.io/kube-openapi v0.0.0-20200410145947-61e04a5be9a6
	k8s.io/utils v0.0.0-20200603063816-c1c6865ac451
	logur.dev/adapter/logrus v0.5.0
	sigs.k8s.io/controller-runtime v0.6.2
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.1+incompatible
	github.com/banzaicloud/bank-vaults/pkg/sdk => ./pkg/sdk
	github.com/heroku/docker-registry-client => github.com/banzaicloud/docker-registry-client v0.0.0-20191118103116-f48ee8de5b3b
)

go 1.13
