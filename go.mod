module github.com/banzaicloud/bank-vaults

require (
	cloud.google.com/go v0.43.0
	emperror.dev/errors v0.4.3
	github.com/Azure/azure-sdk-for-go v23.2.0+incompatible
	github.com/Azure/go-autorest/autorest v0.9.2
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.1
	github.com/Azure/go-autorest/autorest/to v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/Masterminds/semver v1.4.2
	github.com/Masterminds/sprig v2.15.0+incompatible
	github.com/aliyun/alibaba-cloud-sdk-go v0.0.0-20190308093441-53f19b3c6bee
	github.com/aliyun/aliyun-oss-go-sdk v0.0.0-20171213061034-52de7239022c
	github.com/aokoli/goutils v1.0.1 // indirect
	github.com/aws/aws-sdk-go v1.27.2
	github.com/baiyubin/aliyun-sts-go-sdk v0.0.0-20180326062324-cfa1a18b161f // indirect
	github.com/banzaicloud/bank-vaults/pkg/sdk v0.0.0-00010101000000-000000000000
	github.com/banzaicloud/k8s-objectmatcher v1.0.1-0.20190813150246-386389f72468
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/coreos/etcd-operator v0.9.4
	github.com/coreos/prometheus-operator v0.29.0
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/frankban/quicktest v1.4.0 // indirect
	github.com/fsnotify/fsnotify v1.4.7
	github.com/gin-gonic/gin v1.4.0
	github.com/go-ini/ini v1.34.0 // indirect
	github.com/google/go-cmp v0.3.0
	github.com/goph/emperror v0.17.2
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/hashicorp/vault/api v1.0.4
	github.com/heroku/docker-registry-client v0.0.0-20181004091502-47ecf50fd8d4
	github.com/huandu/xstrings v1.2.1 // indirect
	github.com/imdario/mergo v0.3.7
	github.com/jpillora/backoff v0.0.0-20180909062703-3050d21c67d7
	github.com/mattn/go-isatty v0.0.8 // indirect
	github.com/opencontainers/image-spec v1.0.1
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pierrec/lz4 v2.2.5+incompatible // indirect
	github.com/prometheus/client_golang v1.0.0
	github.com/prometheus/common v0.6.0 // indirect
	github.com/prometheus/procfs v0.0.3 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/slok/kubewebhook v0.3.0
	github.com/smartystreets/goconvey v0.0.0-20190306220146-200a235640ff // indirect
	github.com/spf13/cast v1.3.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
	github.com/stretchr/testify v1.4.0
	github.com/ugorji/go v1.1.7 // indirect
	golang.org/x/crypto v0.0.0-20190927123631-a832865fa7ad // indirect
	golang.org/x/net v0.0.0-20190926025831-c00fd9afed17 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sys v0.0.0-20190927073244-c990c680b611 // indirect
	golang.org/x/tools v0.0.0-20190929041059-e7abfedfabcf // indirect
	google.golang.org/api v0.7.0
	gopkg.in/ini.v1 v1.42.0 // indirect
	k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/client-go v11.0.1-0.20190516230509-ae8359b20417+incompatible
	k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
	k8s.io/kube-openapi v0.0.0-20190816220812-743ec37842bf
	sigs.k8s.io/controller-runtime v0.4.0
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v13.3.1+incompatible
	github.com/banzaicloud/bank-vaults/pkg/sdk => ./pkg/sdk
	github.com/heroku/docker-registry-client => github.com/banzaicloud/docker-registry-client v0.0.0-20191118103116-f48ee8de5b3b
	golang.org/x/oauth2 => golang.org/x/oauth2 v0.0.0-20180821212333-d2e6202438be
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190918160344-1fbdaa4c8d90
)

go 1.13
