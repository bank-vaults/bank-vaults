module github.com/banzaicloud/bank-vaults

go 1.12

require (
	cloud.google.com/go v0.43.0
	github.com/Azure/azure-sdk-for-go v23.2.0+incompatible
	github.com/Azure/go-autorest v11.7.0+incompatible
	github.com/Masterminds/semver v1.4.2
	github.com/Masterminds/sprig v2.15.0+incompatible
	github.com/aliyun/alibaba-cloud-sdk-go v0.0.0-20190308093441-53f19b3c6bee
	github.com/aliyun/aliyun-oss-go-sdk v0.0.0-20171213061034-52de7239022c
	github.com/aokoli/goutils v1.0.1 // indirect
	github.com/aws/aws-sdk-go v1.15.31
	github.com/baiyubin/aliyun-sts-go-sdk v0.0.0-20180326062324-cfa1a18b161f // indirect
	github.com/banzaicloud/bank-vaults/pkg/sdk v0.0.0-00010101000000-000000000000
	github.com/banzaicloud/k8s-objectmatcher v1.0.1-0.20190813150246-386389f72468
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/coreos/etcd-operator v0.9.3
	github.com/coreos/prometheus-operator v0.29.0
	github.com/dimchansky/utfbom v1.1.0 // indirect
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/frankban/quicktest v1.4.0 // indirect
	github.com/fsnotify/fsnotify v1.4.7
	github.com/gin-gonic/gin v1.4.0
	github.com/go-ini/ini v1.34.0 // indirect
	github.com/google/martian v2.1.0+incompatible // indirect
	github.com/googleapis/gax-go v2.0.0+incompatible // indirect
	github.com/goph/emperror v0.17.2
	github.com/gorilla/mux v1.7.2 // indirect
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/hashicorp/vault/api v1.0.4
	github.com/heroku/docker-registry-client v0.0.0-20181004091502-47ecf50fd8d4
	github.com/imdario/mergo v0.3.7
	github.com/jmespath/go-jmespath v0.0.0-20180206201540-c2b33e8439af // indirect
	github.com/jpillora/backoff v0.0.0-20180909062703-3050d21c67d7
	github.com/mattn/go-isatty v0.0.8 // indirect
	github.com/opencontainers/image-spec v1.0.1
	github.com/operator-framework/operator-sdk v0.9.0
	github.com/pierrec/lz4 v2.2.5+incompatible // indirect
	github.com/prometheus/client_golang v1.0.0
	github.com/prometheus/common v0.6.0 // indirect
	github.com/prometheus/procfs v0.0.3 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/slok/kubewebhook v0.3.0
	github.com/smartystreets/goconvey v0.0.0-20190306220146-200a235640ff // indirect
	github.com/spf13/cast v1.3.0
	github.com/spf13/cobra v0.0.4
	github.com/spf13/viper v1.4.0
	github.com/ugorji/go v1.1.7 // indirect
	golang.org/x/crypto v0.0.0-20190927123631-a832865fa7ad // indirect
	golang.org/x/net v0.0.0-20190926025831-c00fd9afed17 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e // indirect
	golang.org/x/sys v0.0.0-20190927073244-c990c680b611 // indirect
	golang.org/x/tools v0.0.0-20190929041059-e7abfedfabcf // indirect
	google.golang.org/api v0.3.0
	google.golang.org/genproto v0.0.0-20190716160619-c506a9f90610 // indirect
	google.golang.org/grpc v1.22.1 // indirect
	gopkg.in/ini.v1 v1.42.0 // indirect
	k8s.io/api v0.0.0-20190820101039-d651a1528133
	k8s.io/apimachinery v0.0.0-20190823012420-8ca64af22337
	k8s.io/client-go v11.0.1-0.20190516230509-ae8359b20417+incompatible
	k8s.io/code-generator v0.0.0-20190808180452-d0071a119380
	k8s.io/kube-openapi v0.0.0-20190722073852-5e22f3d471e6
	sigs.k8s.io/controller-runtime v0.1.10
)

replace github.com/banzaicloud/bank-vaults/pkg/sdk => ./pkg/sdk

replace cloud.google.com/go => cloud.google.com/go v0.26.0

replace k8s.io/api => k8s.io/api v0.0.0-20181213150558-05914d821849

replace k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20181127025237-2b1284ed4c93

replace k8s.io/client-go => k8s.io/client-go v10.0.0+incompatible

replace k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190416052311-01a054e913a9

replace golang.org/x/oauth2 => golang.org/x/oauth2 v0.0.0-20180821212333-d2e6202438be
