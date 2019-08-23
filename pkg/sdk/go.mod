module github.com/banzaicloud/bank-vaults/pkg/sdk

go 1.12

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/fsnotify/fsnotify v1.4.7
	github.com/gin-gonic/gin v1.4.0
	github.com/gosimple/slug v1.7.0 // indirect
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/jinzhu/gorm v1.9.10 // indirect
	github.com/json-iterator/go v1.1.7
	github.com/microcosm-cc/bluemonday v1.0.2 // indirect
	github.com/mitchellh/mapstructure v1.1.2
	github.com/pkg/errors v0.8.1
	github.com/qor/qor v0.0.0-20190319081902-186b0237364b
	github.com/rainycape/unidecode v0.0.0-20150907023854-cb7f23ec59be // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.0
	github.com/spf13/viper v1.4.0
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
