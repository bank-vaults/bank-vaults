// Copyright © 2019 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/spf13/cast"
	v1 "k8s.io/api/core/v1"
	v1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Vault is the Schema for the vaults API

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=true
type Vault struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultSpec   `json:"spec,omitempty"`
	Status VaultStatus `json:"status,omitempty"`
}

// VaultList contains a list of Vault

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type VaultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Vault `json:"items"`
}

func init() {
	gob.Register(VaultConfig{})
	gob.Register(VaultExternalConfig{})
}

type VaultConfig map[string]interface{}

func (c VaultConfig) DeepCopy() VaultConfig {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)
	err := enc.Encode(c)
	if err != nil {
		panic(err)
	}
	var copy VaultConfig
	err = dec.Decode(&copy)
	if err != nil {
		panic(err)
	}
	return copy
}

type VaultExternalConfig map[string]interface{}

func (c VaultExternalConfig) DeepCopy() VaultExternalConfig {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)
	err := enc.Encode(c)
	if err != nil {
		panic(err)
	}
	var copy VaultExternalConfig
	err = dec.Decode(&copy)
	if err != nil {
		panic(err)
	}
	return copy
}

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultSpec defines the desired state of Vault
type VaultSpec struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	Size                       int32                 `json:"size"`
	Image                      string                `json:"image"`
	BankVaultsImage            string                `json:"bankVaultsImage"`
	StatsdDisabled             bool                  `json:"statsdDisabled"`
	StatsDImage                string                `json:"statsdImage"`
	FluentDEnabled             bool                  `json:"fluentdEnabled"`
	FluentDImage               string                `json:"fluentdImage"`
	FluentDConfig              string                `json:"fluentdConfig"`
	WatchedSecretsLabels       []map[string]string   `json:"watchedSecretsLabels"`
	Annotations                map[string]string     `json:"annotations"`
	VaultAnnotations           map[string]string     `json:"vaultAnnotations"`
	VaultConfigurerAnnotations map[string]string     `json:"vaultConfigurerAnnotations"`
	Config                     VaultConfig           `json:"config"`
	ExternalConfig             VaultExternalConfig   `json:"externalConfig"`
	UnsealConfig               UnsealConfig          `json:"unsealConfig"`
	CredentialsConfig          CredentialsConfig     `json:"credentialsConfig"`
	EnvsConfig                 []v1.EnvVar           `json:"envsConfig"`
	SecurityContext            v1.PodSecurityContext `json:"securityContext,omitempty"`
	// This option gives us the option to workaround current StatefulSet limitations around updates
	// See: https://github.com/kubernetes/kubernetes/issues/67250
	// TODO: Should be removed once the ParallelPodManagement policy supports the broken update.
	EtcdVersion           string                        `json:"etcdVersion"`
	EtcdSize              int                           `json:"etcdSize"`
	EtcdAnnotations       map[string]string             `json:"etcdAnnotations,omitempty"`
	EtcdPodAnnotations    map[string]string             `json:"etcdPodAnnotations,omitempty"`
	EtcdPVCSpec           *v1.PersistentVolumeClaimSpec `json:"etcdPVCSpec,omitempty"`
	ServiceType           string                        `json:"serviceType"`
	ServicePorts          map[string]int32              `json:"servicePorts"`
	PodAntiAffinity       string                        `json:"podAntiAffinity"`
	NodeAffinity          v1.NodeAffinity               `json:"nodeAffinity"`
	NodeSelector          map[string]string             `json:"nodeSelector"`
	Tolerations           []v1.Toleration               `json:"tolerations"`
	ServiceAccount        string                        `json:"serviceAccount"`
	Volumes               []v1.Volume                   `json:"volumes,omitempty"`
	VolumeMounts          []v1.VolumeMount              `json:"volumeMounts,omitempty"`
	VaultEnvsConfig       []v1.EnvVar                   `json:"vaultEnvsConfig"`
	Resources             *Resources                    `json:"resources,omitempty"`
	Ingress               *Ingress                      `json:"ingress,omitempty"`
	ServiceMonitorEnabled bool                          `json:"serviceMonitorEnabled,omitempty"`
}

// HAStorageTypes is the set of storage backends supporting High Availability
var HAStorageTypes = map[string]bool{
	"consul":    true,
	"dynamodb":  true,
	"etcd":      true,
	"gcs":       true,
	"mysql":     true,
	"spanner":   true,
	"zookeeper": true,
}

// HasHAStorage detects if Vault is configured to use a storage backend which supports High Availability or if it has
// ha_storage stanza, then doesn't check for ha_enabled flag
func (spec *VaultSpec) HasHAStorage() bool {
	storageType := spec.GetStorageType()
	if _, ok := HAStorageTypes[storageType]; ok {
		return spec.HasStorageHAEnabled()
	}
	if len(spec.getHAStorage()) != 0 {
		return true
	}
	return false
}

// GetStorage returns Vault's storage stanza
func (spec *VaultSpec) GetStorage() map[string]interface{} {
	storage := spec.getStorage()
	return cast.ToStringMap(storage[spec.GetStorageType()])
}

func (spec *VaultSpec) getStorage() map[string]interface{} {
	return cast.ToStringMap(spec.Config["storage"])
}

func (spec *VaultSpec) getHAStorage() map[string]interface{} {
	return cast.ToStringMap(spec.Config["ha_storage"])
}

// GetStorageType returns the type of Vault's storage stanza
func (spec *VaultSpec) GetStorageType() string {
	storage := spec.getStorage()
	return reflect.ValueOf(storage).MapKeys()[0].String()
}

// GetVersion returns the version of Vault
func (spec *VaultSpec) GetVersion() (*semver.Version, error) {
	version := strings.Split(spec.Image, ":")
	if len(version) != 2 {
		return nil, errors.New("failed to find Vault version")
	}
	return semver.NewVersion(version[1])
}

// GetEtcdVersion returns the etcd version to use
func (spec *VaultSpec) GetEtcdVersion() string {
	if spec.EtcdVersion == "" {
		// See https://github.com/coreos/etcd-operator/issues/1962#issuecomment-390539621
		// for more details why we have to pin to 3.1.15
		return "3.1.15"
	}
	return spec.EtcdVersion
}

// GetServiceAccount returns the Kubernetes Service Account to use for Vault
func (spec *VaultSpec) GetServiceAccount() string {
	if spec.ServiceAccount != "" {
		return spec.ServiceAccount
	}
	return "default"
}

// GetEtcdSize returns the number of etcd pods to use
func (spec *VaultSpec) GetEtcdSize() int {
	// Default value of EctdSize is 0. So if < 0 will assume use existing etcd
	if spec.EtcdSize < 0 {
		return -1
	}

	if spec.EtcdSize < 1 {
		return 3
	}
	// check if size given is even. If even, subtract 1. Reasoning: Because of raft consensus protocol,
	// an odd-size cluster tolerates the same number of failures as an even-size cluster but with fewer nodes
	// See https://github.com/etcd-io/etcd/blob/master/Documentation/faq.md#what-is-failure-tolerance
	if spec.EtcdSize%2 == 0 {
		return spec.EtcdSize - 1
	}
	return spec.EtcdSize
}

// HasStorageHAEnabled detects if the ha_enabled field is set to true in Vault's storage stanza
func (spec *VaultSpec) HasStorageHAEnabled() bool {
	storageType := spec.GetStorageType()
	storage := spec.getStorage()
	storageSpecs := cast.ToStringMap(storage[storageType])
	// In Consul HA is always enabled
	return storageType == "consul" || cast.ToBool(storageSpecs["ha_enabled"])
}

// GetTLSDisable returns if Vault's TLS is disabled
func (spec *VaultSpec) GetTLSDisable() bool {
	listener := spec.getListener()
	tcpSpecs := cast.ToStringMap(listener["tcp"])
	return cast.ToBool(tcpSpecs["tls_disable"])
}

func (spec *VaultSpec) getListener() map[string]interface{} {
	return cast.ToStringMap(spec.Config["listener"])
}

// GetBankVaultsImage returns the bank-vaults image to use
func (spec *VaultSpec) GetBankVaultsImage() string {
	if spec.BankVaultsImage == "" {
		return "banzaicloud/bank-vaults:latest"
	}
	return spec.BankVaultsImage
}

// GetStatsDImage returns the StatsD image to use
func (spec *VaultSpec) GetStatsDImage() string {
	if spec.StatsDImage == "" {
		return "prom/statsd-exporter:latest"
	}
	return spec.StatsDImage
}

// GetWatchedSecretsLabels returns the set of labels for secrets to watch in the vault namespace
func (spec *VaultSpec) GetWatchedSecretsLabels() []map[string]string {
	if spec.WatchedSecretsLabels == nil {
		spec.WatchedSecretsLabels = []map[string]string{}
	}

	return spec.WatchedSecretsLabels
}

// GetAnnotations returns the Common Annotations
func (spec *VaultSpec) GetAnnotations() map[string]string {
	if spec.Annotations == nil {
		spec.Annotations = map[string]string{}
	}

	return spec.Annotations
}

// GetVaultAnnotations returns the Vault Pod , Secret and ConfigMap Annotations
func (spec *VaultSpec) GetVaultAnnotations() map[string]string {
	if spec.VaultAnnotations == nil {
		spec.VaultAnnotations = map[string]string{}
	}

	return spec.VaultAnnotations
}

// GetVaultConfigurerAnnotations returns the Vault Configurer Pod Annotations
func (spec *VaultSpec) GetVaultConfigurerAnnotations() map[string]string {
	if spec.VaultConfigurerAnnotations == nil {
		spec.VaultConfigurerAnnotations = map[string]string{}
	}

	return spec.VaultConfigurerAnnotations
}

// GetFluentDImage returns the FluentD image to use
func (spec *VaultSpec) GetFluentDImage() string {
	if spec.FluentDImage == "" {
		return "fluent/fluentd:stable"
	}
	return spec.FluentDImage
}

// IsFluentDEnabled returns true if fluentd sidecar is to be deployed
func (spec *VaultSpec) IsFluentDEnabled() bool {
	return spec.FluentDEnabled
}

// IsStatsdDisabled returns false if statsd sidecar is to be deployed
func (spec *VaultSpec) IsStatsdDisabled() bool {
	return spec.StatsdDisabled
}

// ConfigJSON returns the Config field as a JSON string
func (spec *VaultSpec) ConfigJSON() string {
	config, _ := json.Marshal(spec.Config)
	return string(config)
}

// ExternalConfigJSON returns the ExternalConfig field as a JSON string
func (spec *VaultSpec) ExternalConfigJSON() string {
	config, _ := json.Marshal(spec.ExternalConfig)
	return string(config)
}

// IsAutoUnseal checks if auto-unseal is configured
func (spec *VaultSpec) IsAutoUnseal() bool {
	_, ok := spec.Config["seal"]
	return ok
}

// GetIngress the Ingress configuration for Vault if any
func (vault *Vault) GetIngress() *Ingress {
	if vault.Spec.Ingress != nil {
		// Add the Vault Service as the default backend if not specified
		if vault.Spec.Ingress.Spec.Backend == nil {
			vault.Spec.Ingress.Spec.Backend = &v1beta1.IngressBackend{
				ServiceName: vault.Name,
				ServicePort: intstr.FromInt(8200),
			}
		}

		if vault.Spec.Ingress.Annotations == nil {
			vault.Spec.Ingress.Annotations = map[string]string{}
		}

		// If TLS is enabled add the Ingress TLS backend annotations
		if !vault.Spec.GetTLSDisable() {
			// Supporting the NGINX ingress controller with TLS backends
			// https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#backend-protocol
			vault.Spec.Ingress.Annotations["nginx.ingress.kubernetes.io/backend-protocol"] = "HTTPS"

			// Supporting the Traefik ingress controller with TLS backends
			// https://docs.traefik.io/configuration/backends/kubernetes/#tls-communication-between-traefik-and-backend-pods
			vault.Spec.Ingress.Annotations["ingress.kubernetes.io/protocol"] = "https"

			// Supporting the HAProxy ingress controller with TLS backends
			// https://github.com/jcmoraisjr/haproxy-ingress#secure-backend
			vault.Spec.Ingress.Annotations["ingress.kubernetes.io/secure-backends"] = "true"
		}

		return vault.Spec.Ingress
	}

	return nil
}

// VaultStatus defines the observed state of Vault
type VaultStatus struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	Nodes  []string `json:"nodes"`
	Leader string   `json:"leader"`
}

// UnsealConfig represents the UnsealConfig field of a VaultSpec Kubernetes object
type UnsealConfig struct {
	Options    UnsealOptions           `json:"options,omitempty"`
	Kubernetes *KubernetesUnsealConfig `json:"kubernetes,omitempty"`
	Google     *GoogleUnsealConfig     `json:"google,omitempty"`
	Alibaba    *AlibabaUnsealConfig    `json:"alibaba,omitempty"`
	Azure      *AzureUnsealConfig      `json:"azure,omitempty"`
	AWS        *AWSUnsealConfig        `json:"aws,omitempty"`
}

// UnsealOptions represents the common options to all unsealing backends
type UnsealOptions struct {
	PreFlightChecks bool `json:"preFlightChecks,omitempty"`
}

func (uso UnsealOptions) ToArgs() []string {
	args := []string{}
	if uso.PreFlightChecks {
		args = append(args, "--pre-flight-checks", "true")
	}
	return args
}

// ToArgs returns the UnsealConfig as and argument array for bank-vaults
func (usc *UnsealConfig) ToArgs(vault *Vault) []string {
	args := []string{}
	if usc.Kubernetes != nil {

		secretNamespace := vault.Namespace
		if usc.Kubernetes.SecretNamespace != "" {
			secretNamespace = usc.Kubernetes.SecretNamespace
		}
		secretName := vault.Name + "-unseal-keys"
		if usc.Kubernetes.SecretName != "" {
			secretName = usc.Kubernetes.SecretName
		}
		args = append(args,
			"--mode",
			"k8s",
			"--k8s-secret-namespace",
			secretNamespace,
			"--k8s-secret-name",
			secretName,
		)

	} else if usc.Google != nil {

		args = append(args,
			"--mode",
			"google-cloud-kms-gcs",
			"--google-cloud-kms-key-ring",
			usc.Google.KMSKeyRing,
			"--google-cloud-kms-crypto-key",
			usc.Google.KMSCryptoKey,
			"--google-cloud-kms-location",
			usc.Google.KMSLocation,
			"--google-cloud-kms-project",
			usc.Google.KMSProject,
			"--google-cloud-storage-bucket",
			usc.Google.StorageBucket,
		)

	} else if usc.Azure != nil {

		args = append(args,
			"--mode",
			"azure-key-vault",
			"--azure-key-vault-name",
			usc.Azure.KeyVaultName,
		)

	} else if usc.AWS != nil {

		args = append(args,
			"--mode",
			"aws-kms-s3",
			"--aws-kms-key-id",
			usc.AWS.KMSKeyID,
			"--aws-kms-region",
			usc.AWS.KMSRegion,
			"--aws-s3-bucket",
			usc.AWS.S3Bucket,
			"--aws-s3-prefix",
			usc.AWS.S3Prefix,
			"--aws-s3-region",
			usc.AWS.S3Region,
		)

	} else if usc.Alibaba != nil {

		args = append(args,
			"--mode",
			"alibaba-kms-oss",
			"--alibaba-kms-region",
			usc.Alibaba.KMSRegion,
			"--alibaba-kms-key-id",
			usc.Alibaba.KMSKeyID,
			"--alibaba-oss-endpoint",
			usc.Alibaba.OSSEndpoint,
			"--alibaba-oss-bucket",
			usc.Alibaba.OSSBucket,
			"--alibaba-oss-prefix",
			usc.Alibaba.OSSPrefix,
		)

	}
	return args
}

// KubernetesUnsealConfig holds the parameters for Kubernetes based unsealing
type KubernetesUnsealConfig struct {
	SecretNamespace string `json:"secretNamespace"`
	SecretName      string `json:"secretName"`
}

// GoogleUnsealConfig holds the parameters for Google KMS based unsealing
type GoogleUnsealConfig struct {
	KMSKeyRing    string `json:"kmsKeyRing"`
	KMSCryptoKey  string `json:"kmsCryptoKey"`
	KMSLocation   string `json:"kmsLocation"`
	KMSProject    string `json:"kmsProject"`
	StorageBucket string `json:"storageBucket"`
}

// AlibabaUnsealConfig holds the parameters for Alibaba Cloud KMS based unsealing
//  --alibaba-kms-region eu-central-1 --alibaba-kms-key-id 9d8063eb-f9dc-421b-be80-15d195c9f148 --alibaba-oss-endpoint oss-eu-central-1.aliyuncs.com --alibaba-oss-bucket bank-vaults
type AlibabaUnsealConfig struct {
	KMSRegion   string `json:"kmsRegion"`
	KMSKeyID    string `json:"kmsKeyId"`
	OSSEndpoint string `json:"ossEndpoint"`
	OSSBucket   string `json:"ossBucket"`
	OSSPrefix   string `json:"ossPrefix"`
}

// AzureUnsealConfig holds the parameters for Azure Key Vault based unsealing
type AzureUnsealConfig struct {
	KeyVaultName string `json:"keyVaultName"`
}

// AWSUnsealConfig holds the parameters for AWS KMS based unsealing
type AWSUnsealConfig struct {
	KMSKeyID  string `json:"kmsKeyId"`
	KMSRegion string `json:"kmsRegion"`
	S3Bucket  string `json:"s3Bucket"`
	S3Prefix  string `json:"s3Prefix"`
	S3Region  string `json:"s3Region"`
}

// CredentialsConfig configuration for a credentials file provided as a secret
type CredentialsConfig struct {
	Env        string `json:"env"`
	Path       string `json:"path"`
	SecretName string `json:"secretName"`
}

// Resources holds different container's ResourceRequirements
type Resources struct {
	Vault              *v1.ResourceRequirements `json:"vault,omitempty"`
	BankVaults         *v1.ResourceRequirements `json:"bankVaults,omitempty"`
	Etcd               *v1.ResourceRequirements `json:"etcd,omitempty"`
	PrometheusExporter *v1.ResourceRequirements `json:"prometheusExporter,omitempty"`
}

// Ingress specification for the Vault cluster
type Ingress struct {
	Annotations map[string]string   `json:"annotations,omitempty"`
	Spec        v1beta1.IngressSpec `json:"spec,omitempty"`
}
