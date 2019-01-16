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
	"encoding/json"
	"reflect"

	"github.com/spf13/cast"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultSpec defines the desired state of Vault
type VaultSpec struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	Size              int32                  `json:"size"`
	Image             string                 `json:"image"`
	BankVaultsImage   string                 `json:"bankVaultsImage"`
	StatsDImage       string                 `json:"statsdImage"`
	FluentDEnabled    bool                   `json:"fluentdEnabled"`
	FluentDImage      string                 `json:"fluentdImage"`
	Annotations       map[string]string      `json:"annotations"`
	Config            map[string]interface{} `json:"config"`
	ExternalConfig    map[string]interface{} `json:"externalConfig"`
	UnsealConfig      UnsealConfig           `json:"unsealConfig"`
	CredentialsConfig CredentialsConfig      `json:"credentialsConfig"`
	EnvsConfig        []v1.EnvVar            `json:"envsConfig"`
	SecurityContext   v1.PodSecurityContext  `json:"securityContext,omitempty"`
	// This option gives us the option to workaround current StatefulSet limitations around updates
	// See: https://github.com/kubernetes/kubernetes/issues/67250
	// TODO: Should be removed once the ParallelPodManagement policy supports the broken update.
	SupportUpgrade     bool                    `json:"supportUpgrade"`
	EtcdVersion        string                  `json:"etcdVersion"`
	EtcdSize           int                     `json:"etcdSize"`
	EtcdAnnotations    map[string]string       `json:"etcdAnnotations,omitempty"`
	ServiceType        string                  `json:"serviceType"`
	PodAntiAffinity    string                  `json:"podAntiAffinity"`
	NodeAffinity       v1.NodeAffinity         `json:"nodeAffinity"`
	ServiceAccount     string                  `json:"serviceAccount"`
	Volumes            []v1.Volume             `json:"volumes,omitempty"`
	VolumeMounts       []v1.VolumeMount        `json:"volumeMounts,omitempty"`
	VaultEnvsConfig    []v1.EnvVar             `json:"vaultEnvsConfig"`
	VaultResource      v1.ResourceRequirements `json:"vaultResource"`
	BankVaultsResource v1.ResourceRequirements `json:"bankVaultsResource"`
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

// GetAnnotations returns the Annotations
func (spec *VaultSpec) GetAnnotations() map[string]string {
	if spec.Annotations == nil {
		spec.Annotations = map[string]string{}
	}
	spec.Annotations["prometheus.io/scrape"] = "true"
	spec.Annotations["prometheus.io/path"] = "/metrics"
	spec.Annotations["prometheus.io/port"] = "9102"
	return spec.Annotations
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
	// zero value for bool is false
	return spec.FluentDEnabled
}

// ConfigJSON returns the Config field as a JSON string
func (spec *VaultSpec) ConfigJSON() string {
	if _, ok := spec.Config["disable_clustering"]; !ok {
		spec.Config["disable_clustering"] = true
	}
	config, _ := json.Marshal(spec.Config)
	return string(config)
}

// ExternalConfigJSON returns the ExternalConfig field as a JSON string
func (spec *VaultSpec) ExternalConfigJSON() string {
	config, _ := json.Marshal(spec.ExternalConfig)
	return string(config)
}

// VaultStatus defines the observed state of Vault
type VaultStatus struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	Nodes []string `json:"nodes"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Vault is the Schema for the vaults API
// +k8s:openapi-gen=true
type Vault struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultSpec   `json:"spec,omitempty"`
	Status VaultStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VaultList contains a list of Vault
type VaultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Vault `json:"items"`
}

// UnsealConfig represents the UnsealConfig field of a VaultSpec Kubernetes object
type UnsealConfig struct {
	Kubernetes *KubernetesUnsealConfig `json:"kubernetes"`
	Google     *GoogleUnsealConfig     `json:"google"`
	Alibaba    *AlibabaUnsealConfig    `json:"alibaba"`
	Azure      *AzureUnsealConfig      `json:"azure"`
	AWS        *AWSUnsealConfig        `json:"aws"`
}

// ToArgs returns the UnsealConfig as and argument array for bank-vaults
func (usc *UnsealConfig) ToArgs(vault *Vault) []string {
	if usc.Kubernetes != nil {
		secretNamespace := vault.Namespace
		if usc.Kubernetes.SecretNamespace != "" {
			secretNamespace = usc.Kubernetes.SecretNamespace
		}
		secretName := vault.Name + "-unseal-keys"
		if usc.Kubernetes.SecretName != "" {
			secretName = usc.Kubernetes.SecretName
		}
		return []string{"--mode", "k8s", "--k8s-secret-namespace", secretNamespace, "--k8s-secret-name", secretName}
	}
	if usc.Google != nil {
		return []string{
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
		}
	}
	if usc.Azure != nil {
		return []string{"--mode", "azure-key-vault", "--azure-key-vault-name", usc.Azure.KeyVaultName}
	}
	if usc.AWS != nil {
		return []string{
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
		}
	}
	if usc.Alibaba != nil {
		return []string{
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
		}
	}
	return []string{}
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

func init() {
	SchemeBuilder.Register(&Vault{}, &VaultList{})
}
