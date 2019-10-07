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
	"time"

	"github.com/Masterminds/semver"
	"github.com/spf13/cast"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
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
// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
type VaultSpec struct {

	// Size defines the number of Vault instances in the cluster (>= 1 means HA)
	// default: 1
	Size int32 `json:"size"`

	// Image specifies the Vault image to use for the Vault instances
	// default: library/vault:latest
	Image string `json:"image"`

	// BankVaultsImage specifies the Bank Vaults image to use for Vault unsealing and configuration
	// default: banzaicloud/bank-vaults:latest
	BankVaultsImage string `json:"bankVaultsImage"`

	// StatsDDisabled specifies if StatsD based metrics should be disabled
	// default: false
	StatsDDisabled bool `json:"statsdDisabled"`

	// StatsDImage specifices the StatsD image to use for Vault metrics exportation
	// default: prom/statsd-exporter:latest
	StatsDImage string `json:"statsdImage"`

	// FluentDEnabled specifies if FluentD based log exportation should be enabled
	// default: false
	FluentDEnabled bool `json:"fluentdEnabled"`

	// FluentDImage specifices the FluentD image to use for Vault log exportation
	// default: fluent/fluentd:stable
	FluentDImage string `json:"fluentdImage"`

	// FluentDConfig specifices the FluentD configuration to use for Vault log exportation
	// default:
	FluentDConfig string `json:"fluentdConfig"`

	// WatchedSecretsLabels specifices a set of Kubernetes label selectors which select Secrets to watch.
	// If these Secrets change the Vault cluster gets restarted. For example a Secret that Cert-Manager is
	// managing a public Certificate for Vault using let's Encrypt.
	// default:
	WatchedSecretsLabels []map[string]string `json:"watchedSecretsLabels"`

	// Annotations define a set of common Kubernetes annotations that will be added to all operator managed resources.
	// default:
	Annotations map[string]string `json:"annotations"`

	// VaultAnnotations define a set of Kubernetes annotations that will be added to all Vault Pods.
	// default:
	VaultAnnotations map[string]string `json:"vaultAnnotations"`

	// VaultLabels define a set of Kubernetes labels that will be added to all Vault Pods.
	// default:
	VaultLabels map[string]string `json:"vaultLabels"`

	// VaultPodSpec is a Kubernetes Pod specification snippet (`spec:` block) that will be merged into the operator generated
	// Vault Pod specification.
	// default:
	VaultPodSpec v1.PodSpec `json:"vaultPodSpec"`

	// VaultConfigurerAnnotations define a set of Kubernetes annotations that will be added to the Vault Configurer Pod.
	// default:
	VaultConfigurerAnnotations map[string]string `json:"vaultConfigurerAnnotations"`

	// VaultConfigurerLabels define a set of Kubernetes labels that will be added to all Vault Configurer Pod.
	// default:
	VaultConfigurerLabels map[string]string `json:"vaultConfigurerLabels"`

	// VaultConfigurerPodSpec is a Kubernetes Pod specification snippet (`spec:` block) that will be merged into
	// the operator generated Vault Configurer Pod specification.
	// default:
	VaultConfigurerPodSpec v1.PodSpec `json:"vaultConfigurerPodSpec"`

	// Config is the Vault Server configuration. See https://www.vaultproject.io/docs/configuration/ for more details.
	// default:
	Config VaultConfig `json:"config"`

	// ExternalConfig is higher level configuration block which instructs the Bank Vaults Configurer to configure Vault
	// through its API, thus allows setting up:
	// - Secret Engines
	// - Auth Methods
	// - Autid Devices
	// - Plugin Backends
	// - Policies
	// - Startup Secrets (Bank Vaults feature)
	// A documented example: https://github.com/banzaicloud/bank-vaults/blob/master/vault-config.yml
	// default:
	ExternalConfig VaultExternalConfig `json:"externalConfig"`

	// UnsealConfig defines where the Vault cluster's unseal keys and root token should be stored after initialization.
	// See the type's documentation for more details. Only one method may be specified.
	// default: Kubernetes Secret based unsealing
	UnsealConfig UnsealConfig `json:"unsealConfig"`

	// CredentialsConfig defines a external Secret for Vault and how it should be mounted to the Vault Pod
	// for example accessing Cloud resources.
	// default:
	CredentialsConfig CredentialsConfig `json:"credentialsConfig"`

	// EnvsConfig is a list of Kubernetes environment variable definitions that will be passed to all Bank-Vaults pods.
	// default:
	EnvsConfig []v1.EnvVar `json:"envsConfig"`

	// SecurityContext is a Kubernetes PodSecurityContext that will be applied to all Pods created by the operator.
	// default:
	SecurityContext v1.PodSecurityContext `json:"securityContext,omitempty"`

	// EtcdVersion is the ETCD version of the automatically provisioned ETCD cluster
	// default: "3.1.15"
	EtcdVersion string `json:"etcdVersion"`

	// EtcdSize is the size of the automatically provisioned ETCD cluster, -1 will disable automatic cluster provisioning.
	// The cluster is only provisioned if it is detected from the Vault configuration that it would like to use
	// ETCD as the storage backend. If not odd it will be changed always to the next (< etcdSize) odd number.
	// default: 3
	EtcdSize int `json:"etcdSize"`

	// EtcdRepository is the repository used to pull the etcd imaegs
	// default:
	EtcdRepository string `json:"etcdRepository,omitempty"`

	// BusyBox image used for the etcd pod init container
	// default:
	EtcdPodBusyBoxImage string `json:"etcdPodBusyBoxImage,omitempty"`

	// EtcdAnnotations define a set of Kubernetes annotations that will be added to ETCD Cluster CR.
	// default:
	EtcdAnnotations map[string]string `json:"etcdAnnotations,omitempty"`

	// EtcdPodAnnotations define a set of Kubernetes annotations that will be added to ETCD Pods.
	// default:
	EtcdPodAnnotations map[string]string `json:"etcdPodAnnotations,omitempty"`

	// EtcdPVCSpec is a Kuberrnetes PersistentVolumeClaimSpec that will be used by the ETCD Pods.
	// emptyDir is used if not defined (no persistence).
	// default:
	EtcdPVCSpec *v1.PersistentVolumeClaimSpec `json:"etcdPVCSpec,omitempty"`

	// ServiceType is a Kuberrnetes Service type of the Vault Service.
	// default: ClusterIP
	ServiceType string `json:"serviceType"`

	// ServicePorts is an extra map of ports that should be exposed by the Vault Service.
	// default:
	ServicePorts map[string]int32 `json:"servicePorts"`

	// PodAntiAffinity is the TopologyKey in the Vault Pod's PodAntiAffinity.
	// No PodAntiAffinity is used if empty.
	// default:
	PodAntiAffinity string `json:"podAntiAffinity"`

	// NodeAffinity is Kubernetees NodeAffinity definition that should be applied to all Vault Pods.
	// default:
	NodeAffinity v1.NodeAffinity `json:"nodeAffinity"`

	// NodeSelector is Kubernetees NodeSelector definition that should be applied to all Vault Pods.
	// default:
	NodeSelector map[string]string `json:"nodeSelector"`

	// Tolerations is Kubernetes Tolerations definition that should be applied to all Vault Pods.
	// default:
	Tolerations []v1.Toleration `json:"tolerations"`

	// ServiceAccount is Kubernetes ServiceAccount in which the Vault Pods should be running in.
	// default: default
	ServiceAccount string `json:"serviceAccount"`

	// Volumes define some extra Kubernetes Volumes for the Vault Pods.
	// default:
	Volumes []v1.Volume `json:"volumes,omitempty"`

	// VolumeMounts define some extra Kubernetes Volume mounts for the Vault Pods.
	// default:
	VolumeMounts []v1.VolumeMount `json:"volumeMounts,omitempty"`

	// VolumeClaimTemplates define some extra Kubernetes PersistentVolumeClaim templates for the Vault Statefulset.
	// default:
	VolumeClaimTemplates []v1.PersistentVolumeClaim `json:"volumeClaimTemplates,omitempty"`

	// VaultEnvsConfig is a list of Kubernetes environment variable definitions that will be passed to Vault Pods.
	// default:
	VaultEnvsConfig []v1.EnvVar `json:"vaultEnvsConfig"`

	// Resources defines the resource limits for all the resources created by the operator.
	// See the type for more details.
	// default:
	Resources *Resources `json:"resources,omitempty"`

	// Ingress, if it is specified the operator will create an Ingress resource for the Vault Service and
	// will annotate it with the correct Ingress annotations specific to the TLS settings in the configuration.
	// See the type for more details.
	// default:
	Ingress *Ingress `json:"ingress,omitempty"`

	// ServiceMonitorEnabled enables the creation of Prometheus Operator specific ServiceMonitor for Vault.
	// default: false
	ServiceMonitorEnabled bool `json:"serviceMonitorEnabled,omitempty"`

	// TLSExpiryThreshold is the Vault TLS certificate expiration threshold in Go's Duration format.
	// default: 168h
	TLSExpiryThreshold *time.Duration `json:"tlsExpiryThreshold,omitempty"`

	// CANamespaces define a list of namespaces where the generated CA certificate for Vault should be distributed,
	// use ["*"] for all namespaces.
	// default:
	CANamespaces []string `json:"caNamespaces,omitempty"`
}

// HAStorageTypes is the set of storage backends supporting High Availability
var HAStorageTypes = map[string]bool{
	"consul":     true,
	"dynamodb":   true,
	"etcd":       true,
	"gcs":        true,
	"mysql":      true,
	"postgresql": true,
	"raft":       true,
	"spanner":    true,
	"zookeeper":  true,
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
	return storageType == "consul" || storageType == "raft" || cast.ToBool(storageSpecs["ha_enabled"])
}

// GetTLSDisable returns if Vault's TLS should be disabled
func (spec *VaultSpec) GetTLSDisable() bool {
	listener := spec.getListener()
	tcpSpecs := cast.ToStringMap(listener["tcp"])
	return cast.ToBool(tcpSpecs["tls_disable"])
}

// GetTLSExpiryThreshold returns the Vault TLS certificate expiration threshold
func (spec *VaultSpec) GetTLSExpiryThreshold() time.Duration {
	if spec.TLSExpiryThreshold == nil {
		return time.Hour * 168
	}
	return *spec.TLSExpiryThreshold
}

func (spec *VaultSpec) getListener() map[string]interface{} {
	return cast.ToStringMap(spec.Config["listener"])
}

// GetVaultImage returns the Vault image to use
func (spec *VaultSpec) GetVaultImage() string {
	if spec.Image == "" {
		return "vault:latest"
	}
	return spec.Image
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

// GetVaultLAbels returns the Vault Pod , Secret and ConfigMap Labels
func (spec *VaultSpec) GetVaultLabels() map[string]string {
	if spec.VaultLabels == nil {
		spec.VaultLabels = map[string]string{}
	}

	return spec.VaultLabels
}

// GetVaultConfigurerLabels returns the Vault Configurer Pod Labels
func (spec *VaultSpec) GetVaultConfigurerLabels() map[string]string {
	if spec.VaultConfigurerLabels == nil {
		spec.VaultConfigurerLabels = map[string]string{}
	}

	return spec.VaultConfigurerLabels
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

// IsStatsDDisabled returns false if statsd sidecar is to be deployed
func (spec *VaultSpec) IsStatsDDisabled() bool {
	return spec.StatsDDisabled
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

// IsRaftStorage checks if raft storage is configured
func (spec *VaultSpec) IsRaftStorage() bool {
	return spec.GetStorageType() == "raft"
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
	Options    UnsealOptions          `json:"options,omitempty"`
	Kubernetes KubernetesUnsealConfig `json:"kubernetes,omitempty"`
	Google     *GoogleUnsealConfig    `json:"google,omitempty"`
	Alibaba    *AlibabaUnsealConfig   `json:"alibaba,omitempty"`
	Azure      *AzureUnsealConfig     `json:"azure,omitempty"`
	AWS        *AWSUnsealConfig       `json:"aws,omitempty"`
	Vault      *VaultUnsealConfig     `json:"vault,omitempty"`
}

// UnsealOptions represents the common options to all unsealing backends
type UnsealOptions struct {
	PreFlightChecks *bool `json:"preFlightChecks,omitempty"`
}

func (uso UnsealOptions) ToArgs() []string {
	args := []string{}
	if uso.PreFlightChecks == nil || *uso.PreFlightChecks {
		args = append(args, "--pre-flight-checks", "true")
	}
	return args
}

// ToArgs returns the UnsealConfig as and argument array for bank-vaults
func (usc *UnsealConfig) ToArgs(vault *Vault) []string {
	args := []string{}

	if usc.Google != nil {

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

	} else if usc.Vault != nil {

		args = append(args,
			"--mode",
			"vault",
			"--vault-addr",
			usc.Vault.Address,
			"--vault-unseal-keys-path",
			usc.Vault.UnsealKeysPath,
		)

		if usc.Vault.Token != "" {
			args = append(args,
				"--vault-token",
				usc.Vault.Token,
			)
		} else if usc.Vault.TokenPath != "" {
			args = append(args,
				"--vault-token-path",
				usc.Vault.TokenPath,
			)
		} else if usc.Vault.Role != "" {
			args = append(args,
				"--vault-role",
				usc.Vault.Role,
				"--vault-auth-path",
				usc.Vault.AuthPath,
			)
		}

	} else {

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

// VaultUnsealConfig holds the parameters for remote Vault based unsealing
type VaultUnsealConfig struct {
	Address        string `json:"address"`
	UnsealKeysPath string `json:"unsealKeysPath"`
	Role           string `json:"role"`
	AuthPath       string `json:"authPath"`
	TokenPath      string `json:"tokenPath"`
	Token          string `json:"token"`
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
