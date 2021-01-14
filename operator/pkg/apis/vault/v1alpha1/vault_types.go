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
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/coreos/etcd-operator/pkg/util/etcdutil"
	"github.com/imdario/mergo"
	"github.com/spf13/cast"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	extv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var log = logf.Log.WithName("controller_vault")

var bankVaultsImage string

func init() {
	if bankVaultsImage = os.Getenv("BANK_VAULTS_IMAGE"); bankVaultsImage == "" {
		bankVaultsImage = "ghcr.io/banzaicloud/bank-vaults:latest"
	}
}

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

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultSpec defines the desired state of Vault
// Important: Run "make generate-code" to regenerate code after modifying this file
type VaultSpec struct {

	// Size defines the number of Vault instances in the cluster (>= 1 means HA)
	// default: 1
	Size int32 `json:"size,omitempty"`

	// Image specifies the Vault image to use for the Vault instances
	// default: library/vault:latest
	Image string `json:"image,omitempty"`

	// BankVaultsImage specifies the Bank Vaults image to use for Vault unsealing and configuration
	// default: banzaicloud/bank-vaults:latest
	BankVaultsImage string `json:"bankVaultsImage,omitempty"`

	// BankVaultsVolumeMounts define some extra Kubernetes Volume mounts for the Bank Vaults Sidecar container.
	// default:
	BankVaultsVolumeMounts []v1.VolumeMount `json:"bankVaultsVolumeMounts,omitempty"`

	// StatsDDisabled specifies if StatsD based metrics should be disabled
	// default: false
	StatsDDisabled bool `json:"statsdDisabled,omitempty"`

	// StatsDImage specifices the StatsD image to use for Vault metrics exportation
	// default: prom/statsd-exporter:latest
	StatsDImage string `json:"statsdImage,omitempty"`

	// FluentDEnabled specifies if FluentD based log exportation should be enabled
	// default: false
	FluentDEnabled bool `json:"fluentdEnabled,omitempty"`

	// FluentDImage specifices the FluentD image to use for Vault log exportation
	// default: fluent/fluentd:edge
	FluentDImage string `json:"fluentdImage,omitempty"`

	// FleuntDConfLocation is the location of the fluent.conf file
	// default: "/fluentd/etc"
	FleuntDConfLocation string `json:"fleuntdConfLocation,omitempty"`

	// FluentDConfig specifices the FluentD configuration to use for Vault log exportation
	// default:
	FluentDConfig string `json:"fluentdConfig,omitempty"`

	// WatchedSecretsLabels specifices a set of Kubernetes label selectors which select Secrets to watch.
	// If these Secrets change the Vault cluster gets restarted. For example a Secret that Cert-Manager is
	// managing a public Certificate for Vault using let's Encrypt.
	// default:
	WatchedSecretsLabels []map[string]string `json:"watchedSecretsLabels,omitempty"`

	// WatchedSecretsAnnotations specifices a set of Kubernetes annotations selectors which select Secrets to watch.
	// If these Secrets change the Vault cluster gets restarted. For example a Secret that Cert-Manager is
	// managing a public Certificate for Vault using let's Encrypt.
	// default:
	WatchedSecretsAnnotations []map[string]string `json:"watchedSecretsAnnotations,omitempty"`

	// Annotations define a set of common Kubernetes annotations that will be added to all operator managed resources.
	// default:
	Annotations map[string]string `json:"annotations,omitempty"`

	// VaultAnnotations define a set of Kubernetes annotations that will be added to all Vault Pods.
	// default:
	VaultAnnotations map[string]string `json:"vaultAnnotations,omitempty"`

	// VaultLabels define a set of Kubernetes labels that will be added to all Vault Pods.
	// default:
	VaultLabels map[string]string `json:"vaultLabels,omitempty"`

	// VaultPodSpec is a Kubernetes Pod specification snippet (`spec:` block) that will be merged into the operator generated
	// Vault Pod specification.
	// default:
	VaultPodSpec *EmbeddedPodSpec `json:"vaultPodSpec,omitempty"`

	// VaultContainerSpec is a Kubernetes Container specification snippet that will be merged into the operator generated
	// Vault Container specification.
	// default:
	VaultContainerSpec v1.Container `json:"vaultContainerSpec,omitempty"`

	// VaultConfigurerAnnotations define a set of Kubernetes annotations that will be added to the Vault Configurer Pod.
	// default:
	VaultConfigurerAnnotations map[string]string `json:"vaultConfigurerAnnotations,omitempty"`

	// VaultConfigurerLabels define a set of Kubernetes labels that will be added to all Vault Configurer Pod.
	// default:
	VaultConfigurerLabels map[string]string `json:"vaultConfigurerLabels,omitempty"`

	// VaultConfigurerPodSpec is a Kubernetes Pod specification snippet (`spec:` block) that will be merged into
	// the operator generated Vault Configurer Pod specification.
	// default:
	VaultConfigurerPodSpec *EmbeddedPodSpec `json:"vaultConfigurerPodSpec,omitempty"`

	// Config is the Vault Server configuration. See https://www.vaultproject.io/docs/configuration/ for more details.
	// default:
	Config extv1beta1.JSON `json:"config"`

	// ExternalConfig is higher level configuration block which instructs the Bank Vaults Configurer to configure Vault
	// through its API, thus allows setting up:
	// - Secret Engines
	// - Auth Methods
	// - Audit Devices
	// - Plugin Backends
	// - Policies
	// - Startup Secrets (Bank Vaults feature)
	// A documented example: https://github.com/banzaicloud/bank-vaults/blob/master/vault-config.yml
	// default:
	ExternalConfig extv1beta1.JSON `json:"externalConfig,omitempty"`

	// UnsealConfig defines where the Vault cluster's unseal keys and root token should be stored after initialization.
	// See the type's documentation for more details. Only one method may be specified.
	// default: Kubernetes Secret based unsealing
	UnsealConfig UnsealConfig `json:"unsealConfig,omitempty"`

	// CredentialsConfig defines a external Secret for Vault and how it should be mounted to the Vault Pod
	// for example accessing Cloud resources.
	// default:
	CredentialsConfig CredentialsConfig `json:"credentialsConfig,omitempty"`

	// EnvsConfig is a list of Kubernetes environment variable definitions that will be passed to all Bank-Vaults pods.
	// default:
	EnvsConfig []v1.EnvVar `json:"envsConfig,omitempty"`

	// SecurityContext is a Kubernetes PodSecurityContext that will be applied to all Pods created by the operator.
	// default:
	SecurityContext v1.PodSecurityContext `json:"securityContext,omitempty"`

	// EtcdVersion is the ETCD version of the automatically provisioned ETCD cluster
	// default: "3.3.17"
	EtcdVersion string `json:"etcdVersion,omitempty"`

	// EtcdSize is the size of the automatically provisioned ETCD cluster, -1 will disable automatic cluster provisioning.
	// The cluster is only provisioned if it is detected from the Vault configuration that it would like to use
	// ETCD as the storage backend. If not odd it will be changed always to the next (< etcdSize) odd number.
	// default: 3
	EtcdSize int `json:"etcdSize,omitempty"`

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

	// EtcdAffinity is a Kubernetes Affinity that will be used by the ETCD Pods.
	// If not defined PodAntiAffinity will be use.  If both are empty no Affinity is used
	// default:
	EtcdAffinity *v1.Affinity `json:"etcdAffinity,omitempty"`

	// ServiceType is a Kubernetes Service type of the Vault Service.
	// default: ClusterIP
	ServiceType string `json:"serviceType,omitempty"`

	// LoadBalancerIP is an optional setting for allocating a specific address for the entry service object
	// of type LoadBalancer
	// default: ""
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`

	// serviceRegistrationEnabled enables the injection of the service_registration Vault stanza.
	// This requires elaborated RBAC privileges for updating Pod labels for the Vault Pod.
	// default: false
	ServiceRegistrationEnabled bool `json:"serviceRegistrationEnabled,omitempty"`

	// RaftLeaderAddress defines the leader address of the raft cluster in multi-cluster deployments.
	// (In single cluster (namespace) deployments it is automatically detected).
	// "self" is a special value which means that this instance should be the bootstrap leader instance.
	// default: ""
	RaftLeaderAddress string `json:"raftLeaderAddress,omitempty"`

	// ServicePorts is an extra map of ports that should be exposed by the Vault Service.
	// default:
	ServicePorts map[string]int32 `json:"servicePorts,omitempty"`

	// Affinity is a group of affinity scheduling rules applied to all Vault Pods.
	// default:
	Affinity *v1.Affinity `json:"affinity,omitempty"`

	// PodAntiAffinity is the TopologyKey in the Vault Pod's PodAntiAffinity.
	// No PodAntiAffinity is used if empty.
	// Deprecated. Use Affinity.
	// default:
	PodAntiAffinity string `json:"podAntiAffinity,omitempty"`

	// NodeAffinity is Kubernetees NodeAffinity definition that should be applied to all Vault Pods.
	// Deprecated. Use Affinity.
	// default:
	NodeAffinity v1.NodeAffinity `json:"nodeAffinity,omitempty"`

	// NodeSelector is Kubernetees NodeSelector definition that should be applied to all Vault Pods.
	// default:
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations is Kubernetes Tolerations definition that should be applied to all Vault Pods.
	// default:
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`

	// ServiceAccount is Kubernetes ServiceAccount in which the Vault Pods should be running in.
	// default: default
	ServiceAccount string `json:"serviceAccount,omitempty"`

	// Volumes define some extra Kubernetes Volumes for the Vault Pods.
	// default:
	Volumes []v1.Volume `json:"volumes,omitempty"`

	// VolumeMounts define some extra Kubernetes Volume mounts for the Vault Pods.
	// default:
	VolumeMounts []v1.VolumeMount `json:"volumeMounts,omitempty"`

	// VolumeClaimTemplates define some extra Kubernetes PersistentVolumeClaim templates for the Vault Statefulset.
	// default:
	VolumeClaimTemplates []EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplates,omitempty"`

	// VaultEnvsConfig is a list of Kubernetes environment variable definitions that will be passed to the Vault container.
	// default:
	VaultEnvsConfig []v1.EnvVar `json:"vaultEnvsConfig,omitempty"`

	// SidecarEnvsConfig is a list of Kubernetes environment variable definitions that will be passed to Vault sidecar containers.
	// default:
	SidecarEnvsConfig []v1.EnvVar `json:"sidecarEnvsConfig,omitempty"`

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

	// ExistingTLSSecretName is name of the secret that contains a TLS server certificate and key and the corresponding CA certificate.
	// Required secret format kubernetes.io/tls type secret keys + ca.crt key
	// If it is set, generating certificate will be disabled
	// default: ""
	ExistingTLSSecretName string `json:"existingTlsSecretName,omitempty"`

	// TLSExpiryThreshold is the Vault TLS certificate expiration threshold in Go's Duration format.
	// default: 168h
	TLSExpiryThreshold string `json:"tlsExpiryThreshold,omitempty"`

	// TLSAdditionalHosts is a list of additional hostnames or IP addresses to add to the SAN on the automatically generated TLS certificate.
	// default:
	TLSAdditionalHosts []string `json:"tlsAdditionalHosts,omitempty"`

	// CANamespaces define a list of namespaces where the generated CA certificate for Vault should be distributed,
	// use ["*"] for all namespaces.
	// default:
	CANamespaces []string `json:"caNamespaces,omitempty"`

	// IstioEnabled describes if the cluster has a Istio running and enabled.
	// default: false
	IstioEnabled bool `json:"istioEnabled,omitempty"`

	// VeleroEnabled describes if the cluster has a Velero running and enabled.
	// default: false
	VeleroEnabled bool `json:"veleroEnabled,omitempty"`

	// VeleroFsfreezeImage specifices the Velero Fsrfeeze image to use in Velero backup hooks
	// default: velero/fsfreeze-pause:latest
	VeleroFsfreezeImage string `json:"veleroFsfreezeImage,omitempty"`

	// InitContainers add extra initContainers
	VaultInitContainers []v1.Container `json:"vaultInitContainers,omitempty"`
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
	if spec.hasHAStorageStanza() {
		return true
	}
	return false
}

func (spec *VaultSpec) hasHAStorageStanza() bool {
	return len(spec.getHAStorage()) != 0
}

// HasEtcdStorage detects if Vault is configured to use etcd as storage or ha_storage backend
func (spec *VaultSpec) HasEtcdStorage() bool {
	if spec.hasHAStorageStanza() && spec.GetHAStorageType() == "etcd" {
		return true
	}
	return spec.GetStorageType() == "etcd"
}

// GetStorage returns Vault's storage stanza
func (spec *VaultSpec) GetStorage() map[string]interface{} {
	storage := spec.getStorage()
	return cast.ToStringMap(storage[spec.GetStorageType()])
}

func (spec *VaultSpec) getStorage() map[string]interface{} {
	config := spec.GetVaultConfig()
	return cast.ToStringMap(config["storage"])
}

// GetHAStorage returns Vault's ha_storage stanza
func (spec *VaultSpec) GetHAStorage() map[string]interface{} {
	haStorage := spec.getHAStorage()
	return cast.ToStringMap(haStorage[spec.GetHAStorageType()])
}

func (spec *VaultSpec) getHAStorage() map[string]interface{} {
	config := spec.GetVaultConfig()
	return cast.ToStringMap(config["ha_storage"])
}

func (spec *VaultSpec) GetVaultConfig() map[string]interface{} {
	var config map[string]interface{}
	// This config JSON is already validated,
	// so we can skip wiring through the error everywhere.
	_ = json.Unmarshal(spec.Config.Raw, &config)
	return config
}

// GetEtcdStorage returns the etcd storage if configured or nil
func (spec *VaultSpec) GetEtcdStorage() map[string]interface{} {
	if spec.hasHAStorageStanza() && spec.GetHAStorageType() == "etcd" {
		return spec.GetHAStorage()
	}
	if spec.GetStorageType() == "etcd" {
		return spec.GetStorage()
	}
	return nil
}

// GetStorageType returns the type of Vault's storage stanza
func (spec *VaultSpec) GetStorageType() string {
	storage := spec.getStorage()
	return reflect.ValueOf(storage).MapKeys()[0].String()
}

// GetHAStorageType returns the type of Vault's ha_storage stanza
func (spec *VaultSpec) GetHAStorageType() string {
	haStorage := spec.getHAStorage()
	if len(haStorage) == 0 {
		return ""
	}
	return reflect.ValueOf(haStorage).MapKeys()[0].String()
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
		return "3.3.17"
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

// IsTLSDisabled returns if Vault's TLS should be disabled
func (spec *VaultSpec) IsTLSDisabled() bool {
	listener := spec.getListener()
	tcp := cast.ToStringMap(listener["tcp"])
	return cast.ToBool(tcp["tls_disable"])
}

// IsTelemetryUnauthenticated returns if Vault's telemetry endpoint can be accessed publicly
func (spec *VaultSpec) IsTelemetryUnauthenticated() bool {
	listener := spec.getListener()
	tcp := cast.ToStringMap(listener["tcp"])
	telemetry := cast.ToStringMap(tcp["telemetry"])
	return cast.ToBool(telemetry["unauthenticated_metrics_access"])
}

// GetAPIScheme returns if Vault's API address should be called on http or https
func (spec *VaultSpec) GetAPIScheme() string {
	if spec.IsTLSDisabled() {
		return "http"
	}
	return "https"
}

// GetTLSExpiryThreshold returns the Vault TLS certificate expiration threshold
func (spec *VaultSpec) GetTLSExpiryThreshold() time.Duration {
	if spec.TLSExpiryThreshold == "" {
		return time.Hour * 168
	}
	duration, err := time.ParseDuration(spec.TLSExpiryThreshold)
	if err != nil {
		log.Error(err, "using default treshold due to parse error", "tlsExpiryThreshold", spec.TLSExpiryThreshold)
		return time.Hour * 168
	}
	return duration
}

func (spec *VaultSpec) getListener() map[string]interface{} {
	config := spec.GetVaultConfig()
	return cast.ToStringMap(config["listener"])
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
		return bankVaultsImage
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

// GetVeleroFsfreezeImage returns the Velero Fsreeze image to use
func (spec *VaultSpec) GetVeleroFsfreezeImage() string {
	if spec.VeleroFsfreezeImage == "" {
		return "ubuntu:bionic"
	}
	return spec.VeleroFsfreezeImage
}

// GetVolumeClaimTemplates fixes the "status diff" in PVC templates
func (spec *VaultSpec) GetVolumeClaimTemplates() []v1.PersistentVolumeClaim {
	var pvcs []v1.PersistentVolumeClaim
	for _, pvc := range spec.VolumeClaimTemplates {
		pvcs = append(pvcs, v1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:        pvc.Name,
				Labels:      pvc.Labels,
				Annotations: pvc.Annotations,
			},
			Spec: pvc.Spec,
		})
	}
	return pvcs
}

// GetWatchedSecretsLabels returns the set of labels for secrets to watch in the vault namespace
func (spec *VaultSpec) GetWatchedSecretsLabels() []map[string]string {
	if spec.WatchedSecretsLabels == nil {
		spec.WatchedSecretsLabels = []map[string]string{}
	}

	return spec.WatchedSecretsLabels
}

// GetWatchedSecretsAnnotations returns the set of annotations for secrets to watch in the vault namespace
func (spec *VaultSpec) GetWatchedSecretsAnnotations() []map[string]string {
	if spec.WatchedSecretsAnnotations == nil {
		spec.WatchedSecretsAnnotations = []map[string]string{}
	}

	return spec.WatchedSecretsAnnotations
}

// GetAnnotations returns the Common Annotations
func (spec *VaultSpec) GetAnnotations() map[string]string {
	if spec.Annotations == nil {
		spec.Annotations = map[string]string{}
	}

	return spec.Annotations
}

// GetAPIPortName returns the main Vault port name based on Istio and TLS settings
func (spec *VaultSpec) GetAPIPortName() string {
	portName := "api-port"
	if spec.IstioEnabled {
		if spec.IsTLSDisabled() {
			return "http-" + portName
		}
		return "https-" + portName
	}
	return portName
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
		return "fluent/fluentd:edge"
	}
	return spec.FluentDImage
}

// GetFluentDConfMountPath returns the mount path for the fluent.conf
func (spec *VaultSpec) GetFluentDConfMountPath() string {
	if spec.FleuntDConfLocation == "" {
		return "/fluentd/etc"
	}
	return spec.FleuntDConfLocation
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
func (v *Vault) ConfigJSON() (string, error) {
	config := map[string]interface{}{}

	err := json.Unmarshal(v.Spec.Config.Raw, &config)
	if err != nil {
		return "", err
	}

	if v.Spec.ServiceRegistrationEnabled && v.Spec.HasHAStorage() {
		serviceRegistration := map[string]interface{}{
			"service_registration": map[string]interface{}{
				"kubernetes": map[string]string{
					"namespace": v.Namespace,
				},
			},
		}

		if err := mergo.Merge(&config, serviceRegistration); err != nil {
			return "", err
		}
	}

	// Overwrite Vault config with the generated TLS certificate's settings
	if v.Spec.HasEtcdStorage() && v.Spec.GetEtcdSize() > 0 {
		storageKey := "storage"
		if v.Spec.hasHAStorageStanza() && v.Spec.GetHAStorageType() == "etcd" {
			storageKey = "ha_storage"
		}
		etcdStorage := map[string]interface{}{
			storageKey: map[string]interface{}{
				"etcd": map[string]interface{}{
					"tls_ca_file":   "/etcd/tls/" + etcdutil.CliCAFile,
					"tls_cert_file": "/etcd/tls/" + etcdutil.CliCertFile,
					"tls_key_file":  "/etcd/tls/" + etcdutil.CliKeyFile,
				},
			},
		}

		if err := mergo.Merge(&config, etcdStorage); err != nil {
			return "", err
		}
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return "", err
	}

	return string(configJSON), nil
}

// ExternalConfigJSON returns the ExternalConfig field as a JSON string
func (spec *VaultSpec) ExternalConfigJSON() string {
	return string(spec.ExternalConfig.Raw)
}

// IsAutoUnseal checks if auto-unseal is configured
func (spec *VaultSpec) IsAutoUnseal() bool {
	config := spec.GetVaultConfig()
	_, ok := config["seal"]
	return ok
}

// IsRaftStorage checks if raft storage is configured
func (spec *VaultSpec) IsRaftStorage() bool {
	return spec.GetStorageType() == "raft"
}

// IsRaftHAStorage checks if raft ha_storage is configured
func (spec *VaultSpec) IsRaftHAStorage() bool {
	return spec.GetStorageType() != "raft" && spec.GetHAStorageType() == "raft"
}

// IsRaftBootstrapFollower checks if this cluster should be considered the bootstrap follower.
func (spec *VaultSpec) IsRaftBootstrapFollower() bool {
	return spec.RaftLeaderAddress != "" && spec.RaftLeaderAddress != "self"
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
		if !vault.Spec.IsTLSDisabled() {
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

// LabelsForVault returns the labels for selecting the resources
// belonging to the given vault CR name.
func (vault *Vault) LabelsForVault() map[string]string {
	return map[string]string{"app.kubernetes.io/name": "vault", "vault_cr": vault.Name}
}

// LabelsForVaultConfigurer returns the labels for selecting the resources
// belonging to the given vault CR name.
func (vault *Vault) LabelsForVaultConfigurer() map[string]string {
	return map[string]string{"app.kubernetes.io/name": "vault-configurator", "vault_cr": vault.Name}
}

// AsOwnerReference returns this Vault instance as an OwnerReference
func (vault *Vault) AsOwnerReference() metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: vault.APIVersion,
		Kind:       vault.Kind,
		Name:       vault.Name,
		UID:        vault.UID,
		Controller: pointer.BoolPtr(true),
	}
}

// VaultStatus defines the observed state of Vault
type VaultStatus struct {
	// Important: Run "make generate-code" to regenerate code after modifying this file
	Nodes      []string                `json:"nodes"`
	Leader     string                  `json:"leader"`
	Conditions []v1.ComponentCondition `json:"conditions,omitempty"`
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
	HSM        *HSMUnsealConfig       `json:"hsm,omitempty"`
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
			"--aws-s3-sse-algo",
			usc.AWS.S3SSE,
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

	} else if usc.HSM != nil {

		mode := "hsm"
		if usc.Kubernetes.SecretNamespace != "" && usc.Kubernetes.SecretName != "" {
			mode = "hsm-k8s"
		}

		args = append(args,
			"--mode",
			mode,
			"--hsm-module-path",
			usc.HSM.ModulePath,
			"--hsm-slot-id",
			fmt.Sprint(usc.HSM.SlotID),
			"--hsm-key-label",
			usc.HSM.KeyLabel,
			"--hsm-pin",
			usc.HSM.Pin,
		)

		if usc.HSM.TokenLabel != "" {
			args = append(args,
				"--hsm-token-label",
				usc.HSM.TokenLabel,
			)
		}

		if mode == "hsm-k8s" {
			var secretLabels []string
			for k, v := range vault.LabelsForVault() {
				secretLabels = append(secretLabels, k+"="+v)
			}

			sort.Strings(secretLabels)

			args = append(args,
				"--k8s-secret-namespace",
				usc.Kubernetes.SecretNamespace,
				"--k8s-secret-name",
				usc.Kubernetes.SecretName,
				"--k8s-secret-labels",
				strings.Join(secretLabels, ","),
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

		var secretLabels []string
		for k, v := range vault.LabelsForVault() {
			secretLabels = append(secretLabels, k+"="+v)
		}

		sort.Strings(secretLabels)

		args = append(args,
			"--mode",
			"k8s",
			"--k8s-secret-namespace",
			secretNamespace,
			"--k8s-secret-name",
			secretName,
			"--k8s-secret-labels",
			strings.Join(secretLabels, ","),
		)

	}

	return args
}

// HSMDaemonNeeded returns if the unsealing mechanims needs a HSM Daemon present
func (usc *UnsealConfig) HSMDaemonNeeded() bool {
	return usc.HSM != nil && usc.HSM.Daemon
}

// KubernetesUnsealConfig holds the parameters for Kubernetes based unsealing
type KubernetesUnsealConfig struct {
	SecretNamespace string `json:"secretNamespace,omitempty"`
	SecretName      string `json:"secretName,omitempty"`
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
	S3SSE     string `json:"s3SSE,omitempty"`
}

// VaultUnsealConfig holds the parameters for remote Vault based unsealing
type VaultUnsealConfig struct {
	Address        string `json:"address"`
	UnsealKeysPath string `json:"unsealKeysPath"`
	Role           string `json:"role,omitempty"`
	AuthPath       string `json:"authPath,omitempty"`
	TokenPath      string `json:"tokenPath,omitempty"`
	Token          string `json:"token,omitempty"`
}

// HSMUnsealConfig holds the parameters for remote HSM based unsealing
type HSMUnsealConfig struct {
	Daemon     bool   `json:"daemon,omitempty"`
	ModulePath string `json:"modulePath"`
	SlotID     uint   `json:"slotId,omitempty"`
	TokenLabel string `json:"tokenLabel,omitempty"`
	Pin        string `json:"pin"`
	KeyLabel   string `json:"keyLabel"`
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
	HSMDaemon          *v1.ResourceRequirements `json:"hsmDaemon,omitempty"`
	Etcd               *v1.ResourceRequirements `json:"etcd,omitempty"`
	PrometheusExporter *v1.ResourceRequirements `json:"prometheusExporter,omitempty"`
	FluentD            *v1.ResourceRequirements `json:"fluentd,omitempty"`
}

// Ingress specification for the Vault cluster
type Ingress struct {
	Annotations map[string]string   `json:"annotations,omitempty"`
	Spec        v1beta1.IngressSpec `json:"spec,omitempty"`
}
