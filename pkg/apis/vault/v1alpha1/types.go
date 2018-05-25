package v1alpha1

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VaultList represents a list of Vault Kubernetes objects
type VaultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Vault `json:"items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Vault represents a Vault Kubernetes object
type Vault struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              VaultSpec   `json:"spec"`
	Status            VaultStatus `json:"status,omitempty"`
}

// VaultSpec represents the Spec field of a Vault Kubernetes object
type VaultSpec struct {
	Size            int32                  `json:"size"`
	Image           string                 `json:"image"`
	BankVaultsImage string                 `json:"bankVaultsImage"`
	Config          map[string]interface{} `json:"config"`
	ExternalConfig  map[string]interface{} `json:"externalConfig"`
	UnsealConfig    UnsealConfig           `json:"unsealConfig"`
}

// GetBankVaultsImage returns the bank-vaults image to use
func (spec *VaultSpec) GetBankVaultsImage() string {
	if spec.BankVaultsImage == "" {
		return "banzaicloud/bank-vaults:latest"
	}
	return spec.BankVaultsImage
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

// VaultStatus represents the Status field of a Vault Kubernetes object
type VaultStatus struct {
	Nodes []string `json:"nodes"`
}

// UnsealConfig represents the UnsealConfig field of a VaultSpec Kubernetes object
type UnsealConfig struct {
	Kubernetes *KubernetesUnsealConfig `json:"kubernetes"`
	Google     *GoogleUnsealConfig     `json:"google"`
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
			"--aws-s3-bucket",
			usc.AWS.S3Bucket,
			"--aws-s3-prefix",
			usc.AWS.S3Prefix,
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

// AzureUnsealConfig holds the parameters for Azure Key Vault based unsealing
type AzureUnsealConfig struct {
	KeyVaultName string `json:"keyVaultName"`
}

// AWSUnsealConfig holds the parameters for AWS KMS based unsealing
type AWSUnsealConfig struct {
	KMSKeyID string `json:"kmsKeyId"`
	S3Bucket string `json:"s3Bucket"`
	S3Prefix string `json:"s3Prefix"`
}
