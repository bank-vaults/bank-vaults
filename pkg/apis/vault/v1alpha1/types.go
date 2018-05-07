package v1alpha1

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type VaultList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Vault `json:"items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Vault struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              VaultSpec   `json:"spec"`
	Status            VaultStatus `json:"status,omitempty"`
}

type VaultSpec struct {
	Size            int32                  `json:"size"`
	Image           string                 `json:"image"`
	BankVaultsImage string                 `json:"bankVaultsImage"`
	Config          map[string]interface{} `json:"config"`
	ExternalConfig  map[string]interface{} `json:"externalConfig"`
	UnsealConfig    UnsealConfig           `json:"unsealConfig"`
}

func (spec *VaultSpec) GetBankVaultsImage() string {
	if spec.BankVaultsImage == "" {
		return "banzaicloud/bank-vaults:latest"
	}
	return spec.BankVaultsImage
}

func (spec *VaultSpec) ConfigJSON() string {
	config, _ := json.Marshal(spec.Config)
	return string(config)
}

func (spec *VaultSpec) ExternalConfigJSON() string {
	config, _ := json.Marshal(spec.ExternalConfig)
	return string(config)
}

type VaultStatus struct {
	Nodes []string `json:"nodes"`
}

type UnsealConfig struct {
	Kubernetes  *KubernetesUnsealConfig  `json:"kubernetes"`
	GoogleCloud *GoogleCloudUnsealConfig `json:"googleCloud"`
	Azure       *AzureUnsealConfig       `json:"azure"`
	AWS         *AWSUnsealConfig         `json:"aws"`
}

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
	if usc.GoogleCloud != nil {
		return []string{
			"--mode",
			"google-cloud-kms-gcs",
			"--google-cloud-kms-key-ring",
			usc.GoogleCloud.KMSKeyRing,
			"--google-cloud-kms-crypto-key",
			usc.GoogleCloud.KMSCryptoKey,
			"--google-cloud-kms-location",
			usc.GoogleCloud.KMSLocation,
			"--google-cloud-kms-project",
			usc.GoogleCloud.KMSProject,
			"--google-cloud-storage-bucket",
			usc.GoogleCloud.StorageBucket,
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

type KubernetesUnsealConfig struct {
	SecretNamespace string `json:"secretNamespace"`
	SecretName      string `json:"secretName"`
}

type GoogleCloudUnsealConfig struct {
	KMSKeyRing    string `json:"kmsKeyRing"`
	KMSCryptoKey  string `json:"kmsCryptoKey"`
	KMSLocation   string `json:"kmsLocation"`
	KMSProject    string `json:"kmsProject"`
	StorageBucket string `json:"storageBucket"`
}

type AzureUnsealConfig struct {
	KeyVaultName string `json:"keyVaultName"`
}

type AWSUnsealConfig struct {
	KMSKeyID string `json:"kmsKeyId"`
	S3Bucket string `json:"s3Bucket"`
	S3Prefix string `json:"s3Prefix"`
}
