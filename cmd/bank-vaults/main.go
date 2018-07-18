package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var appConfig *viper.Viper

const cfgSecretShares = "secret-shares"
const cfgSecretThreshold = "secret-threshold"

const cfgMode = "mode"
const cfgModeValueAWSKMS3 = "aws-kms-s3"
const cfgModeValueGoogleCloudKMSGCS = "google-cloud-kms-gcs"
const cfgModeValueAzureKeyVault = "azure-key-vault"
const cfgModeValueAlibabaKMSOSS = "alibaba-kms-oss"
const cfgModeValueK8S = "k8s"
const cfgModeValueDev = "dev"

const cfgGoogleCloudKMSProject = "google-cloud-kms-project"
const cfgGoogleCloudKMSLocation = "google-cloud-kms-location"
const cfgGoogleCloudKMSKeyRing = "google-cloud-kms-key-ring"
const cfgGoogleCloudKMSCryptoKey = "google-cloud-kms-crypto-key"

const cfgGoogleCloudStorageBucket = "google-cloud-storage-bucket"
const cfgGoogleCloudStoragePrefix = "google-cloud-storage-prefix"

const cfgAWSKMSRegion = "aws-kms-region"
const cfgAWSKMSKeyID = "aws-kms-key-id"

const cfgAWSS3Bucket = "aws-s3-bucket"
const cfgAWSS3Prefix = "aws-s3-prefix"
const cfgAWSS3Region = "aws-s3-region"

const cfgAzureKeyVaultName = "azure-key-vault-name"

const cfgAlibabaOSSEndpoint = "alibaba-oss-endpoint"
const cfgAlibabaOSSBucket = "alibaba-oss-bucket"
const cfgAlibabaOSSPrefix = "alibaba-oss-prefix"
const cfgAlibabaAccessKeyID = "alibaba-access-key-id"
const cfgAlibabaAccessKeySecret = "alibaba-access-key-secret"
const cfgAlibabaKMSRegion = "alibaba-kms-region"
const cfgAlibabaKMSKeyID = "alibaba-kms-key-id"

const cfgK8SNamespace = "k8s-secret-namespace"
const cfgK8SSecret = "k8s-secret-name"

var rootCmd = &cobra.Command{
	Use:   "bank-vaults",
	Short: "Automates initialization, unsealing and configuration of Hashicorp Vault.",
	Long:  `This is a CLI tool to help automate the setup and management of Hashicorp Vault.`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func configIntVar(key string, defaultValue int, description string) {
	rootCmd.PersistentFlags().Int(key, defaultValue, description)
	appConfig.BindPFlag(key, rootCmd.PersistentFlags().Lookup(key))
}

func configStringVar(key, defaultValue, description string) {
	rootCmd.PersistentFlags().String(key, defaultValue, description)
	appConfig.BindPFlag(key, rootCmd.PersistentFlags().Lookup(key))
}

func init() {
	appConfig = viper.New()
	appConfig.SetEnvPrefix("bank_vaults")
	replacer := strings.NewReplacer("-", "_")
	appConfig.SetEnvKeyReplacer(replacer)
	appConfig.AutomaticEnv()

	// SelectMode
	configStringVar(
		cfgMode,
		cfgModeValueGoogleCloudKMSGCS,
		fmt.Sprintf(`Select the mode to use:
						'%s' => Google Cloud Storage with encryption using Google KMS;
						'%s' => AWS S3 Object Storage using AWS KMS encryption;
						'%s' => Azure Key Vault secret;
						'%s' => Alibaba OSS with KMS encryption;
						'%s' => Kubernetes Secrets;
						'%s' => Dev (local) mode`,
			cfgModeValueGoogleCloudKMSGCS,
			cfgModeValueAWSKMS3,
			cfgModeValueAzureKeyVault,
			cfgModeValueAlibabaKMSOSS,
			cfgModeValueK8S,
			cfgModeValueDev),
	)

	// Secret config
	configIntVar(cfgSecretShares, 5, "Total count of secret shares that exist")
	configIntVar(cfgSecretThreshold, 3, "Minimum required secret shares to unseal")

	// Google Cloud KMS flags
	configStringVar(cfgGoogleCloudKMSProject, "", "The Google Cloud KMS project to use")
	configStringVar(cfgGoogleCloudKMSLocation, "", "The Google Cloud KMS location to use (eg. 'global', 'europe-west1')")
	configStringVar(cfgGoogleCloudKMSKeyRing, "", "The name of the Google Cloud KMS key ring to use")
	configStringVar(cfgGoogleCloudKMSCryptoKey, "", "The name of the Google Cloud KMS crypt key to use")

	// Google Cloud Storage flags
	configStringVar(cfgGoogleCloudStorageBucket, "", "The name of the Google Cloud Storage bucket to store values in")
	configStringVar(cfgGoogleCloudStoragePrefix, "", "The prefix to use for values store in Google Cloud Storage")

	// AWS KMS flags
	configStringVar(cfgAWSKMSRegion, "", "The region of the AWS KMS key to encrypt values")
	configStringVar(cfgAWSKMSKeyID, "", "The ID or ARN of the AWS KMS key to encrypt values")

	// AWS S3 Object Storage flags
	configStringVar(cfgAWSS3Bucket, "", "The name of the AWS S3 bucket to store values in")
	configStringVar(cfgAWSS3Prefix, "", "The prefix to use for storing values in AWS S3")
	configStringVar(cfgAWSS3Region, "us-east-1", "The region to use for storing values in AWS S3")

	// Azure Key Vault flags
	configStringVar(cfgAzureKeyVaultName, "", "The name of the Azure Key Vault to encrypt and store values in")

	// Alibaba Access Key flags
	configStringVar(cfgAlibabaAccessKeyID, "", "The Alibaba AccessKeyID to use")
	configStringVar(cfgAlibabaAccessKeySecret, "", "The Alibaba AccessKeySecret to use")

	// Alibaba KMS flags
	configStringVar(cfgAlibabaKMSRegion, "", "The region where the Alibaba KMS key relies")
	configStringVar(cfgAlibabaKMSKeyID, "", "The ID of the Alibaba KMS key to encrypt values")

	// Alibaba Object Storage Service flags
	configStringVar(cfgAlibabaOSSEndpoint, "", "The name of the Alibaba OSS endpoint to store values in")
	configStringVar(cfgAlibabaOSSBucket, "", "The name of the Alibaba OSS bucket to store values in")
	configStringVar(cfgAlibabaOSSPrefix, "", "The prefix to use for values store in Alibaba OSS")

	// K8S Secret Storage flags
	configStringVar(cfgK8SNamespace, "", "The namespace of the K8S Secret to store values in")
	configStringVar(cfgK8SSecret, "", "The name of the K8S Secret to store values in")
}

func main() {
	flag.Parse()
	execute()
}
