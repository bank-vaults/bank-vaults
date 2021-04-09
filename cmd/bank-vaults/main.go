// Copyright © 2020 Banzai Cloud
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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var c = viper.New()

const (
	cfgSecretShares    = "secret-shares"
	cfgSecretThreshold = "secret-threshold"
)

const (
	cfgMode                       = "mode"
	cfgModeValueAWSKMS3           = "aws-kms-s3"
	cfgModeValueGoogleCloudKMSGCS = "google-cloud-kms-gcs"
	cfgModeValueAzureKeyVault     = "azure-key-vault"
	cfgModeValueAlibabaKMSOSS     = "alibaba-kms-oss"
	cfgModeValueVault             = "vault"
	cfgModeValueK8S               = "k8s"
	cfgModeValueHSMK8S            = "hsm-k8s"
	cfgModeValueHSM               = "hsm"
	cfgModeValueDev               = "dev"
	cfgModeValueFile              = "file"
)

const (
	cfgGoogleCloudKMSProject   = "google-cloud-kms-project"
	cfgGoogleCloudKMSLocation  = "google-cloud-kms-location"
	cfgGoogleCloudKMSKeyRing   = "google-cloud-kms-key-ring"
	cfgGoogleCloudKMSCryptoKey = "google-cloud-kms-crypto-key"
)

const (
	cfgGoogleCloudStorageBucket = "google-cloud-storage-bucket"
	cfgGoogleCloudStoragePrefix = "google-cloud-storage-prefix"
)

const (
	cfgAWSKMSRegion = "aws-kms-region"
	cfgAWSKMSKeyID  = "aws-kms-key-id"
)

const (
	cfgAWSS3Bucket = "aws-s3-bucket"
	cfgAWSS3Prefix = "aws-s3-prefix"
	cfgAWSS3Region = "aws-s3-region"
	cfgAWS3SSEAlgo = "aws-s3-sse-algo"
)

const cfgAzureKeyVaultName = "azure-key-vault-name"

const (
	cfgAlibabaOSSEndpoint     = "alibaba-oss-endpoint"
	cfgAlibabaOSSBucket       = "alibaba-oss-bucket"
	cfgAlibabaOSSPrefix       = "alibaba-oss-prefix"
	cfgAlibabaAccessKeyID     = "alibaba-access-key-id"
	cfgAlibabaAccessKeySecret = "alibaba-access-key-secret"
	cfgAlibabaKMSRegion       = "alibaba-kms-region"
	cfgAlibabaKMSKeyID        = "alibaba-kms-key-id"
)

const (
	cfgVaultAddress        = "vault-addr"
	cfgVaultUnsealKeysPath = "vault-unseal-keys-path"
	cfgVaultRole           = "vault-role"
	cfgVaultAuthPath       = "vault-auth-path"
	cfgVaultTokenPath      = "vault-token-path"
	cfgVaultToken          = "vault-token"
)

const (
	cfgK8SNamespace = "k8s-secret-namespace"
	cfgK8SSecret    = "k8s-secret-name"
	cfgK8SLabels    = "k8s-secret-labels"
)

const (
	cfgHSMModulePath = "hsm-module-path"
	cfgHSMSlotID     = "hsm-slot-id"
	cfgHSMTokenLabel = "hsm-token-label" // nolint:gosec
	cfgHSMPin        = "hsm-pin"
	cfgHSMKeyLabel   = "hsm-key-label"
)

const cfgFilePath = "file-path"

// We need to pre-create a value and bind the the flag to this until
// https://github.com/spf13/viper/issues/608 gets fixed.
var k8sSecretLabels map[string]string

var rootCmd = &cobra.Command{
	Use:   "bank-vaults",
	Short: "Automates initialization, unsealing and configuration of Hashicorp Vault.",
	Long:  `This is a CLI tool to help automate the setup and management of Hashicorp Vault.`,
}

func execute() {
	// Handle signals to prevent bad exit codes on `docker stop`.
	// TODO: probably a more sophisticated exit procedure should be implemented in the future.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGABRT)
	go func() {
		<-sigs
		os.Exit(0)
	}()

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatalf("error executing command: %s", err.Error())
	}
}

func configBoolVar(cmd *cobra.Command, key string, defaultValue bool, description string) {
	cmd.PersistentFlags().Bool(key, defaultValue, description)
	_ = c.BindPFlag(key, cmd.PersistentFlags().Lookup(key))
}

func configDurationVar(cmd *cobra.Command, key string, defaultValue time.Duration, description string) {
	cmd.PersistentFlags().Duration(key, defaultValue, description)
	_ = c.BindPFlag(key, cmd.PersistentFlags().Lookup(key))
}

func configIntVar(cmd *cobra.Command, key string, defaultValue int, description string) {
	cmd.PersistentFlags().Int(key, defaultValue, description)
	_ = c.BindPFlag(key, cmd.PersistentFlags().Lookup(key))
}

func configStringVar(cmd *cobra.Command, key, defaultValue, description string) {
	cmd.PersistentFlags().String(key, defaultValue, description)
	_ = c.BindPFlag(key, cmd.PersistentFlags().Lookup(key))
}

func configStringSliceVar(cmd *cobra.Command, key string, defaultValue []string, description string) {
	cmd.PersistentFlags().StringSlice(key, defaultValue, description)
	_ = c.BindPFlag(key, cmd.PersistentFlags().Lookup(key))
}

func configStringMapVar(cmd *cobra.Command, key string, value *map[string]string, description string) {
	cmd.PersistentFlags().StringToStringVar(value, key, nil, description)
	_ = c.BindPFlag(key, cmd.Flags().Lookup(key))
}

func init() {
	c.SetEnvPrefix("bank_vaults")
	replacer := strings.NewReplacer("-", "_")
	c.SetEnvKeyReplacer(replacer)
	c.AutomaticEnv()

	// Select mode
	configStringVar(
		rootCmd,
		cfgMode,
		cfgModeValueK8S,
		fmt.Sprintf(`Select the mode to use:
						'%s' => Google Cloud Storage using Google KMS encryption;
						'%s' => AWS S3 Object Storage using AWS KMS encryption;
						'%s' => Azure Key Vault secret;
						'%s' => Alibaba OSS using Alibaba KMS encryption;
						'%s' => Remote Vault;
						'%s' => Kubernetes Secrets;
						'%s' => Kubernetes Secrets encrypted with HSM;
						'%s' => HSM object on device, using HSM encryption;
						'%s' => Dev (vault server -dev) mode
						'%s' => File mode`,
			cfgModeValueGoogleCloudKMSGCS,
			cfgModeValueAWSKMS3,
			cfgModeValueAzureKeyVault,
			cfgModeValueAlibabaKMSOSS,
			cfgModeValueVault,
			cfgModeValueK8S,
			cfgModeValueHSMK8S,
			cfgModeValueHSM,
			cfgModeValueDev,
			cfgModeValueFile,
		),
	)

	// Secret config
	configIntVar(rootCmd, cfgSecretShares, 5, "Total count of secret shares that exist")
	configIntVar(rootCmd, cfgSecretThreshold, 3, "Minimum required secret shares to unseal")

	// Google Cloud KMS flags
	configStringVar(rootCmd, cfgGoogleCloudKMSProject, "", "The Google Cloud KMS project to use")
	configStringVar(rootCmd, cfgGoogleCloudKMSLocation, "", "The Google Cloud KMS location to use (eg. 'global', 'europe-west1')")
	configStringVar(rootCmd, cfgGoogleCloudKMSKeyRing, "", "The name of the Google Cloud KMS key ring to use")
	configStringVar(rootCmd, cfgGoogleCloudKMSCryptoKey, "", "The name of the Google Cloud KMS crypt key to use")

	// Google Cloud Storage flags
	configStringVar(rootCmd, cfgGoogleCloudStorageBucket, "", "The name of the Google Cloud Storage bucket to store values in")
	configStringVar(rootCmd, cfgGoogleCloudStoragePrefix, "", "The prefix to use for values store in Google Cloud Storage")

	// AWS KMS flags
	configStringSliceVar(rootCmd, cfgAWSKMSRegion, nil, "The region of the AWS KMS key to encrypt values")
	configStringSliceVar(rootCmd, cfgAWSKMSKeyID, nil, "The ID or ARN of the AWS KMS key to encrypt values")

	// AWS S3 Object Storage flags
	configStringSliceVar(rootCmd, cfgAWSS3Region, []string{"us-east-1"}, "The region to use for storing values in AWS S3")
	configStringSliceVar(rootCmd, cfgAWSS3Bucket, nil, "The name of the AWS S3 bucket to store values in")
	configStringVar(rootCmd, cfgAWSS3Prefix, "", "The prefix to use for storing values in AWS S3")
	configStringSliceVar(rootCmd, cfgAWS3SSEAlgo, []string{""}, "The algorithm to use for the S3 SSE")

	// Azure Key Vault flags
	configStringVar(rootCmd, cfgAzureKeyVaultName, "", "The name of the Azure Key Vault to encrypt and store values in")

	// Alibaba Access Key flags
	configStringVar(rootCmd, cfgAlibabaAccessKeyID, "", "The Alibaba AccessKeyID to use")
	configStringVar(rootCmd, cfgAlibabaAccessKeySecret, "", "The Alibaba AccessKeySecret to use")

	// Alibaba KMS flags
	configStringVar(rootCmd, cfgAlibabaKMSRegion, "", "The region where the Alibaba KMS key relies")
	configStringVar(rootCmd, cfgAlibabaKMSKeyID, "", "The ID of the Alibaba KMS key to encrypt values")

	// Alibaba Object Storage Service flags
	configStringVar(rootCmd, cfgAlibabaOSSEndpoint, "", "The name of the Alibaba OSS endpoint to store values in")
	configStringVar(rootCmd, cfgAlibabaOSSBucket, "", "The name of the Alibaba OSS bucket to store values in")
	configStringVar(rootCmd, cfgAlibabaOSSPrefix, "", "The prefix to use for values store in Alibaba OSS")

	// Vault Service Flags
	configStringVar(rootCmd, cfgVaultAddress, "", "The URL of the remote Vault to use as KV. Example: https://vault.myvault.org:8200")
	configStringVar(rootCmd, cfgVaultUnsealKeysPath, "", "Path at the remote URL to store Unseal Keys")
	configStringVar(rootCmd, cfgVaultRole, "", "Vault Role to authenticate as")
	configStringVar(rootCmd, cfgVaultAuthPath, "", "Auth path for Kubernetes auth type")
	configStringVar(rootCmd, cfgVaultTokenPath, "", "Path to file containing Vault token")
	configStringVar(rootCmd, cfgVaultToken, "", "Vault token")

	// K8S Secret Storage flags
	configStringVar(rootCmd, cfgK8SNamespace, "", "The namespace of the K8S Secret to store values in")
	configStringVar(rootCmd, cfgK8SSecret, "", "The name of the K8S Secret to store values in")
	configStringMapVar(rootCmd, cfgK8SLabels, &k8sSecretLabels, "The labels of the K8S Secret to store values in")

	// HSM flags
	configStringVar(rootCmd, cfgHSMModulePath, "", "The library path of the HSM device")
	configIntVar(rootCmd, cfgHSMSlotID, 0, "The ID of the HSM slot")
	configStringVar(rootCmd, cfgHSMTokenLabel, "", "The label of the token in a HSM slot")
	configStringVar(rootCmd, cfgHSMPin, "", "The pin of the HSM token to login with")
	configStringVar(rootCmd, cfgHSMKeyLabel, "bank-vaults", "The label of the HSM private key")

	// File flags
	configStringVar(rootCmd, cfgFilePath, "", "The path prefix of the files where to store values in")
}

func main() {
	flag.Parse()
	execute()
}
