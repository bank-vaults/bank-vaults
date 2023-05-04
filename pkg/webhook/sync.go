// Copyright © 2023 Banzai Cloud
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

package webhook

import (
	"emperror.dev/errors"
	"github.com/bank-vaults/vault-sdk/vault"
	"github.com/banzaicloud/bank-vaults/internal/collector"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

func (mw *MutatingWebhook) SyncDeployment(deployment *appsv1.Deployment, vaultConfig VaultConfig) error {
	// Early exit if secret sync is not enabled
	if !vaultConfig.SecretSync {
		return nil
	}

	mw.logger.Debugf("Collecting secrets from deployment: %s.%s...", deployment.GetNamespace(), deployment.GetName())

	vaultSecrets := make(map[string]int)

	// 1. Collect environment variables that need to be injected from Vault
	envVars, _, err := collector.CollectDeploymentEnvVars(mw.k8sClient, deployment)
	if err != nil {
		return errors.Wrap(err, "failed to collect secrets from envs")
	}
	mw.logger.Debug("Collecting env vars from envs done")

	collector.CollectSecretsFromEnvVars(envVars, vaultSecrets)
	mw.logger.Debug("Collecting secrets from envs done")

	// 2. Collect secrets from vault.security.banzaicloud.io/vault-env-from-path annnotation
	collector.CollectSecretsFromAnnotation(deployment, vaultSecrets)
	mw.logger.Debug("Collecting secrets from annotations done")

	// 3. Collect secrets from Consul templates
	err = collector.CollectSecretsFromTemplates(mw.k8sClient, deployment, vaultSecrets)
	if err != nil {
		return errors.Wrap(err, "failed to collect secrets from templates")
	}
	mw.logger.Debug("Collecting secrets from templates done")

	// Create a Vault client and get the current version of the secrets
	vaultClient, err := mw.newVaultClient(vaultConfig)
	if err != nil {
		return errors.Wrap(err, "failed to create vault client")
	}
	defer vaultClient.Close()

	for secretName := range vaultSecrets {
		currentVersion, err := collector.GetSecretVersionFromVault(vaultClient, secretName)
		if err != nil {
			return errors.Wrap(err, "failed to get secret version from vault")
		}
		vaultSecrets[secretName] = currentVersion
	}

	// Create hash from the secrets
	hashStr, err := collector.CreateCollectedVaultSecretsHash(vaultSecrets)
	if err != nil {
		return errors.Wrap(err, "failed to create hash from secrets")
	}
	mw.logger.Debugf("Hash from collected secrets with updated versions from Vault: %s", hashStr)

	// Set the hash as an annotation on the deployent
	deployment.Spec.Template.GetAnnotations()["alpha.vault.security.banzaicloud.io/secret-version-hash"] = hashStr

	mw.logger.Debugf("Collect secrets from deployment: %s.%s done", deployment.GetNamespace(), deployment.GetName())
	return nil
}

func (mw *MutatingWebhook) SyncSecret(secret *corev1.Secret, vaultClient *vault.Client) error {
	mw.logger.Debugf("Collecting secrets from secret: %s.%s...", secret.GetNamespace(), secret.GetName())

	vaultSecrets := make(map[string]int)

	// Collect environment variables that need to be injected from Vault
	envVars, err := collector.CollectSecretEnvVars(secret)
	if err != nil {
		return errors.Wrap(err, "failed to collect secrets from envs")
	}
	mw.logger.Debug("Collecting env vars from envs done")

	collector.CollectSecretsFromEnvVars(envVars, vaultSecrets)
	mw.logger.Debug("Collecting secrets from envs done")

	for secretName := range vaultSecrets {
		currentVersion, err := collector.GetSecretVersionFromVault(vaultClient, secretName)
		if err != nil {
			return errors.Wrap(err, "failed to get secret version from vault")
		}
		vaultSecrets[secretName] = currentVersion
	}

	// Create hash from the secrets
	hashStr, err := collector.CreateCollectedVaultSecretsHash(vaultSecrets)
	if err != nil {
		return errors.Wrap(err, "failed to create hash from secrets")
	}
	mw.logger.Debugf("Hash from collected secrets with updated versions from Vault: %s", hashStr)

	// Set the hash as an annotation on the deployent
	secret.GetAnnotations()["alpha.vault.security.banzaicloud.io/secret-version-hash"] = hashStr

	mw.logger.Debugf("Collect secrets from deployment: %s.%s done", secret.GetNamespace(), secret.GetName())
	return nil
}

func (mw *MutatingWebhook) SyncConfigMap(configMap *corev1.ConfigMap, vaultClient *vault.Client) error {
	mw.logger.Debugf("Collecting secrets from configmap: %s.%s...", configMap.GetNamespace(), configMap.GetName())

	vaultSecrets := make(map[string]int)

	// Collect environment variables that need to be injected from Vault
	envVars, err := collector.CollectConfigMapEnvVars(configMap)
	if err != nil {
		return errors.Wrap(err, "failed to collect secrets from envs")
	}
	mw.logger.Debug("Collecting env vars from envs done")

	collector.CollectSecretsFromEnvVars(envVars, vaultSecrets)
	mw.logger.Debug("Collecting secrets from envs done")

	for secretName := range vaultSecrets {
		currentVersion, err := collector.GetSecretVersionFromVault(vaultClient, secretName)
		if err != nil {
			return errors.Wrap(err, "failed to get secret version from vault")
		}
		vaultSecrets[secretName] = currentVersion
	}

	// Create hash from the secrets
	hashStr, err := collector.CreateCollectedVaultSecretsHash(vaultSecrets)
	if err != nil {
		return errors.Wrap(err, "failed to create hash from secrets")
	}
	mw.logger.Debugf("Hash from collected secrets with updated versions from Vault: %s", hashStr)

	// Set the hash as an annotation on the deployent
	configMap.GetAnnotations()["alpha.vault.security.banzaicloud.io/secret-version-hash"] = hashStr

	mw.logger.Debugf("Collect secrets from deployment: %s.%s done", configMap.GetNamespace(), configMap.GetName())
	return nil
}
