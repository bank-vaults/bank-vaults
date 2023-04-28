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
	"context"

	"emperror.dev/errors"
	"github.com/banzaicloud/bank-vaults/internal/collector"
	"github.com/slok/kubewebhook/v2/pkg/model"
	"github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (mw *MutatingWebhook) VaultSecretSyncMutator(ctx context.Context, ar *model.AdmissionReview, obj metav1.Object) (*mutating.MutatorResult, error) {
	vaultConfig := parseVaultConfig(obj, ar)

	if vaultConfig.Skip {
		return &mutating.MutatorResult{}, nil
	}

	if !vaultConfig.SecretSync {
		return &mutating.MutatorResult{}, nil
	}

	switch v := obj.(type) {
	case *appsv1.Deployment:
		return &mutating.MutatorResult{MutatedObject: v}, mw.SyncDeployment(v, vaultConfig)

	default:
		return &mutating.MutatorResult{}, nil
	}
}

func (mw *MutatingWebhook) SyncDeployment(deployment *appsv1.Deployment, vaultConfig VaultConfig) error {
	mw.logger.Debugf("Collecting secrets from deployment: %s.%s...", deployment.GetNamespace(), deployment.GetName())

	vaultSecrets := make(map[string]int)

	// 1. Collect environment variables that need to be injected from Vault
	err := collector.CollectDeploymentSecretsFromEnv(deployment, vaultSecrets)
	if err != nil {
		return errors.Wrap(err, "failed to collect secrets from envs")
	}
	mw.logger.Debug("Collecting secrets from envs done")

	// 2. Collect secrets from vault.security.banzaicloud.io/vault-env-from-path annnotation
	collector.CollectSecretsFromAnnotation(deployment, vaultSecrets)
	mw.logger.Debug("Collecting secrets from annotations done")

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

	return nil
}
