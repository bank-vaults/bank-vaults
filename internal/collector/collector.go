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

package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"emperror.dev/errors"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

func CollectDeploymentEnvVars(
	k8sClient kubernetes.Interface,
	deployment *appsv1.Deployment,
) (
	[]corev1.EnvVar,
	map[metav1.Object][]corev1.EnvVar,
	error,
) {
	var envVars []corev1.EnvVar
	objectEnvVars := make(map[metav1.Object][]corev1.EnvVar)

	// Collect containers and initContainers from the deployment
	var containers []corev1.Container
	containers = append(containers, deployment.Spec.Template.Spec.Containers...)
	containers = append(containers, deployment.Spec.Template.Spec.InitContainers...)

	// Iterate through all containers and initContainers in the deployment
	for _, container := range containers {
		// Look for Vault secret references in secrets and configmaps linked as EnvFrom
		if len(container.EnvFrom) > 0 {
			for _, env := range container.EnvFrom {
				if env.ConfigMapRef != nil {
					configMap, err := getConfigmap(k8sClient, env.ConfigMapRef.Name, deployment.Namespace)
					if err != nil {
						if apierrors.IsNotFound(err) || (env.ConfigMapRef.Optional != nil && *env.ConfigMapRef.Optional) {
							continue
						}
						return nil, nil, errors.WrapIfWithDetails(err, "failed to get EnvFrom configmap", "configmap", env.ConfigMapRef.Name)
					}
					for name, value := range configMap.Data {
						appendEnvVar(&envVars, objectEnvVars, configMap, name, value)
					}

					// Look for Vault secret references in last applied configuration
					lastAppliedConfigMap, err := getConfigmapFromLastAppliedConfiguration(configMap)
					if err != nil {
						return nil, nil, errors.WrapIfWithDetails(err, "failed to get EnvFrom configmap from last applied configuration", "configmap", env.ConfigMapRef.Name)
					}
					for name, value := range lastAppliedConfigMap.Data {
						appendEnvVar(&envVars, objectEnvVars, configMap, name, value)
					}
				}
				if env.SecretRef != nil {
					secret, err := getSecret(k8sClient, env.SecretRef.Name, deployment.Namespace)
					if err != nil {
						if apierrors.IsNotFound(err) || (env.SecretRef.Optional != nil && *env.SecretRef.Optional) {
							continue
						}
						return nil, nil, errors.WrapIfWithDetails(err, "failed to get EnvFrom secret", "secret", env.SecretRef.Name)
					}
					for name, value := range secret.Data {
						appendEnvVar(&envVars, objectEnvVars, secret, name, string(value))
					}

					// Look for Vault secret references in last applied configuration
					lastAppliedSecret, err := getSecretFromLastAppliedConfiguration(secret)
					if err != nil {
						return nil, nil, errors.WrapIfWithDetails(err, "failed to get EnvFrom secret from last applied configuration", "secret", env.SecretRef.Name)
					}
					for name, value := range lastAppliedSecret.Data {
						appendEnvVar(&envVars, objectEnvVars, secret, name, string(value))
					}
				}
			}
		}

		// Look for Vault secret references in container envs
		for _, env := range container.Env {
			if HasVaultPrefix(env.Value) || HasInlineVaultDelimiters(env.Value) {
				envVars = append(envVars, env)
			}
			// Look for Vault secret references in secrets and configmaps linked as ValueFrom in container envs
			if env.ValueFrom != nil {
				if env.ValueFrom.ConfigMapKeyRef != nil {
					configMap, err := getConfigmap(k8sClient, env.ValueFrom.ConfigMapKeyRef.Name, deployment.Namespace)
					if err != nil {
						if apierrors.IsNotFound(err) {
							continue
						}
						return nil, nil, errors.WrapIfWithDetails(err, "failed to get ValueFrom configmap", "configmap", env.ValueFrom.ConfigMapKeyRef.Name)
					}

					value := configMap.Data[env.ValueFrom.ConfigMapKeyRef.Key]
					appendEnvVar(&envVars, objectEnvVars, configMap, env.Name, value)

					// Look for Vault secret references in last applied configuration as well
					lastAppliedConfigMap, err := getConfigmapFromLastAppliedConfiguration(configMap)
					if err != nil {
						return nil, nil, errors.WrapIfWithDetails(err, "failed to get ValueFrom configmap from last applied configuration", "configmap", env.ValueFrom.ConfigMapKeyRef.Name)
					}
					value = lastAppliedConfigMap.Data[env.ValueFrom.ConfigMapKeyRef.Key]
					appendEnvVar(&envVars, objectEnvVars, configMap, env.Name, value)
				}
				if env.ValueFrom.SecretKeyRef != nil {
					secret, err := getSecret(k8sClient, env.ValueFrom.SecretKeyRef.Name, deployment.Namespace)
					if err != nil {
						if apierrors.IsNotFound(err) {
							continue
						}
						return nil, nil, errors.WrapIfWithDetails(err, "failed to get ValueFrom secret", "secret", env.ValueFrom.SecretKeyRef.Name)
					}

					// Return either the value from the secret or the value from the last applied configuration
					value := secret.Data[env.ValueFrom.SecretKeyRef.Key]
					appendEnvVar(&envVars, objectEnvVars, secret, env.Name, string(value))

					// Look for Vault secret references in last applied configuration as well
					lastAppliedSecret, err := getSecretFromLastAppliedConfiguration(secret)
					if err != nil {
						return nil, nil, errors.WrapIfWithDetails(err, "failed to get ValueFrom secret from last applied configuration", "secret", env.ValueFrom.SecretKeyRef.Name)
					}

					value = lastAppliedSecret.Data[env.ValueFrom.SecretKeyRef.Key]
					appendEnvVar(&envVars, objectEnvVars, secret, env.Name, string(value))
				}
			}
		}
	}
	return envVars, objectEnvVars, nil
}

func CollectSecretEnvVars(secret *corev1.Secret) ([]corev1.EnvVar, error) {
	var envVars []corev1.EnvVar
	for name, value := range secret.Data {
		if HasVaultPrefix(string(value)) || HasInlineVaultDelimiters(string(value)) {
			envVar := corev1.EnvVar{
				Name:  name,
				Value: string(value),
			}
			envVars = append(envVars, envVar)
		}
	}
	return envVars, nil
}

func CollectConfigMapEnvVars(configmap *corev1.ConfigMap) ([]corev1.EnvVar, error) {
	var envVars []corev1.EnvVar
	for name, value := range configmap.Data {
		if HasVaultPrefix(value) || HasInlineVaultDelimiters(value) {
			envVar := corev1.EnvVar{
				Name:  name,
				Value: value,
			}
			envVars = append(envVars, envVar)
		}
	}
	return envVars, nil
}

func CollectSecretsFromEnvVars(envVars []corev1.EnvVar, vaultSecrets map[string]int) {
	// Iterate through all environment variables and extract secrets
	secretRegexp := regexp.MustCompile(`vault:(.*?)#`)
	for _, envVar := range envVars {
		// Get match group 1 from the regexp
		secret := secretRegexp.FindStringSubmatch(envVar.Value)[1]
		if secret != "" {
			// Check if the secret already exists in the map
			if _, ok := vaultSecrets[secret]; ok {
				// We only need a secret path to be added once
				continue
			} else {
				// Add the secret to the map
				vaultSecrets[secret] = 0
			}
		}
	}
}

func CollectSecretsFromAnnotation(deployment *appsv1.Deployment, vaultSecrets map[string]int) {
	vaultEnvFromPathSecret := deployment.Spec.Template.GetAnnotations()["vault.security.banzaicloud.io/vault-env-from-path"]
	if vaultEnvFromPathSecret != "" {
		if _, ok := vaultSecrets[vaultEnvFromPathSecret]; !ok {
			vaultSecrets[vaultEnvFromPathSecret] = 0
		}
	}
}

func CollectSecretsFromTemplates(
	k8sClient kubernetes.Interface,
	deployment *appsv1.Deployment,
	vaultSecrets map[string]int,
) error {
	// Collect ConfigMap names that can hold Consul templates
	var configMapNames []string
	configMapNames = append(configMapNames, deployment.Spec.Template.GetAnnotations()["vault.security.banzaicloud.io/vault-agent-configmap"])
	configMapNames = append(configMapNames, deployment.Spec.Template.GetAnnotations()["vault.security.banzaicloud.io/vault-ct-configmap"])

	var secretsFromTemplates []string
	for _, configMapName := range configMapNames {
		if configMapName != "" {
			// Get the annotation value
			vaultAgentConfigMap, err := k8sClient.CoreV1().ConfigMaps(deployment.Namespace).Get(context.Background(), configMapName, metav1.GetOptions{})
			if err != nil {
				return err
			}

			// Get the secret path from the configmap
			consulTemplate := vaultAgentConfigMap.Data["config.hcl"]
			if consulTemplate != "" {
				// Read from go template string
				tmpl := template.New("config")
				tmpl.Funcs(template.FuncMap{
					"secret": func(keys ...string) interface{} {
						secretsFromTemplates = append(secretsFromTemplates, keys[0])
						return map[string]interface{}{"Data": map[string]interface{}{"data": map[string]interface{}{"": ""}}}
					},
				})
				tmpl, err := tmpl.Parse(consulTemplate)
				if err != nil {
					return err
				}

				err = tmpl.Execute(io.Discard, nil)
				if err != nil {
					return err
				}
			}
		}
	}

	for _, secret := range secretsFromTemplates {
		// Add "data" to the secret path
		secretPathArray := strings.Split(secret, "/")
		if secretPathArray[0] == "secret" {
			secretPathArray = append(secretPathArray, "")
			copy(secretPathArray[2:], secretPathArray[1:])
			secretPathArray[1] = "data"
			secret = strings.Join(secretPathArray, "/")
			// Check if the secret already exists in the map
			if _, ok := vaultSecrets[secret]; ok {
				// We only need a secret path to be added once
				continue
			} else {
				// Add the secret to the map
				vaultSecrets[secret] = 0
			}
		}
	}
	return nil
}

func GetSecretVersionFromVault(vaultClient *vault.Client, secretPath string) (int, error) {
	secret, err := vaultClient.Vault().Logical().Read(secretPath)
	if err != nil {
		return 0, err
	}
	if secret != nil {
		secretVersion, err := secret.Data["metadata"].(map[string]interface{})["version"].(json.Number).Int64()
		if err != nil {
			return 0, err
		}
		return int(secretVersion), nil
	}

	return 0, errors.Wrap(errors.New("Secret not found"), secretPath)
}

func CreateCollectedVaultSecretsHash(vaultSecrets map[string]int) (string, error) {
	// Convert usedSecrets to an alphabetically ordered string slice
	var usedSecretsSlice []string //nolint:prealloc
	for k, v := range vaultSecrets {
		usedSecretsSlice = append(usedSecretsSlice, k)
		usedSecretsSlice = append(usedSecretsSlice, strconv.Itoa(v))
	}
	sort.Strings(usedSecretsSlice)

	// Convert usedSecretsSlice to byte slice
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(usedSecretsSlice)
	if err != nil {
		return "", err
	}
	data := buf.Bytes()

	// Create a sha256 hash
	h := sha256.Sum256(data)
	// Convert hash to hex string
	return hex.EncodeToString(h[:]), nil
}

func SetAnnotationToConfigMaps(
	k8sClient kubernetes.Interface,
	vaultClient *vault.Client,
	configMaps map[string][]corev1.EnvVar,
	namespace string,
) error {
	for configMapName, envVars := range configMaps {
		configMapVaultSecrets := make(map[string]int)
		CollectSecretsFromEnvVars(envVars, configMapVaultSecrets)

		for secretName := range configMapVaultSecrets {
			currentVersion, err := GetSecretVersionFromVault(vaultClient, secretName)
			if err != nil {
				return errors.Wrap(err, "failed to get secret version from vault")
			}
			configMapVaultSecrets[secretName] = currentVersion
		}

		// Create hash from the secrets
		hashStr, err := CreateCollectedVaultSecretsHash(configMapVaultSecrets)
		if err != nil {
			return errors.Wrap(err, "failed to create hash from secrets")
		}

		// Set the hash as an annotation on the deployent
		_, err = k8sClient.CoreV1().ConfigMaps(namespace).Patch(context.Background(), configMapName, types.MergePatchType, []byte(fmt.Sprintf(`{"metadata":{"annotations":{"alpha.vault.security.banzaicloud.io/secret-version-hash":"%s"}}}`, hashStr)), metav1.PatchOptions{})
		if err != nil {
			return errors.Wrap(err, "failed to set annotation to configmap")
		}
	}
	return nil
}

func SetAnnotationToSecrets(
	k8sClient kubernetes.Interface,
	vaultClient *vault.Client,
	secrets map[string][]corev1.EnvVar,
	namespace string,
) error {
	for secretName, envVars := range secrets {
		secretVaultSecrets := make(map[string]int)
		CollectSecretsFromEnvVars(envVars, secretVaultSecrets)

		for secretName := range secretVaultSecrets {
			currentVersion, err := GetSecretVersionFromVault(vaultClient, secretName)
			if err != nil {
				return errors.Wrap(err, "failed to get secret version from vault")
			}
			secretVaultSecrets[secretName] = currentVersion
		}

		// Create hash from the secrets
		hashStr, err := CreateCollectedVaultSecretsHash(secretVaultSecrets)
		if err != nil {
			return errors.Wrap(err, "failed to create hash from secrets")
		}

		// Set the hash as an annotation on the deployent
		_, err = k8sClient.CoreV1().Secrets(namespace).Patch(context.Background(), secretName, types.MergePatchType, []byte(fmt.Sprintf(`{"metadata":{"annotations":{"alpha.vault.security.banzaicloud.io/secret-version-hash":"%s"}}}`, hashStr)), metav1.PatchOptions{})
		if err != nil {
			return errors.Wrap(err, "failed to set annotation to secret")
		}
	}
	return nil
}
