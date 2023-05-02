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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CollectDeploymentSecretsFromEnv(
	deployment *appsv1.Deployment,
	vaultSecrets map[string]int,
) error {
	var envVars []corev1.EnvVar

	// Collect containers and initContainers from the deployment
	var containers []corev1.Container
	containers = append(containers, deployment.Spec.Template.Spec.Containers...)
	containers = append(containers, deployment.Spec.Template.Spec.InitContainers...)

	// Iterate through all containers and initContainers in the deployment
	for _, container := range containers {
		// List of environment variables to set in the container.
		for _, env := range container.Env {
			if HasVaultPrefix(env.Value) || HasInlineVaultDelimiters(env.Value) {
				envVars = append(envVars, env)
			}
		}
	}

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

	return nil
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
