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
	"context"
	"regexp"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

func LookForEnvFrom(k8sClient kubernetes.Interface, envFrom []corev1.EnvFromSource, ns string) ([]corev1.EnvVar, error) {
	var envVars []corev1.EnvVar

	for _, env := range envFrom {
		if env.ConfigMapRef != nil {
			configmap, err := getConfigmap(k8sClient, env.ConfigMapRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (env.ConfigMapRef.Optional != nil && *env.ConfigMapRef.Optional) {
					continue
				}
				return envVars, err
			}
			for key, value := range configmap.Data {
				if HasVaultPrefix(value) || HasInlineVaultDelimiters(value) {
					envFromCM := corev1.EnvVar{
						Name:  key,
						Value: value,
					}
					envVars = append(envVars, envFromCM)
				}
			}
		}
		if env.SecretRef != nil {
			secret, err := getSecret(k8sClient, env.SecretRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (env.SecretRef.Optional != nil && *env.SecretRef.Optional) {
					continue
				}
				return envVars, err
			}
			for name, v := range secret.Data {
				value := string(v)
				if HasVaultPrefix(value) || HasInlineVaultDelimiters(value) {
					envFromSec := corev1.EnvVar{
						Name:  name,
						Value: value,
					}
					envVars = append(envVars, envFromSec)
				}
			}
		}
	}
	return envVars, nil
}

func LookForValueFrom(k8sClient kubernetes.Interface, env corev1.EnvVar, ns string) (*corev1.EnvVar, error) {
	if env.ValueFrom.ConfigMapKeyRef != nil {
		configmap, err := getConfigmap(k8sClient, env.ValueFrom.ConfigMapKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		value := configmap.Data[env.ValueFrom.ConfigMapKeyRef.Key]
		if HasVaultPrefix(value) || HasInlineVaultDelimiters(value) {
			fromCM := corev1.EnvVar{
				Name:  env.Name,
				Value: value,
			}
			return &fromCM, nil
		}
	}
	if env.ValueFrom.SecretKeyRef != nil {
		secret, err := getSecret(k8sClient, env.ValueFrom.SecretKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		value := string(secret.Data[env.ValueFrom.SecretKeyRef.Key])
		if HasVaultPrefix(value) || HasInlineVaultDelimiters(value) {
			fromSecret := corev1.EnvVar{
				Name:  env.Name,
				Value: value,
			}
			return &fromSecret, nil
		}
	}
	return nil, nil
}

func getConfigmap(k8sClient kubernetes.Interface, cmName string, ns string) (*corev1.ConfigMap, error) {
	configMap, err := k8sClient.CoreV1().ConfigMaps(ns).Get(context.Background(), cmName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return configMap, nil
}

func getSecret(k8sClient kubernetes.Interface, secretName string, ns string) (*corev1.Secret, error) {
	secret, err := k8sClient.CoreV1().Secrets(ns).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func CollectSecretsFromAnnotation(deployment *appsv1.Deployment, vaultSecrets map[string]int) {
	vaultEnvFromPathSecret := deployment.Spec.Template.GetAnnotations()["vault.security.banzaicloud.io/vault-env-from-path"]
	if vaultEnvFromPathSecret != "" {
		if _, ok := vaultSecrets[vaultEnvFromPathSecret]; !ok {
			vaultSecrets[vaultEnvFromPathSecret] = 0
		}
	}
}
