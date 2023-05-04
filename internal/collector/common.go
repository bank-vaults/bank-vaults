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
	"encoding/json"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func HasVaultPrefix(value string) bool {
	return strings.HasPrefix(value, "vault:") || strings.HasPrefix(value, ">>vault:")
}

var inlineMutationRegex = regexp.MustCompile(`\${([>]{0,2}vault:.*?#*}?)}`)

func HasInlineVaultDelimiters(value string) bool {
	return len(FindInlineVaultDelimiters(value)) > 0
}

func FindInlineVaultDelimiters(value string) [][]string {
	return inlineMutationRegex.FindAllStringSubmatch(value, -1)
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

func getConfigmapFromLastAppliedConfiguration(configmap *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	var lastAppliedConfigMap corev1.ConfigMap
	err := json.Unmarshal([]byte(configmap.ObjectMeta.GetAnnotations()["kubectl.kubernetes.io/last-applied-configuration"]), &lastAppliedConfigMap)
	if err != nil {
		return nil, err
	}

	return &lastAppliedConfigMap, nil
}

func getSecretFromLastAppliedConfiguration(secret *corev1.Secret) (*corev1.Secret, error) {
	var lastAppliedSecret corev1.Secret
	err := json.Unmarshal([]byte(secret.ObjectMeta.GetAnnotations()["kubectl.kubernetes.io/last-applied-configuration"]), &lastAppliedSecret)
	if err != nil {
		return nil, err
	}

	return &lastAppliedSecret, nil
}

func appendEnvVar(envVars *[]corev1.EnvVar, mapWithEnvVars map[metav1.Object][]corev1.EnvVar, object metav1.Object, varName, varValue string) {
	if HasVaultPrefix(varValue) || HasInlineVaultDelimiters(varValue) {
		envVar := corev1.EnvVar{
			Name:  varName,
			Value: varValue,
		}
		*envVars = append(*envVars, envVar)
		mapWithEnvVars[object] = append(mapWithEnvVars[object], envVar)
	}
}
