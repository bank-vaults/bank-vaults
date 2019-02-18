// Copyright © 2018 Banzai Cloud
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
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	whhttp "github.com/slok/kubewebhook/pkg/http"
	"github.com/slok/kubewebhook/pkg/log"
	whcontext "github.com/slok/kubewebhook/pkg/webhook/context"
	"github.com/slok/kubewebhook/pkg/webhook/mutating"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type vaultConfig struct {
	addr       string
	role       string
	path       string
	skipVerify string
	useAgent   bool
}

var vaultAgentConfig = `
pid_file = "./pidfile"
exit_after_auth = true

auto_auth {
	method "kubernetes" {
		mount_path = "%s"
		config = {
			role = "%s"
		}
	}

	sink "file" {
		config = {
			path = "/vault/token"
		}
	}
}`

func getInitContainers(vaultConfig vaultConfig) []corev1.Container {
	containers := []corev1.Container{}

	if vaultConfig.useAgent {
		containers = append(containers, corev1.Container{
			Name:            "vault-agent",
			Image:           viper.GetString("vault_image"),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"vault", "agent", "-config=/vault-agent/config.hcl"},
			Env: []corev1.EnvVar{
				{
					Name:  "VAULT_ADDR",
					Value: vaultConfig.addr,
				},
				{
					Name:  "VAULT_SKIP_VERIFY",
					Value: vaultConfig.skipVerify,
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "vault-agent-config",
					MountPath: "/vault-agent/",
				},
				{
					Name:      "vault-env",
					MountPath: "/vault/",
				},
			},
		})
	}

	containers = append(containers, corev1.Container{
		Name:            "copy-vault-env",
		Image:           viper.GetString("vault_env_image"),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"sh", "-c", "cp /usr/local/bin/vault-env /vault/"},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "vault-env",
				MountPath: "/vault/",
			},
		},
	})

	return containers
}

func getVolumes(name string, vaultConfig vaultConfig) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "vault-env",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		},
	}

	if vaultConfig.useAgent {
		volumes = append(volumes, corev1.Volume{
			Name: "vault-agent-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: name + "-vault-agent-config",
					},
				},
			},
		})
	}

	return volumes
}

func vaultSecretsMutator(ctx context.Context, obj metav1.Object) (bool, error) {
	var podSpec *corev1.PodSpec

	switch v := obj.(type) {
	case *corev1.Pod:
		podSpec = &v.Spec
	default:
		return false, nil
	}

	vaultConfig := parseVaultConfig(obj)

	return false, mutatePodSpec(obj, podSpec, vaultConfig, whcontext.GetAdmissionRequest(ctx).Namespace)
}

func parseVaultConfig(obj metav1.Object) vaultConfig {
	var vaultConfig vaultConfig
	annotations := obj.GetAnnotations()
	vaultConfig.addr = annotations["vault.security.banzaicloud.io/vault-addr"]
	vaultConfig.role = annotations["vault.security.banzaicloud.io/vault-role"]
	if vaultConfig.role == "" {
		vaultConfig.role = "default"
	}
	vaultConfig.path = annotations["vault.security.banzaicloud.io/vault-path"]
	if vaultConfig.path == "" {
		vaultConfig.path = "kubernetes"
	}
	vaultConfig.skipVerify = annotations["vault.security.banzaicloud.io/vault-skip-verify"]
	vaultConfig.useAgent, _ = strconv.ParseBool(annotations["vault.security.banzaicloud.io/vault-agent"])
	return vaultConfig
}

func getConfigMapForVaultAgent(obj metav1.Object, vaultConfig vaultConfig) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: obj.GetName() + "-vault-agent-config",
			// OwnerReferences: []metav1.OwnerReference{
			// 	{
			// 		Name: obj.GetName(),
			// 		// UID:  obj.GetUID(),
			// 	},
			// },
		},
		Data: map[string]string{
			"config.hcl": fmt.Sprintf(vaultAgentConfig, vaultConfig.path, vaultConfig.role),
		},
	}
}

func getDataFromConfigmap(cmName string, ns string) (map[string]string, error) {
	clientset, err := newClientSet()
	if err != nil {
		return nil, err
	}
	configMap, err := clientset.CoreV1().ConfigMaps(ns).Get(cmName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return configMap.Data, nil
}

func getDataFromSecret(secretName string, ns string) (map[string][]byte, error) {
	clientset, err := newClientSet()
	if err != nil {
		return nil, err
	}
	secret, err := clientset.CoreV1().Secrets(ns).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func lookForEnvFrom(envFrom []corev1.EnvFromSource, ns string) []corev1.EnvVar {
	var envVars []corev1.EnvVar

	for _, ef := range envFrom {
		if ef.ConfigMapRef != nil {
			data, err := getDataFromConfigmap(ef.ConfigMapRef.Name, ns)
			if err != nil {
				continue
			}
			for key, value := range data {
				if strings.HasPrefix(value, "vault:") {
					envFromCM := corev1.EnvVar{
						Name:  key,
						Value: value,
					}
					envVars = append(envVars, envFromCM)
				}
			}
		}
		if ef.SecretRef != nil {
			data, err := getDataFromSecret(ef.SecretRef.Name, ns)
			if err != nil {
				continue
			}
			for key, value := range data {
				if strings.HasPrefix(string(value), "vault:") {
					envFromSec := corev1.EnvVar{
						Name:  key,
						Value: string(value),
					}
					envVars = append(envVars, envFromSec)
				}
			}
		}
	}
	return envVars
}

func lookForValueFrom(env corev1.EnvVar, ns string) (corev1.EnvVar, error) {
	if env.ValueFrom.ConfigMapKeyRef != nil {
		data, err := getDataFromConfigmap(env.ValueFrom.ConfigMapKeyRef.Name, ns)
		if err != nil {
			return corev1.EnvVar{}, err
		}
		if strings.HasPrefix(data[env.ValueFrom.ConfigMapKeyRef.Key], "vault:") {
			fromCM := corev1.EnvVar{
				Name:  env.Name,
				Value: data[env.ValueFrom.ConfigMapKeyRef.Key],
			}
			return fromCM, nil
		}
	}
	if env.ValueFrom.SecretKeyRef != nil {
		data, err := getDataFromSecret(env.ValueFrom.SecretKeyRef.Name, ns)
		if err != nil {
			return corev1.EnvVar{}, err
		}
		fmt.Println(string(data[env.ValueFrom.SecretKeyRef.Key]))
		if strings.HasPrefix(string(data[env.ValueFrom.SecretKeyRef.Key]), "vault:") {
			fromSecret := corev1.EnvVar{
				Name:  env.Name,
				Value: string(data[env.ValueFrom.SecretKeyRef.Key]),
			}
			return fromSecret, nil
		}
	}
	return corev1.EnvVar{}, nil
}

func mutateContainers(containers []corev1.Container, vaultConfig vaultConfig, ns string) bool {
	mutated := false
	for i, container := range containers {
		var envVars []corev1.EnvVar
		if len(container.EnvFrom) > 0 {
			envFrom := lookForEnvFrom(container.EnvFrom, ns)
			envVars = append(envVars, envFrom...)
		}

		for _, env := range container.Env {
			if strings.HasPrefix(env.Value, "vault:") {
				envVars = append(envVars, env)
			}
			if env.ValueFrom != nil {
				valueFrom, err := lookForValueFrom(env, ns)
				if err != nil {
					continue
				}
				envVars = append(envVars, valueFrom)
			}
		}
		if len(envVars) == 0 {
			continue
		}

		mutated = true

		args := append(container.Command, container.Args...)

		container.Command = []string{"/vault/vault-env"}
		container.Args = args

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "vault-env",
				MountPath: "/vault/",
			},
		}...)

		container.Env = append(container.Env, []corev1.EnvVar{
			{
				Name:  "VAULT_ADDR",
				Value: vaultConfig.addr,
			},
			{
				Name:  "VAULT_SKIP_VERIFY",
				Value: vaultConfig.skipVerify,
			},
			{
				Name:  "VAULT_PATH",
				Value: vaultConfig.path,
			},
			{
				Name:  "VAULT_ROLE",
				Value: vaultConfig.role,
			},
		}...)

		if vaultConfig.useAgent {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "VAULT_TOKEN_FILE",
				Value: "/vault/token",
			})
		}

		containers[i] = container
	}

	return mutated
}
func newClientSet() (*kubernetes.Clientset, error) {
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

func mutatePodSpec(obj metav1.Object, podSpec *corev1.PodSpec, vaultConfig vaultConfig, ns string) error {

	clientset, err := newClientSet()
	if err != nil {
		return err
	}

	initContainersMutated := mutateContainers(podSpec.InitContainers, vaultConfig, ns)
	containersMutated := mutateContainers(podSpec.Containers, vaultConfig, ns)

	if initContainersMutated || containersMutated {

		if vaultConfig.useAgent {

			configMap := getConfigMapForVaultAgent(obj, vaultConfig)

			_, err := clientset.CoreV1().ConfigMaps(obj.GetNamespace()).Create(configMap)
			if err != nil {
				if errors.IsAlreadyExists(err) {
					_, err = clientset.CoreV1().ConfigMaps(obj.GetNamespace()).Update(configMap)
					if err != nil {
						return err
					}
				} else {
					return err
				}
			}
		}

		podSpec.InitContainers = append(getInitContainers(vaultConfig), podSpec.InitContainers...)
		podSpec.Volumes = append(podSpec.Volumes, getVolumes(obj.GetName(), vaultConfig)...)
	}

	return nil
}

func initConfig() {
	viper.SetDefault("vault_image", "vault:latest")
	viper.SetDefault("vault_env_image", "banzaicloud/vault-env:latest")
	viper.AutomaticEnv()
}

func handlerFor(config mutating.WebhookConfig, mutator mutating.MutatorFunc, logger log.Logger) http.Handler {
	webhook, err := mutating.NewWebhook(config, mutator, nil, nil, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating webhook: %s", err)
		os.Exit(1)
	}

	handler, err := whhttp.HandlerFor(webhook)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating webhook: %s", err)
		os.Exit(1)
	}

	return handler
}

func main() {

	initConfig()

	logger := &log.Std{Debug: viper.GetBool("debug")}

	mutator := mutating.MutatorFunc(vaultSecretsMutator)

	podHandler := handlerFor(mutating.WebhookConfig{Name: "vault-secrets-pods", Obj: &corev1.Pod{}}, mutator, logger)

	mux := http.NewServeMux()
	mux.Handle("/pods", podHandler)

	logger.Infof("Listening on :443")
	err := http.ListenAndServeTLS(":443", viper.GetString("tls_cert_file"), viper.GetString("tls_private_key_file"), mux)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error serving webhook: %s", err)
		os.Exit(1)
	}
}
