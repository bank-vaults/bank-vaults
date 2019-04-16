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
	metaVer "k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type vaultConfig struct {
	addr       string
	role       string
	path       string
	skipVerify string
	tlsConfigMap string
	useAgent   bool
	ctConfigMap string
	ctShareProcess bool
}

var vaultAgentConfig = `
pid_file = "./pidfile"
exit_after_auth = true

auto_auth {
	method "kubernetes" {
		mount_path = "auth/%s"
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

func getInitContainers(originalContainers []corev1.Container, vaultConfig vaultConfig, initContainersMutated bool, containersMutated bool, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}

	if vaultConfig.useAgent || vaultConfig.ctConfigMap != "" {

		var serviceAccountMount corev1.VolumeMount

	mountSearch:
		for _, container := range originalContainers {
			for _, mount := range container.VolumeMounts {
				if mount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
					serviceAccountMount = mount
					break mountSearch
				}
			}
		}

		containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
			Name:      "vault-agent-config",
			MountPath: "/vault/agent/",
		})

		containers = append(containers, corev1.Container{
			Name:            "vault-agent",
			Image:           viper.GetString("vault_image"),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"vault", "agent", "-config=/vault/agent/config.hcl"},
			Env: containerEnvVars,
			VolumeMounts: containerVolMounts,
		})
	}

	if initContainersMutated || containersMutated {
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
	}

	return containers
}

func getContainers(vaultConfig vaultConfig, versionCompared int, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	containers := []corev1.Container{}
	securityContext := &corev1.SecurityContext{}

	if versionCompared >= 0 || vaultConfig.ctShareProcess {
		securityContext = &corev1.SecurityContext{
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{
					"SYS_PTRACE",
				},
			},
		}
	}

	containerEnvVars = append(containerEnvVars, corev1.EnvVar{
		Name:  "HOME",
		Value: "/vault/",
	})

	containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
			Name:		"ct-secrets",
			MountPath:	"/vault/secrets",
		}, corev1.VolumeMount{
			Name:		"ct-configmap",
			MountPath:	"/vault/ct-config/config.hcl",
			ReadOnly:	true,
			SubPath:	"config.hcl",
		},
	)

	containers = append(containers, corev1.Container{
		Name:			"consul-template",
		Image:			viper.GetString("vault_ct_image"),
		Args: 			[]string{"-config","/vault/ct-config/config.hcl"},
		ImagePullPolicy: corev1.PullIfNotPresent,
		SecurityContext: securityContext,
		Env: containerEnvVars,
		VolumeMounts: containerVolMounts,
	})

	return containers
}

func getVolumes(agentConfigMapName string, vaultConfig vaultConfig, logger log.Logger) []corev1.Volume {
	logger.Infof("Add generic volumes to podspec")

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

	if vaultConfig.useAgent || vaultConfig.ctConfigMap != "" {
		logger.Infof("Add vault agent volumes to podspec")
		volumes = append(volumes, corev1.Volume{
			Name: "vault-agent-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: agentConfigMapName,
					},
				},
			},
		})
	}

	if vaultConfig.tlsConfigMap != "" {
		logger.Infof("Add vault TLS volume to podspec")
		volumes = append(volumes, corev1.Volume{
			Name: "vault-tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: vaultConfig.tlsConfigMap,
				},
			},
		})
	}
	if vaultConfig.ctConfigMap != "" {
		logger.Infof("Add consul template volumes to podspec")

		defaultMode := int32(420)
		volumes = append(volumes,
			corev1.Volume{
				Name: "ct-secrets",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			},
			corev1.Volume{
				Name: "ct-configmap",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vaultConfig.ctConfigMap,
						},
						DefaultMode: &defaultMode,
						Items: []corev1.KeyToPath{
							{
								Key:  "config.hcl",
								Path: "config.hcl",
							},
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

	return false, mutatePodSpec(obj, podSpec, vaultConfig, whcontext.GetAdmissionRequest(ctx).Namespace, whcontext.GetAdmissionRequest(ctx).Name)
}

func parseVaultConfig(obj metav1.Object) vaultConfig {
	var vaultConfig vaultConfig
	annotations := obj.GetAnnotations()

	if val, ok := annotations["vault.security.banzaicloud.io/vault-addr"]; ok {
		vaultConfig.addr = val
	} else {
		vaultConfig.addr = viper.GetString("vault_addr")
	}

	vaultConfig.role = annotations["vault.security.banzaicloud.io/vault-role"]
	if vaultConfig.role == "" {
		vaultConfig.role = "default"
	}

	vaultConfig.path = annotations["vault.security.banzaicloud.io/vault-path"]
	if vaultConfig.path == "" {
		vaultConfig.path = "kubernetes"
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-skip-verify"]; ok {
		vaultConfig.skipVerify = val
	} else {
		vaultConfig.skipVerify = viper.GetString("vault_skip_verify")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-tls-configmap"]; ok {
		vaultConfig.tlsConfigMap = val
	} else {
		vaultConfig.tlsConfigMap = viper.GetString("vault_tls_configmap")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-agent"]; ok {
		vaultConfig.useAgent, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.useAgent,_  = strconv.ParseBool(viper.GetString("vault_agent"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/ct-configmap"]; ok {
		vaultConfig.ctConfigMap = val
	} else {
		vaultConfig.ctConfigMap = ""
	}

	if val, ok := annotations["vault.security.banzaicloud.io/ct-share-process-namespace"]; ok {
		vaultConfig.ctShareProcess, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.ctShareProcess, _ = strconv.ParseBool(viper.GetString("vault_ct_share_process_namespace"))
	}

	return vaultConfig
}

func getConfigMapForVaultAgent(obj metav1.Object, vaultConfig vaultConfig) *corev1.ConfigMap {
	var ownerReferences []metav1.OwnerReference
	name := obj.GetName()
	if name == "" {
		ownerReferences = obj.GetOwnerReferences()
		if len(ownerReferences) > 0 {
			generateNameSlice := strings.Split(ownerReferences[0].Name, "-")
			name = strings.Join(generateNameSlice[:len(generateNameSlice)-1], "-")
		}
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name + "-vault-agent-config",
			OwnerReferences: ownerReferences,
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

func lookForEnvFrom(envFrom []corev1.EnvFromSource, ns string) ([]corev1.EnvVar, error) {
	var envVars []corev1.EnvVar

	for _, ef := range envFrom {
		if ef.ConfigMapRef != nil {
			data, err := getDataFromConfigmap(ef.ConfigMapRef.Name, ns)
			if err != nil {
				return envVars, err
			}
			for key, value := range data {
				if strings.HasPrefix(value, "vault:") || strings.HasPrefix(value, ">>vault:") {
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
				return envVars, err
			}
			for key, value := range data {
				if strings.HasPrefix(string(value), "vault:") || strings.HasPrefix(string(value), ">>vault:") {
					envFromSec := corev1.EnvVar{
						Name:  key,
						Value: string(value),
					}
					envVars = append(envVars, envFromSec)
				}
			}
		}
	}
	return envVars, nil
}

func lookForValueFrom(env corev1.EnvVar, ns string) (*corev1.EnvVar, error) {
	if env.ValueFrom.ConfigMapKeyRef != nil {
		data, err := getDataFromConfigmap(env.ValueFrom.ConfigMapKeyRef.Name, ns)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(data[env.ValueFrom.ConfigMapKeyRef.Key], "vault:") {
			fromCM := corev1.EnvVar{
				Name:  env.Name,
				Value: data[env.ValueFrom.ConfigMapKeyRef.Key],
			}
			return &fromCM, nil
		}
	}
	if env.ValueFrom.SecretKeyRef != nil {
		data, err := getDataFromSecret(env.ValueFrom.SecretKeyRef.Name, ns)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(string(data[env.ValueFrom.SecretKeyRef.Key]), "vault:") {
			fromSecret := corev1.EnvVar{
				Name:  env.Name,
				Value: string(data[env.ValueFrom.SecretKeyRef.Key]),
			}
			return &fromSecret, nil
		}
	}
	return nil, nil
}

func mutateContainers(containers []corev1.Container, vaultConfig vaultConfig, ns string) (bool, error) {
	mutated := false

	for i, container := range containers {
		var envVars []corev1.EnvVar
		if len(container.EnvFrom) > 0 {
			envFrom, err := lookForEnvFrom(container.EnvFrom, ns)
			if err != nil {
				return false, err
			}
			envVars = append(envVars, envFrom...)
					}

		for _, env := range container.Env {
			if strings.HasPrefix(env.Value, "vault:") {
				envVars = append(envVars, env)
			}
			if env.ValueFrom != nil {
				valueFrom, err := lookForValueFrom(env, ns)
				if err != nil {
					return false, err
				}
				if valueFrom == nil {
					continue
				}
				envVars = append(envVars, *valueFrom)
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

	return mutated, nil
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

func mutatePodSpec(obj metav1.Object, podSpec *corev1.PodSpec, vaultConfig vaultConfig, ns string, name string) error {

	logger := &log.Std{Debug: viper.GetBool("debug")}

	clientset, err := newClientSet()
	if err != nil {
		return err
	}

	logger.Infof("Successfully connected to the API")

	initContainersMutated, err := mutateContainers(podSpec.InitContainers, vaultConfig, ns)
	if err != nil {
		return err
	}

	if initContainersMutated {
		logger.Infof("Successfully mutated pod init containers")
	} else {
		logger.Infof("No pod init containers were mutated")
	}

	containersMutated, err := mutateContainers(podSpec.Containers, vaultConfig, ns)
	if err != nil {
		return err
	}

	if containersMutated {
		logger.Infof("Successfully mutated pod containers")
	} else {
		logger.Infof("No pod containers were mutated")
	}

	containerEnvVars := []corev1.EnvVar{
		{
			Name:  "VAULT_ADDR",
			Value: vaultConfig.addr,
		},
		{
			Name:  "VAULT_SKIP_VERIFY",
			Value: vaultConfig.skipVerify,
		},
	}
	containerVolMounts := []corev1.VolumeMount{
		{
			Name:      "vault-env",
			MountPath: "/vault/",
		},
	}
    if vaultConfig.tlsConfigMap != "" {
		containerEnvVars = append(containerEnvVars, corev1.EnvVar{
				Name:  "VAULT_CACERT",
				Value: "/vault/tls/ca.crt",
		})
		containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
				Name:      "vault-tls",
				MountPath: "/vault/tls",
		})
	}

	var agentConfigMapName string
	if initContainersMutated || containersMutated || vaultConfig.ctConfigMap != "" {
		if vaultConfig.useAgent || vaultConfig.ctConfigMap != "" {
			configMap := getConfigMapForVaultAgent(obj, vaultConfig)
			agentConfigMapName = configMap.Name

			_, err := clientset.CoreV1().ConfigMaps(ns).Create(configMap)
			if err != nil {
				if errors.IsAlreadyExists(err) {
					_, err = clientset.CoreV1().ConfigMaps(ns).Update(configMap)
					if err != nil {
						return err
					}
				} else {
					return err
				}
			}
		}

		podSpec.InitContainers = append(getInitContainers(podSpec.Containers, vaultConfig, initContainersMutated, containersMutated, containerEnvVars, containerVolMounts), podSpec.InitContainers...)
		logger.Infof("Successfully appended pod init containers to spec")
	}

	if vaultConfig.ctConfigMap != "" {
		logger.Infof("Consul template config found")

		apiVersion, _ := clientset.Discovery().ServerVersion()
		versionCompared := metaVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
		logger.Infof("Kuberentes API version detected: %s", apiVersion.String())
		if versionCompared >= 0 || vaultConfig.ctShareProcess {
			logger.Infof("Detected shared process namespace")
			sharePorcessNamespace := true
			podSpec.ShareProcessNamespace = &sharePorcessNamespace
		}
		podSpec.Containers = append(getContainers(vaultConfig, versionCompared, containerEnvVars, containerVolMounts), podSpec.Containers...)

		fsGroup := int64(1000)
		podSpec.SecurityContext.FSGroup = &fsGroup

		logger.Infof("Successfully appended pod containers to spec")
	}

	if initContainersMutated || containersMutated || vaultConfig.ctConfigMap != "" {
		podSpec.Volumes = append(podSpec.Volumes, getVolumes(agentConfigMapName, vaultConfig, logger)...)
		logger.Infof("Successfully appended pod spec volumes")
	}

	return nil
}

func initConfig() {
	viper.SetDefault("vault_image", "vault:latest")
	viper.SetDefault("vault_env_image", "banzaicloud/vault-env:latest")
	viper.SetDefault("vault_ct_image", "hashicorp/consul-template:latest")
	viper.SetDefault("vault_addr", "https://127.0.0.1:8200")
	viper.SetDefault("vault_skip_verify", "false")
	viper.SetDefault("vault_tls_configmap", "")
	viper.SetDefault("vault_agent", "true")
	viper.SetDefault("vault_ct_share_process_namespace", "false")
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

	logger.Infof("Listening on :8443")
	err := http.ListenAndServeTLS(":8443", viper.GetString("tls_cert_file"), viper.GetString("tls_private_key_file"), mux)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error serving webhook: %s", err)
		os.Exit(1)
	}
}
