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
	"context"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeVer "k8s.io/apimachinery/pkg/version"
)

const vaultAgentConfig = `
pid_file = "/tmp/pidfile"

auto_auth {
	method "kubernetes" {
		mount_path = "auth/%s"
		config = {
			role = "%s"
		}
	}

	sink "file" {
		config = {
			path = "/vault/.vault-token"
		}
	}
}`

func (mw *mutatingWebhook) mutatePod(ctx context.Context, pod *corev1.Pod, vaultConfig VaultConfig, ns string, dryRun bool) error {
	mw.logger.Debug("Successfully connected to the API")

	initContainersMutated, err := mw.mutateContainers(ctx, pod.Spec.InitContainers, &pod.Spec, vaultConfig, ns)
	if err != nil {
		return err
	}

	if initContainersMutated {
		mw.logger.Debug("Successfully mutated pod init containers")
	} else {
		mw.logger.Debug("No pod init containers were mutated")
	}

	containersMutated, err := mw.mutateContainers(ctx, pod.Spec.Containers, &pod.Spec, vaultConfig, ns)
	if err != nil {
		return err
	}

	if containersMutated {
		mw.logger.Debug("Successfully mutated pod containers")
	} else {
		mw.logger.Debug("No pod containers were mutated")
	}

	containerEnvVars := []corev1.EnvVar{
		{
			Name:  "VAULT_ADDR",
			Value: vaultConfig.Addr,
		},
		{
			Name:  "VAULT_SKIP_VERIFY",
			Value: strconv.FormatBool(vaultConfig.SkipVerify),
		},
	}
	containerVolMounts := []corev1.VolumeMount{
		{
			Name:      "vault-env",
			MountPath: "/vault/",
		},
	}
	if vaultConfig.TLSSecret != "" {
		mountPath := "/vault/tls/"
		volumeName := "vault-tls"
		if hasTLSVolume(pod.Spec.Volumes) {
			mountPath = "/vault-env/tls/"
			volumeName = "vault-env-tls"
		}

		containerEnvVars = append(containerEnvVars, corev1.EnvVar{
			Name:  "VAULT_CACERT",
			Value: mountPath + "ca.crt",
		})
		containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
			Name:      volumeName,
			MountPath: mountPath,
		})
	}

	if initContainersMutated || containersMutated || vaultConfig.CtConfigMap != "" || vaultConfig.AgentConfigMap != "" {
		var agentConfigMapName string

		if vaultConfig.UseAgent || vaultConfig.CtConfigMap != "" {
			if vaultConfig.AgentConfigMap != "" {
				agentConfigMapName = vaultConfig.AgentConfigMap
			} else {
				configMap := getConfigMapForVaultAgent(pod, vaultConfig)
				agentConfigMapName = configMap.Name
				if !dryRun {
					_, err := mw.k8sClient.CoreV1().ConfigMaps(ns).Create(context.Background(), configMap, metav1.CreateOptions{})
					if err != nil {
						if errors.IsAlreadyExists(err) {
							_, err = mw.k8sClient.CoreV1().ConfigMaps(ns).Update(context.Background(), configMap, metav1.UpdateOptions{})
							if err != nil {
								return err
							}
						} else {
							return err
						}
					}
				}
			}
		}

		pod.Spec.InitContainers = append(getInitContainers(pod.Spec.Containers, pod.Spec.SecurityContext, vaultConfig, initContainersMutated, containersMutated, containerEnvVars, containerVolMounts), pod.Spec.InitContainers...)
		mw.logger.Debug("Successfully appended pod init containers to spec")

		pod.Spec.Volumes = append(pod.Spec.Volumes, mw.getVolumes(pod.Spec.Volumes, agentConfigMapName, vaultConfig)...)
		mw.logger.Debug("Successfully appended pod spec volumes")
	}

	if vaultConfig.CtConfigMap != "" {
		mw.logger.Debug("Consul Template config found")

		mw.addSecretsVolToContainers(vaultConfig, pod.Spec.Containers)

		if vaultConfig.CtShareProcessDefault == "empty" {
			mw.logger.Debugf("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := mw.k8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			mw.logger.Debugf("Kubernetes API version detected: %s", apiVersion.String())

			if versionCompared >= 0 {
				vaultConfig.CtShareProcess = true
			} else {
				vaultConfig.CtShareProcess = false
			}
		}

		if vaultConfig.CtShareProcess {
			mw.logger.Debugf("Detected shared process namespace")
			shareProcessNamespace := true
			pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}
		pod.Spec.Containers = append(getContainers(vaultConfig, containerEnvVars, containerVolMounts), pod.Spec.Containers...)

		mw.logger.Debug("Successfully appended pod containers to spec")
	}

	if vaultConfig.AgentConfigMap != "" && !vaultConfig.UseAgent {
		mw.logger.Debug("Vault Agent config found")

		mw.addAgentSecretsVolToContainers(vaultConfig, pod.Spec.Containers)

		if vaultConfig.AgentShareProcessDefault == "empty" {
			mw.logger.Debug("Test our Kubernetes API Version and make the final decision on enabling ShareProcessNamespace")
			apiVersion, _ := mw.k8sClient.Discovery().ServerVersion()
			versionCompared := kubeVer.CompareKubeAwareVersionStrings("v1.12.0", apiVersion.String())
			mw.logger.Debugf("Kubernetes API version detected: %s", apiVersion.String())

			if versionCompared >= 0 {
				vaultConfig.AgentShareProcess = true
			} else {
				vaultConfig.AgentShareProcess = false
			}
		}

		if vaultConfig.AgentShareProcess {
			mw.logger.Debug("Detected shared process namespace")
			shareProcessNamespace := true
			pod.Spec.ShareProcessNamespace = &shareProcessNamespace
		}
		pod.Spec.Containers = append(getAgentContainers(pod.Spec.Containers, vaultConfig, containerEnvVars, containerVolMounts), pod.Spec.Containers...)

		mw.logger.Debug("Successfully appended pod containers to spec")
	}

	return nil
}

func (mw *mutatingWebhook) mutateContainers(ctx context.Context, containers []corev1.Container, podSpec *corev1.PodSpec, vaultConfig VaultConfig, ns string) (bool, error) {
	mutated := false

	for i, container := range containers {
		var envVars []corev1.EnvVar
		if len(container.EnvFrom) > 0 {
			envFrom, err := mw.lookForEnvFrom(container.EnvFrom, ns)
			if err != nil {
				return false, err
			}
			envVars = append(envVars, envFrom...)
		}

		for _, env := range container.Env {
			if hasVaultPrefix(env.Value) {
				envVars = append(envVars, env)
			}
			if hasInlineVaultDelimiters(env.Value) {
				envVars = append(envVars, env)
			}
			if env.ValueFrom != nil {
				valueFrom, err := mw.lookForValueFrom(env, ns)
				if err != nil {
					return false, err
				}
				if valueFrom == nil {
					continue
				}
				envVars = append(envVars, *valueFrom)
			}
		}

		if len(envVars) == 0 && vaultConfig.VaultEnvFromPath == "" {
			continue
		}

		mutated = true

		args := container.Command

		// the container has no explicitly specified command
		if len(args) == 0 {
			imageConfig, err := mw.registry.GetImageConfig(ctx, mw.k8sClient, ns, &container, podSpec) // nolint:gosec
			if err != nil {
				return false, err
			}

			args = append(args, imageConfig.Entrypoint...)

			// If no Args are defined we can use the Docker CMD from the image
			// https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/#notes
			if len(container.Args) == 0 {
				args = append(args, imageConfig.Cmd...)
			}
		}

		args = append(args, container.Args...)

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
				Value: vaultConfig.Addr,
			},
			{
				Name:  "VAULT_SKIP_VERIFY",
				Value: strconv.FormatBool(vaultConfig.SkipVerify),
			},
			{
				Name:  "VAULT_AUTH_METHOD",
				Value: vaultConfig.AuthMethod,
			},
			{
				Name:  "VAULT_PATH",
				Value: vaultConfig.Path,
			},
			{
				Name:  "VAULT_ROLE",
				Value: vaultConfig.Role,
			},
			{
				Name:  "VAULT_IGNORE_MISSING_SECRETS",
				Value: vaultConfig.IgnoreMissingSecrets,
			},
			{
				Name:  "VAULT_ENV_PASSTHROUGH",
				Value: vaultConfig.VaultEnvPassThrough,
			},
			{
				Name:  "VAULT_JSON_LOG",
				Value: vaultConfig.EnableJSONLog,
			},
			{
				Name:  "VAULT_CLIENT_TIMEOUT",
				Value: vaultConfig.ClientTimeout.String(),
			},
		}...)

		if vaultConfig.LogLevel != "" {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "VAULT_LOG_LEVEL",
					Value: vaultConfig.LogLevel,
				},
			}...)
		}

		if len(vaultConfig.TransitKeyID) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "VAULT_TRANSIT_KEY_ID",
					Value: vaultConfig.TransitKeyID,
				},
			}...)
		}

		if len(vaultConfig.TransitPath) > 0 {
			container.Env = append(container.Env, []corev1.EnvVar{
				{
					Name:  "VAULT_TRANSIT_PATH",
					Value: vaultConfig.TransitPath,
				},
			}...)
		}

		if vaultConfig.TLSSecret != "" {
			mountPath := "/vault/tls/"
			volumeName := "vault-tls"
			if hasTLSVolume(podSpec.Volumes) {
				mountPath = "/vault-env/tls/"
				volumeName = "vault-env-tls"
			}

			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "VAULT_CACERT",
				Value: mountPath + "ca.crt",
			})
			container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
				Name:      volumeName,
				MountPath: mountPath,
			})
		}

		if vaultConfig.UseAgent || vaultConfig.TokenAuthMount != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "VAULT_TOKEN_FILE",
				Value: "/vault/.vault-token",
			})
		}

		if vaultConfig.VaultEnvDaemon {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "VAULT_ENV_DAEMON",
				Value: "true",
			})
		}

		if vaultConfig.VaultEnvFromPath != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "VAULT_ENV_FROM_PATH",
				Value: vaultConfig.VaultEnvFromPath,
			})
		}

		containers[i] = container
	}

	return mutated, nil
}

func (mw *mutatingWebhook) addSecretsVolToContainers(vaultConfig VaultConfig, containers []corev1.Container) {
	for i, container := range containers {
		mw.logger.Debugf("Add secrets VolumeMount to container %s", container.Name)

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "ct-secrets",
				MountPath: vaultConfig.ConfigfilePath,
			},
		}...)

		containers[i] = container
	}
}

func (mw *mutatingWebhook) addAgentSecretsVolToContainers(vaultConfig VaultConfig, containers []corev1.Container) {
	for i, container := range containers {
		mw.logger.Debugf("Add secrets VolumeMount to container %s", container.Name)

		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "agent-secrets",
				MountPath: vaultConfig.ConfigfilePath,
			},
		}...)

		containers[i] = container
	}
}

func (mw *mutatingWebhook) getVolumes(existingVolumes []corev1.Volume, agentConfigMapName string, vaultConfig VaultConfig) []corev1.Volume {
	mw.logger.Debug("Add generic volumes to podspec")

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

	if vaultConfig.UseAgent || vaultConfig.CtConfigMap != "" {
		mw.logger.Debug("Add vault agent volumes to podspec")
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

	if vaultConfig.TLSSecret != "" {
		mw.logger.Debug("Add vault TLS volume to podspec")

		volumeName := "vault-tls"
		if hasTLSVolume(existingVolumes) {
			volumeName = "vault-env-tls"
		}

		volumes = append(volumes, corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: vaultConfig.TLSSecret,
							},
							Items: []corev1.KeyToPath{{
								Key:  "ca.crt",
								Path: "ca.crt",
							}},
						},
					}},
				},
			},
		})
	}
	if vaultConfig.CtConfigMap != "" {
		mw.logger.Debug("Add consul template volumes to podspec")

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
							Name: vaultConfig.CtConfigMap,
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

	if vaultConfig.AgentConfigMap != "" {
		mw.logger.Debug("Add vault-agent volumes to podspec")

		defaultMode := int32(420)
		volumes = append(volumes,
			corev1.Volume{
				Name: "agent-secrets",
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumMemory,
					},
				},
			},
			corev1.Volume{
				Name: "agent-configmap",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: vaultConfig.AgentConfigMap,
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

// If the original Pod contained a Volume "vault-tls", for example Vault instances provisioned by the Operator
// we need to handle that edge case and choose another name for the vault-tls volume for accessing Vault with TLS.
func hasTLSVolume(volumes []corev1.Volume) bool {
	for _, volume := range volumes {
		if volume.Name == "vault-tls" {
			return true
		}
	}
	return false
}

func hasPodSecurityContextRunAsUser(p *corev1.PodSecurityContext) bool {
	return p.RunAsUser != nil
}

func getServiceAccountMount(containers []corev1.Container) (serviceAccountMount corev1.VolumeMount) {
mountSearch:
	for _, container := range containers {
		for _, mount := range container.VolumeMounts {
			if mount.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {
				serviceAccountMount = mount
				break mountSearch
			}
		}
	}
	return serviceAccountMount
}

func getInitContainers(originalContainers []corev1.Container, podSecurityContext *corev1.PodSecurityContext, vaultConfig VaultConfig, initContainersMutated bool, containersMutated bool, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	var containers = []corev1.Container{}

	if vaultConfig.TokenAuthMount != "" {
		// vault.security.banzaicloud.io/token-auth-mount: "token:vault-token"
		split := strings.Split(vaultConfig.TokenAuthMount, ":")
		mountName := split[0]
		tokenName := split[1]
		fileLoc := "/token/" + tokenName
		cmd := fmt.Sprintf("cp %s /vault/.vault-token", fileLoc)

		containers = append(containers, corev1.Container{
			Name:            "copy-vault-token",
			Image:           vaultConfig.AgentImage,
			ImagePullPolicy: vaultConfig.AgentImagePullPolicy,
			Command:         []string{"sh", "-c", cmd},
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "vault-env",
					MountPath: "/vault/",
				},
				{
					Name:      mountName,
					MountPath: "/token",
				},
			},
		})
	} else if vaultConfig.UseAgent || vaultConfig.CtConfigMap != "" {
		serviceAccountMount := getServiceAccountMount(originalContainers)

		containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
			Name:      "vault-agent-config",
			MountPath: "/vault/agent/",
		})

		runAsUser := int64(100)
		securityContext := &corev1.SecurityContext{
			RunAsUser:                &runAsUser,
			AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
		}

		containers = append(containers, corev1.Container{
			Name:            "vault-agent",
			Image:           vaultConfig.AgentImage,
			ImagePullPolicy: vaultConfig.AgentImagePullPolicy,
			SecurityContext: securityContext,
			Command:         []string{"vault", "agent", "-config=/vault/agent/config.hcl", "-exit-after-auth"},
			Env:             containerEnvVars,
			VolumeMounts:    containerVolMounts,
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("250m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			},
		})
	}

	if initContainersMutated || containersMutated {
		containers = append(containers, corev1.Container{
			Name:            "copy-vault-env",
			Image:           vaultConfig.EnvImage,
			ImagePullPolicy: vaultConfig.EnvImagePullPolicy,
			Command:         []string{"sh", "-c", "cp /usr/local/bin/vault-env /vault/"},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "vault-env",
					MountPath: "/vault/",
				},
			},

			SecurityContext: getSecurityContext(podSecurityContext, vaultConfig),
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("250m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			},
		})
	}

	return containers
}

func getContainers(vaultConfig VaultConfig, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	var containers = []corev1.Container{}
	securityContext := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
	}

	if vaultConfig.CtShareProcess {
		securityContext = &corev1.SecurityContext{
			AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{
					"SYS_PTRACE",
				},
			},
		}
	}

	containerVolMounts = append(containerVolMounts, corev1.VolumeMount{
		Name:      "ct-secrets",
		MountPath: "/vault/secrets",
	}, corev1.VolumeMount{
		Name:      "vault-env",
		MountPath: "/home/consul-template",
	}, corev1.VolumeMount{
		Name:      "ct-configmap",
		MountPath: "/vault/ct-config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	},
	)

	var ctCommandString []string
	if vaultConfig.CtOnce {
		ctCommandString = []string{"-config", "/vault/ct-config/config.hcl", "-once"}
	} else {
		ctCommandString = []string{"-config", "/vault/ct-config/config.hcl"}
	}

	containers = append(containers, corev1.Container{
		Name:            "consul-template",
		Image:           vaultConfig.CtImage,
		Args:            ctCommandString,
		ImagePullPolicy: vaultConfig.CtImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    vaultConfig.CtCPU,
				corev1.ResourceMemory: vaultConfig.CtMemory,
			},
		},
	})

	return containers
}

func getAgentContainers(originalContainers []corev1.Container, vaultConfig VaultConfig, containerEnvVars []corev1.EnvVar, containerVolMounts []corev1.VolumeMount) []corev1.Container {
	var containers = []corev1.Container{}
	securityContext := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
		Capabilities: &corev1.Capabilities{
			Add: []corev1.Capability{
				"IPC_LOCK",
			},
		},
	}

	if vaultConfig.AgentShareProcess {
		securityContext = &corev1.SecurityContext{
			AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{
					"SYS_PTRACE",
					"IPC_LOCK",
				},
			},
		}
	}

	serviceAccountMount := getServiceAccountMount(originalContainers)

	containerVolMounts = append(containerVolMounts, serviceAccountMount, corev1.VolumeMount{
		Name:      "agent-secrets",
		MountPath: "/vault/secrets",
	}, corev1.VolumeMount{
		Name:      "agent-configmap",
		MountPath: "/vault/config/config.hcl",
		ReadOnly:  true,
		SubPath:   "config.hcl",
	},
	)

	var agentCommandString []string
	if vaultConfig.AgentOnce {
		agentCommandString = []string{"agent", "-config", "/vault/config/config.hcl", "-exit-after-auth"}
	} else {
		agentCommandString = []string{"agent", "-config", "/vault/config/config.hcl"}
	}

	containers = append(containers, corev1.Container{
		Name:            "vault-agent",
		Image:           vaultConfig.AgentImage,
		Args:            agentCommandString,
		ImagePullPolicy: vaultConfig.AgentImagePullPolicy,
		SecurityContext: securityContext,
		Env:             containerEnvVars,
		VolumeMounts:    containerVolMounts,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    vaultConfig.AgentCPU,
				corev1.ResourceMemory: vaultConfig.AgentMemory,
			},
		},
	})

	return containers
}

func getSecurityContext(podSecurityContext *corev1.PodSecurityContext, vaultConfig VaultConfig) *corev1.SecurityContext {
	if hasPodSecurityContextRunAsUser(podSecurityContext) {
		return &corev1.SecurityContext{
			RunAsUser:                podSecurityContext.RunAsUser,
			AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
		}
	}

	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
	}
}

func getConfigMapForVaultAgent(pod *corev1.Pod, vaultConfig VaultConfig) *corev1.ConfigMap {
	ownerReferences := pod.GetOwnerReferences()
	name := pod.GetName()
	// If we have no name we are probably part of some controller,
	// try to get the name of the owner controller.
	if name == "" {
		if len(ownerReferences) > 0 {
			if strings.Contains(ownerReferences[0].Name, "-") {
				generateNameSlice := strings.Split(ownerReferences[0].Name, "-")
				name = strings.Join(generateNameSlice[:len(generateNameSlice)-1], "-")
			} else {
				name = ownerReferences[0].Name
			}
		}
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name + "-vault-agent-config",
			OwnerReferences: ownerReferences,
		},
		Data: map[string]string{
			"config.hcl": fmt.Sprintf(vaultAgentConfig, vaultConfig.Path, vaultConfig.Role),
		},
	}
}
