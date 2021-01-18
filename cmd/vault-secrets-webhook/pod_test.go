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
	"testing"
	"time"

	cmp "github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	fake "k8s.io/client-go/kubernetes/fake"

	"github.com/banzaicloud/bank-vaults/cmd/vault-secrets-webhook/registry"
)

var vaultConfig = VaultConfig{
	Addr:                 "addr",
	SkipVerify:           false,
	Path:                 "path",
	Role:                 "role",
	AuthMethod:           "jwt",
	IgnoreMissingSecrets: "ignoreMissingSecrets",
	VaultEnvPassThrough:  "vaultEnvPassThrough",
	EnableJSONLog:        "enableJSONLog",
	ClientTimeout:        10 * time.Second,
}

type MockRegistry struct {
	Image v1.Config
}

func (r *MockRegistry) GetImageConfig(_ context.Context, _ kubernetes.Interface, _ string, _ *corev1.Container, _ *corev1.PodSpec) (*v1.Config, error) {
	return &r.Image, nil
}

func Test_mutatingWebhook_mutateContainers(t *testing.T) {
	vaultConfigEnvFrom := vaultConfig
	vaultConfigEnvFrom.VaultEnvFromPath = "secrets/application"

	type fields struct {
		k8sClient kubernetes.Interface
		registry  registry.ImageRegistry
	}
	type args struct {
		containers  []corev1.Container
		podSpec     *corev1.PodSpec
		vaultConfig VaultConfig
		ns          string
	}
	tests := []struct {
		name             string
		fields           fields
		args             args
		mutated          bool
		wantErr          bool
		wantedContainers []corev1.Container
	}{
		{name: "Will mutate container with command, no args",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: "vault:secrets",
							},
						},
					},
				},
				vaultConfig: vaultConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/vault/vault-env"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "vault-env", MountPath: "/vault/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_ENV_PASSTHROUGH", Value: "vaultEnvPassThrough"},
						{Name: "VAULT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{name: "Will mutate container with command, other syntax",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: ">>vault:secrets",
							},
						},
					},
				},
				vaultConfig: vaultConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/vault/vault-env"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "vault-env", MountPath: "/vault/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_ENV_PASSTHROUGH", Value: "vaultEnvPassThrough"},
						{Name: "VAULT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{name: "Will mutate container with args, no command",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{
						Entrypoint: []string{"myEntryPoint"},
					},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: ">>vault:secrets",
							},
						},
					},
				},
				vaultConfig: vaultConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/vault/vault-env"},
					Args:         []string{"myEntryPoint"},
					VolumeMounts: []corev1.VolumeMount{{Name: "vault-env", MountPath: "/vault/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_ENV_PASSTHROUGH", Value: "vaultEnvPassThrough"},
						{Name: "VAULT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{name: "Will mutate container with no container-command, no entrypoint",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{
						Cmd: []string{"myCmd"},
					},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: ">>vault:secrets",
							},
						},
					},
				},
				vaultConfig: vaultConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/vault/vault-env"},
					Args:         []string{"myCmd"},
					VolumeMounts: []corev1.VolumeMount{{Name: "vault-env", MountPath: "/vault/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_ENV_PASSTHROUGH", Value: "vaultEnvPassThrough"},
						{Name: "VAULT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{name: "Will not mutate container without secrets with correct prefix",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
					},
				},
				vaultConfig: vaultConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:    "MyContainer",
					Image:   "myimage",
					Command: []string{"/bin/bash"},
				},
			},
			mutated: false,
			wantErr: false,
		},
		{name: "Will mutate container with env-from-path annotation",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: "vault:secrets",
							},
						},
					},
				},
				vaultConfig: vaultConfigEnvFrom,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/vault/vault-env"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "vault-env", MountPath: "/vault/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_ENV_PASSTHROUGH", Value: "vaultEnvPassThrough"},
						{Name: "VAULT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
						{Name: "VAULT_ENV_FROM_PATH", Value: "secrets/application"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{name: "Will mutate container with command, no args, with inline mutation",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				containers: []corev1.Container{
					{
						Name:    "MyContainer",
						Image:   "myimage",
						Command: []string{"/bin/bash"},
						Args:    nil,
						Env: []corev1.EnvVar{
							{
								Name:  "myvar",
								Value: "scheme://${vault:secret/data/account#username}:${vault:secret/data/account#password}@127.0.0.1:8080",
							},
						},
					},
				},
				vaultConfig: vaultConfig,
			},
			wantedContainers: []corev1.Container{
				{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/vault/vault-env"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "vault-env", MountPath: "/vault/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "scheme://${vault:secret/data/account#username}:${vault:secret/data/account#password}@127.0.0.1:8080"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "false"},
						{Name: "VAULT_AUTH_METHOD", Value: "jwt"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_ENV_PASSTHROUGH", Value: "vaultEnvPassThrough"},
						{Name: "VAULT_JSON_LOG", Value: "enableJSONLog"},
						{Name: "VAULT_CLIENT_TIMEOUT", Value: "10s"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &mutatingWebhook{
				k8sClient: tt.fields.k8sClient,
				registry:  tt.fields.registry,
				logger:    logrus.NewEntry(logrus.New()),
			}
			got, err := mw.mutateContainers(context.Background(), tt.args.containers, tt.args.podSpec, tt.args.vaultConfig, tt.args.ns)
			if (err != nil) != tt.wantErr {
				t.Errorf("mutatingWebhook.mutateContainers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.mutated {
				t.Errorf("mutatingWebhook.mutateContainers() = %v, want %v", got, tt.mutated)
			}
			if !cmp.Equal(tt.args.containers, tt.wantedContainers) {
				t.Errorf("mutatingWebhook.mutateContainers() = diff %v", cmp.Diff(tt.args.containers, tt.wantedContainers))
			}
		})
	}
}

func Test_mutatingWebhook_mutatePod(t *testing.T) {
	type fields struct {
		k8sClient kubernetes.Interface
		registry  registry.ImageRegistry
	}
	type args struct {
		pod         *corev1.Pod
		vaultConfig VaultConfig
		ns          string
	}
	defaultMode := int32(420)
	runAsUser := int64(100)
	initContainerSecurityContext := &corev1.SecurityContext{
		RunAsUser:                &runAsUser,
		AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
	}

	tests := []struct {
		name      string
		fields    fields
		args      args
		wantErr   bool
		wantedPod *corev1.Pod
	}{
		{name: "Will mutate pod with ct-configmap annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "MyContainer",
								Image:   "myimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
									},
								},
							},
						},
					},
				},
				vaultConfig: VaultConfig{
					CtConfigMap:          "config-map-test",
					ConfigfilePath:       "/vault/secrets",
					Addr:                 "test",
					SkipVerify:           false,
					CtCPU:                resource.MustParse("50m"),
					CtMemory:             resource.MustParse("128Mi"),
					AgentImage:           "vault:latest",
					AgentImagePullPolicy: "IfNotPresent",
				},
			},
			wantedPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "vault-agent",
							Image:           "vault:latest",
							Command:         []string{"vault", "agent", "-config=/vault/agent/config.hcl", "-exit-after-auth"},
							ImagePullPolicy: "IfNotPresent",
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
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
							SecurityContext: initContainerSecurityContext,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "vault-env",
									MountPath: "/vault/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "vault-agent-config",
									MountPath: "/vault/agent/",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name: "consul-template",
							Args: []string{"-config", "/vault/ct-config/config.hcl"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "vault-env",
									MountPath: "/vault/",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
								{
									Name:      "vault-env",
									MountPath: "/home/consul-template",
								},
								{
									Name:      "ct-configmap",
									ReadOnly:  true,
									MountPath: "/vault/ct-config/config.hcl",
									SubPath:   "config.hcl",
								},
							},
						},
						{
							Name:    "MyContainer",
							Image:   "myimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "ct-secrets",
									MountPath: "/vault/secrets",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "vault-env",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "vault-agent-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "-vault-agent-config",
									},
								},
							},
						},
						{
							Name: "ct-secrets",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "ct-configmap",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "config-map-test",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "config.hcl",
											Path: "config.hcl",
										},
									},
									DefaultMode: &defaultMode,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{name: "Will mutate pod with agent-configmap annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:    "MyContainer",
								Image:   "myimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
									},
								},
							},
						},
					},
				},
				vaultConfig: VaultConfig{
					AgentConfigMap:       "config-map-test",
					ConfigfilePath:       "/vault/secrets",
					Addr:                 "test",
					SkipVerify:           false,
					AgentCPU:             resource.MustParse("50m"),
					AgentMemory:          resource.MustParse("128Mi"),
					AgentImage:           "vault:latest",
					AgentImagePullPolicy: "IfNotPresent",
				},
			},
			wantedPod: &corev1.Pod{
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{},
					Containers: []corev1.Container{
						{
							Name:            "vault-agent",
							Image:           "vault:latest",
							ImagePullPolicy: "IfNotPresent",
							Args:            []string{"agent", "-config", "/vault/config/config.hcl"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "VAULT_ADDR",
									Value: "test",
								},
								{
									Name:  "VAULT_SKIP_VERIFY",
									Value: "false",
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &vaultConfig.PspAllowPrivilegeEscalation,
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{
										"IPC_LOCK",
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "vault-env",
									MountPath: "/vault/",
								},
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "agent-secrets",
									MountPath: "/vault/secrets",
								},
								{
									Name:      "agent-configmap",
									ReadOnly:  true,
									MountPath: "/vault/config/config.hcl",
									SubPath:   "config.hcl",
								},
							},
						},
						{
							Name:    "MyContainer",
							Image:   "myimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{
									Name:      "agent-secrets",
									MountPath: "/vault/secrets",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "vault-env",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "agent-secrets",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "agent-configmap",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "config-map-test",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "config.hcl",
											Path: "config.hcl",
										},
									},
									DefaultMode: &defaultMode,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := &mutatingWebhook{
				k8sClient: tt.fields.k8sClient,
				registry:  tt.fields.registry,
				logger:    logrus.NewEntry(logrus.New()),
			}
			err := mw.mutatePod(context.Background(), tt.args.pod, tt.args.vaultConfig, tt.args.ns, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("mutatingWebhook.mutatePod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !cmp.Equal(tt.args.pod, tt.wantedPod) {
				t.Errorf("mutatingWebhook.mutatePod() = diff %v", cmp.Diff(tt.args.pod, tt.wantedPod))
			}
		})
	}
}
