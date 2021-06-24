// Copyright © 2021 Banzai Cloud
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
	"testing"
	"time"

	cmp "github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	fake "k8s.io/client-go/kubernetes/fake"
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
	t.Parallel()

	vaultConfigEnvFrom := vaultConfig
	vaultConfigEnvFrom.VaultEnvFromPath = "secrets/application"

	type fields struct {
		k8sClient kubernetes.Interface
		registry  ImageRegistry
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
		{
			name: "Will mutate container with command, no args",
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
		{
			name: "Will mutate container with command, other syntax",
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
		{
			name: "Will mutate container with args, no command",
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
		{
			name: "Will mutate container with no container-command, no entrypoint",
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
		{
			name: "Will not mutate container without secrets with correct prefix",
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
		{
			name: "Will mutate container with env-from-path annotation",
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
		{
			name: "Will mutate container with command, no args, with inline mutation",
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
		ttp := tt
		t.Run(ttp.name, func(t *testing.T) {
			t.Parallel()

			mw := &MutatingWebhook{
				k8sClient: ttp.fields.k8sClient,
				registry:  ttp.fields.registry,
				logger:    logrus.NewEntry(logrus.New()),
			}
			got, err := mw.mutateContainers(context.Background(), ttp.args.containers, ttp.args.podSpec, ttp.args.vaultConfig, ttp.args.ns)
			if (err != nil) != ttp.wantErr {
				t.Errorf("MutatingWebhook.mutateContainers() error = %v, wantErr %v", err, ttp.wantErr)
				return
			}
			if got != ttp.mutated {
				t.Errorf("MutatingWebhook.mutateContainers() = %v, want %v", got, ttp.mutated)
			}
			if !cmp.Equal(ttp.args.containers, ttp.wantedContainers) {
				t.Errorf("MutatingWebhook.mutateContainers() = diff %v", cmp.Diff(ttp.args.containers, ttp.wantedContainers))
			}
		})
	}
}

func Test_mutatingWebhook_mutatePod(t *testing.T) {
	t.Parallel()

	type fields struct {
		k8sClient kubernetes.Interface
		registry  ImageRegistry
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
		{
			name: "Will mutate pod with ct-configmap annotations",
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
					EnvCPURequest:        resource.MustParse("50m"),
					EnvMemoryRequest:     resource.MustParse("64Mi"),
					EnvCPULimit:          resource.MustParse("250m"),
					EnvMemoryLimit:       resource.MustParse("64Mi"),
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
		{
			name: "Will mutate pod with ct-once annotations",
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
					CtOnce:               true,
					ConfigfilePath:       "/vault/secrets",
					Addr:                 "test",
					SkipVerify:           false,
					CtCPU:                resource.MustParse("50m"),
					CtMemory:             resource.MustParse("128Mi"),
					AgentImage:           "vault:latest",
					AgentImagePullPolicy: "IfNotPresent",
					EnvCPURequest:        resource.MustParse("50m"),
					EnvMemoryRequest:     resource.MustParse("64Mi"),
					EnvCPULimit:          resource.MustParse("250m"),
					EnvMemoryLimit:       resource.MustParse("64Mi"),
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
						{
							Name: "consul-template",
							Args: []string{"-config", "/vault/ct-config/config.hcl", "-once"},
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
					},
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
		{
			name: "Will mutate pod with agent-configmap annotations",
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
		{
			name: "Will mutate pod with vault-ct-inject-in-initcontainers and ct-once annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Name:    "MyInitContainer",
								Image:   "myInitimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
									},
								},
							},
						},
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
					CtConfigMap:              "config-map-test",
					CtOnce:                   true,
					CtInjectInInitcontainers: true,
					ConfigfilePath:           "/vault/secrets",
					Addr:                     "test",
					SkipVerify:               false,
					CtCPU:                    resource.MustParse("50m"),
					CtMemory:                 resource.MustParse("128Mi"),
					AgentImage:               "vault:latest",
					AgentImagePullPolicy:     "IfNotPresent",
					EnvCPURequest:            resource.MustParse("50m"),
					EnvMemoryRequest:         resource.MustParse("64Mi"),
					EnvCPULimit:              resource.MustParse("250m"),
					EnvMemoryLimit:           resource.MustParse("64Mi"),
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
						{
							Name: "consul-template",
							Args: []string{"-config", "/vault/ct-config/config.hcl", "-once"},
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
							Name:    "MyInitContainer",
							Image:   "myInitimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
								},
								{Name: "ct-secrets", MountPath: "/vault/secrets"},
							},
						},
					},
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
		{
			name: "Will mutate pod with vault-ct-inject-in-initcontainers and without ct-once annotations",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
				registry: &MockRegistry{
					Image: v1.Config{},
				},
			},
			args: args{
				pod: &corev1.Pod{
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Name:    "MyInitContainer",
								Image:   "myInitimage",
								Command: []string{"/bin/bash"},
								Args:    nil,
								VolumeMounts: []corev1.VolumeMount{
									{
										MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
									},
								},
							},
						},
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
					CtConfigMap:              "config-map-test",
					CtInjectInInitcontainers: true,
					ConfigfilePath:           "/vault/secrets",
					Addr:                     "test",
					SkipVerify:               false,
					CtCPU:                    resource.MustParse("50m"),
					CtMemory:                 resource.MustParse("128Mi"),
					AgentImage:               "vault:latest",
					AgentImagePullPolicy:     "IfNotPresent",
					EnvCPURequest:            resource.MustParse("50m"),
					EnvMemoryRequest:         resource.MustParse("64Mi"),
					EnvCPULimit:              resource.MustParse("250m"),
					EnvMemoryLimit:           resource.MustParse("64Mi"),
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
						{
							Name:    "MyInitContainer",
							Image:   "myInitimage",
							Command: []string{"/bin/bash"},
							Args:    nil,
							VolumeMounts: []corev1.VolumeMount{
								{
									MountPath: "/var/run/secrets/kubernetes.io/serviceaccount",
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
	}

	for _, tt := range tests {
		ttp := tt
		t.Run(ttp.name, func(t *testing.T) {
			t.Parallel()

			mw := &MutatingWebhook{
				k8sClient: ttp.fields.k8sClient,
				registry:  ttp.fields.registry,
				logger:    logrus.NewEntry(logrus.New()),
			}
			err := mw.MutatePod(context.Background(), ttp.args.pod, ttp.args.vaultConfig, ttp.args.ns, false)
			if (err != nil) != ttp.wantErr {
				t.Errorf("MutatingWebhook.MutatePod() error = %v, wantErr %v", err, ttp.wantErr)
				return
			}

			if !cmp.Equal(ttp.args.pod, ttp.wantedPod) {
				t.Errorf("MutatingWebhook.MutatePod() = diff %v", cmp.Diff(ttp.args.pod, ttp.wantedPod))
			}
		})
	}
}
