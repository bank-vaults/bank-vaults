// Copyright © 2019 Banzai Cloud
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
	"testing"

	cmp "github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	fake "k8s.io/client-go/kubernetes/fake"

	internal "github.com/banzaicloud/bank-vaults/internal/configuration"
)

var vaultConfig = internal.VaultConfig{
	Addr:                 "addr",
	SkipVerify:           "skipVerify",
	Path:                 "path",
	Role:                 "role",
	IgnoreMissingSecrets: "ignoreMissingSecrets",
	VaultEnvPassThrough:  "vaultEnvPassThrough",
	EnableJSONLog:        "enableJSONLog",
}

func Test_mutatingWebhook_mutateContainers(t *testing.T) {

	type fields struct {
		k8sClient kubernetes.Interface
	}
	type args struct {
		containers  []corev1.Container
		podSpec     *corev1.PodSpec
		vaultConfig internal.VaultConfig
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
			},
			args: args{
				containers: []corev1.Container{
					corev1.Container{
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
				corev1.Container{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/vault/vault-env"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "vault-env", MountPath: "/vault/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: "vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "skipVerify"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_ENV_PASSTHROUGH", Value: "vaultEnvPassThrough"},
						{Name: "VAULT_JSON_LOG", Value: "enableJSONLog"},
					},
				},
			},
			mutated: true,
			wantErr: false,
		},
		{name: "Will mutate container with command, other syntax",
			fields: fields{
				k8sClient: fake.NewSimpleClientset(),
			},
			args: args{
				containers: []corev1.Container{
					corev1.Container{
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
				corev1.Container{
					Name:         "MyContainer",
					Image:        "myimage",
					Command:      []string{"/vault/vault-env"},
					Args:         []string{"/bin/bash"},
					VolumeMounts: []corev1.VolumeMount{{Name: "vault-env", MountPath: "/vault/"}},
					Env: []corev1.EnvVar{
						{Name: "myvar", Value: ">>vault:secrets"},
						{Name: "VAULT_ADDR", Value: "addr"},
						{Name: "VAULT_SKIP_VERIFY", Value: "skipVerify"},
						{Name: "VAULT_PATH", Value: "path"},
						{Name: "VAULT_ROLE", Value: "role"},
						{Name: "VAULT_IGNORE_MISSING_SECRETS", Value: "ignoreMissingSecrets"},
						{Name: "VAULT_ENV_PASSTHROUGH", Value: "vaultEnvPassThrough"},
						{Name: "VAULT_JSON_LOG", Value: "enableJSONLog"},
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
			}
			got, err := mw.mutateContainers(tt.args.containers, tt.args.podSpec, tt.args.vaultConfig, tt.args.ns)
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
