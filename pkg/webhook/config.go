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
	"strconv"
	"time"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VaultConfig represents vault options
type VaultConfig struct {
	Addr                        string
	AuthMethod                  string
	Role                        string
	Path                        string
	SkipVerify                  bool
	TLSSecret                   string
	ClientTimeout               time.Duration
	UseAgent                    bool
	VaultEnvDaemon              bool
	VaultEnvDelay               time.Duration
	TransitKeyID                string
	TransitPath                 string
	CtConfigMap                 string
	CtImage                     string
	CtInjectInInitcontainers    bool
	CtOnce                      bool
	CtImagePullPolicy           corev1.PullPolicy
	CtShareProcess              bool
	CtShareProcessDefault       string
	CtCPU                       resource.Quantity
	CtMemory                    resource.Quantity
	PspAllowPrivilegeEscalation bool
	IgnoreMissingSecrets        string
	VaultEnvPassThrough         string
	ConfigfilePath              string
	MutateConfigMap             bool
	EnableJSONLog               string
	LogLevel                    string
	AgentConfigMap              string
	AgentOnce                   bool
	AgentShareProcess           bool
	AgentShareProcessDefault    string
	AgentCPU                    resource.Quantity
	AgentMemory                 resource.Quantity
	AgentImage                  string
	AgentImagePullPolicy        corev1.PullPolicy
	EnvImage                    string
	EnvImagePullPolicy          corev1.PullPolicy
	Skip                        bool
	VaultEnvFromPath            string
	TokenAuthMount              string
	EnvCPURequest               resource.Quantity
	EnvMemoryRequest            resource.Quantity
	EnvCPULimit                 resource.Quantity
	EnvMemoryLimit              resource.Quantity
	VaultNamespace              string
}

func parseVaultConfig(obj metav1.Object) VaultConfig {
	var vaultConfig VaultConfig
	annotations := obj.GetAnnotations()

	if val := annotations["vault.security.banzaicloud.io/mutate"]; val == "skip" {
		vaultConfig.Skip = true

		return vaultConfig
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-addr"]; ok {
		vaultConfig.Addr = val
	} else {
		vaultConfig.Addr = viper.GetString("vault_addr")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-role"]; ok {
		vaultConfig.Role = val
	} else {
		if val := viper.GetString("vault_role"); val != "" {
			vaultConfig.Role = val
		} else {
			switch p := obj.(type) {
			case *corev1.Pod:
				vaultConfig.Role = p.Spec.ServiceAccountName
			default:
				vaultConfig.Role = "default"
			}
		}
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-auth-method"]; ok {
		vaultConfig.AuthMethod = val
	} else {
		vaultConfig.AuthMethod = viper.GetString("vault_auth_method")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-path"]; ok {
		vaultConfig.Path = val
	} else {
		vaultConfig.Path = viper.GetString("vault_path")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-skip-verify"]; ok {
		vaultConfig.SkipVerify, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.SkipVerify = viper.GetBool("vault_skip_verify")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-tls-secret"]; ok {
		vaultConfig.TLSSecret = val
	} else {
		vaultConfig.TLSSecret = viper.GetString("vault_tls_secret")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-client-timeout"]; ok {
		vaultConfig.ClientTimeout, _ = time.ParseDuration(val)
	} else {
		vaultConfig.ClientTimeout, _ = time.ParseDuration(viper.GetString("vault_client_timeout"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-agent"]; ok {
		vaultConfig.UseAgent, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.UseAgent, _ = strconv.ParseBool(viper.GetString("vault_agent"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-env-daemon"]; ok {
		vaultConfig.VaultEnvDaemon, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.VaultEnvDaemon, _ = strconv.ParseBool(viper.GetString("vault_env_daemon"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-env-delay"]; ok {
		vaultConfig.VaultEnvDelay, _ = time.ParseDuration(val)
	} else {
		vaultConfig.VaultEnvDelay, _ = time.ParseDuration(viper.GetString("vault_env_delay"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-ct-configmap"]; ok {
		vaultConfig.CtConfigMap = val
	} else {
		vaultConfig.CtConfigMap = ""
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-ct-image"]; ok {
		vaultConfig.CtImage = val
	} else {
		vaultConfig.CtImage = viper.GetString("vault_ct_image")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-ignore-missing-secrets"]; ok {
		vaultConfig.IgnoreMissingSecrets = val
	} else {
		vaultConfig.IgnoreMissingSecrets = viper.GetString("vault_ignore_missing_secrets")
	}
	if val, ok := annotations["vault.security.banzaicloud.io/vault-env-passthrough"]; ok {
		vaultConfig.VaultEnvPassThrough = val
	} else {
		vaultConfig.VaultEnvPassThrough = viper.GetString("vault_env_passthrough")
	}
	if val, ok := annotations["vault.security.banzaicloud.io/vault-configfile-path"]; ok {
		vaultConfig.ConfigfilePath = val
	} else if val, ok := annotations["vault.security.banzaicloud.io/vault-ct-secrets-mount-path"]; ok {
		vaultConfig.ConfigfilePath = val
	} else {
		vaultConfig.ConfigfilePath = "/vault/secrets"
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-ct-pull-policy"]; ok {
		vaultConfig.CtImagePullPolicy = getPullPolicy(val)
	} else {
		vaultConfig.CtImagePullPolicy = getPullPolicy(viper.GetString("vault_ct_pull_policy"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-ct-once"]; ok {
		vaultConfig.CtOnce, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.CtOnce = false
	}

	if val, err := resource.ParseQuantity(annotations["vault.security.banzaicloud.io/vault-ct-cpu"]); err == nil {
		vaultConfig.CtCPU = val
	} else {
		vaultConfig.CtCPU = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations["vault.security.banzaicloud.io/vault-ct-memory"]); err == nil {
		vaultConfig.CtMemory = val
	} else {
		vaultConfig.CtMemory = resource.MustParse("128Mi")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-ct-share-process-namespace"]; ok {
		vaultConfig.CtShareProcessDefault = "found"
		vaultConfig.CtShareProcess, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.CtShareProcessDefault = "empty"
		vaultConfig.CtShareProcess = false
	}

	if val, ok := annotations["vault.security.banzaicloud.io/psp-allow-privilege-escalation"]; ok {
		vaultConfig.PspAllowPrivilegeEscalation, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.PspAllowPrivilegeEscalation, _ = strconv.ParseBool(viper.GetString("psp_allow_privilege_escalation"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/mutate-configmap"]; ok {
		vaultConfig.MutateConfigMap, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.MutateConfigMap, _ = strconv.ParseBool(viper.GetString("mutate_configmap"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/log-level"]; ok {
		vaultConfig.LogLevel = val
	} else {
		vaultConfig.LogLevel = viper.GetString("log_level")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/enable-json-log"]; ok {
		vaultConfig.EnableJSONLog = val
	} else {
		vaultConfig.EnableJSONLog = viper.GetString("enable_json_log")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/transit-key-id"]; ok {
		vaultConfig.TransitKeyID = val
	}

	if val, ok := annotations["vault.security.banzaicloud.io/transit-path"]; ok {
		vaultConfig.TransitPath = val
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-agent-configmap"]; ok {
		vaultConfig.AgentConfigMap = val
	} else {
		vaultConfig.AgentConfigMap = ""
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-agent-once"]; ok {
		vaultConfig.AgentOnce, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.AgentOnce = false
	}

	if val, err := resource.ParseQuantity(annotations["vault.security.banzaicloud.io/vault-agent-cpu"]); err == nil {
		vaultConfig.AgentCPU = val
	} else {
		vaultConfig.AgentCPU = resource.MustParse("100m")
	}

	if val, err := resource.ParseQuantity(annotations["vault.security.banzaicloud.io/vault-agent-memory"]); err == nil {
		vaultConfig.AgentMemory = val
	} else {
		vaultConfig.AgentMemory = resource.MustParse("128Mi")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-agent-share-process-namespace"]; ok {
		vaultConfig.AgentShareProcessDefault = "found"
		vaultConfig.AgentShareProcess, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.AgentShareProcessDefault = "empty"
		vaultConfig.AgentShareProcess = false
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-env-from-path"]; ok {
		vaultConfig.VaultEnvFromPath = val
	}

	if val, ok := annotations["vault.security.banzaicloud.io/token-auth-mount"]; ok {
		vaultConfig.TokenAuthMount = val
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-env-image"]; ok {
		vaultConfig.EnvImage = val
	} else {
		vaultConfig.EnvImage = viper.GetString("vault_env_image")
	}
	if val, ok := annotations["vault.security.banzaicloud.io/vault-env-image-pull-policy"]; ok {
		vaultConfig.EnvImagePullPolicy = getPullPolicy(val)
	} else {
		vaultConfig.EnvImagePullPolicy = getPullPolicy(viper.GetString("vault_env_pull_policy"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-image"]; ok {
		vaultConfig.AgentImage = val
	} else {
		vaultConfig.AgentImage = viper.GetString("vault_image")
	}
	if val, ok := annotations["vault.security.banzaicloud.io/vault-image-pull-policy"]; ok {
		vaultConfig.AgentImagePullPolicy = getPullPolicy(val)
	} else {
		vaultConfig.AgentImagePullPolicy = getPullPolicy(viper.GetString("vault_image_pull_policy"))
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-namespace"]; ok {
		vaultConfig.VaultNamespace = val
	} else {
		vaultConfig.VaultNamespace = viper.GetString("VAULT_NAMESPACE")
	}

	if val, ok := annotations["vault.security.banzaicloud.io/vault-ct-inject-in-initcontainers"]; ok {
		vaultConfig.CtInjectInInitcontainers, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.CtInjectInInitcontainers = false
	}

	if val, err := resource.ParseQuantity(viper.GetString("VAULT_ENV_CPU_REQUEST")); err == nil {
		vaultConfig.EnvCPURequest = val
	} else {
		vaultConfig.EnvCPURequest = resource.MustParse("50m")
	}

	if val, err := resource.ParseQuantity(viper.GetString("VAULT_ENV_MEMORY_REQUEST")); err == nil {
		vaultConfig.EnvMemoryRequest = val
	} else {
		vaultConfig.EnvMemoryRequest = resource.MustParse("64Mi")
	}

	if val, err := resource.ParseQuantity(viper.GetString("VAULT_ENV_CPU_LIMIT")); err == nil {
		vaultConfig.EnvCPULimit = val
	} else {
		vaultConfig.EnvCPULimit = resource.MustParse("250m")
	}

	if val, err := resource.ParseQuantity(viper.GetString("VAULT_ENV_MEMORY_LIMIT")); err == nil {
		vaultConfig.EnvMemoryLimit = val
	} else {
		vaultConfig.EnvMemoryLimit = resource.MustParse("64Mi")
	}

	return vaultConfig
}

func getPullPolicy(pullPolicyStr string) corev1.PullPolicy {
	switch pullPolicyStr {
	case "Never", "never":
		return corev1.PullNever
	case "Always", "always":
		return corev1.PullAlways
	case "IfNotPresent", "ifnotpresent":
		return corev1.PullIfNotPresent
	}

	return corev1.PullIfNotPresent
}

func SetConfigDefaults() {
	viper.SetDefault("vault_image", "vault:latest")
	viper.SetDefault("vault_image_pull_policy", string(corev1.PullIfNotPresent))
	viper.SetDefault("vault_env_image", "ghcr.io/banzaicloud/vault-env:latest")
	viper.SetDefault("vault_env_pull_policy", string(corev1.PullIfNotPresent))
	viper.SetDefault("vault_ct_image", "hashicorp/consul-template:0.24.1-alpine")
	viper.SetDefault("vault_ct_pull_policy", string(corev1.PullIfNotPresent))
	viper.SetDefault("vault_addr", "https://vault:8200")
	viper.SetDefault("vault_skip_verify", "false")
	viper.SetDefault("vault_path", "kubernetes")
	viper.SetDefault("vault_auth_method", "jwt")
	viper.SetDefault("vault_role", "")
	viper.SetDefault("vault_tls_secret", "")
	viper.SetDefault("vault_client_timeout", "10s")
	viper.SetDefault("vault_agent", "false")
	viper.SetDefault("vault_env_daemon", "false")
	viper.SetDefault("vault_ct_share_process_namespace", "")
	viper.SetDefault("psp_allow_privilege_escalation", "false")
	viper.SetDefault("vault_ignore_missing_secrets", "false")
	viper.SetDefault("vault_env_passthrough", "")
	viper.SetDefault("mutate_configmap", "false")
	viper.SetDefault("tls_cert_file", "")
	viper.SetDefault("tls_private_key_file", "")
	viper.SetDefault("listen_address", ":8443")
	viper.SetDefault("telemetry_listen_address", "")
	viper.SetDefault("default_image_pull_secret", "")
	viper.SetDefault("default_image_pull_secret_namespace", "")
	viper.SetDefault("registry_skip_verify", "false")
	viper.SetDefault("enable_json_log", "false")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("vault_agent_share_process_namespace", "")
	viper.SetDefault("VAULT_ENV_CPU_REQUEST", "")
	viper.SetDefault("VAULT_ENV_MEMORY_REQUEST", "")
	viper.SetDefault("VAULT_ENV_CPU_LIMIT", "")
	viper.SetDefault("VAULT_ENV_MEMORY_LIMIT", "")
	viper.SetDefault("VAULT_NAMESPACE", "")
	viper.AutomaticEnv()
}
