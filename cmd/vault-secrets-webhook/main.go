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
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"emperror.dev/errors"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	whhttp "github.com/slok/kubewebhook/pkg/http"
	"github.com/slok/kubewebhook/pkg/observability/metrics"
	whcontext "github.com/slok/kubewebhook/pkg/webhook/context"
	"github.com/slok/kubewebhook/pkg/webhook/mutating"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	logrusadapter "logur.dev/adapter/logrus"
	kubernetesConfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/banzaicloud/bank-vaults/cmd/vault-secrets-webhook/registry"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
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
	TransitKeyID                string
	TransitPath                 string
	CtConfigMap                 string
	CtImage                     string
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
	InlineMutation              bool
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
}

func init() {
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
	viper.SetDefault("inline_mutation", "false")
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
	viper.AutomaticEnv()
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

	if val, ok := annotations["vault.security.banzaicloud.io/inline-mutation"]; ok {
		vaultConfig.InlineMutation, _ = strconv.ParseBool(val)
	} else {
		vaultConfig.InlineMutation, _ = strconv.ParseBool(viper.GetString("inline_mutation"))
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

type mutatingWebhook struct {
	k8sClient kubernetes.Interface
	namespace string
	registry  registry.ImageRegistry
	logger    *logrus.Entry
}

func (mw *mutatingWebhook) vaultSecretsMutator(ctx context.Context, obj metav1.Object) (bool, error) {
	vaultConfig := parseVaultConfig(obj)

	if vaultConfig.Skip {
		return false, nil
	}

	switch v := obj.(type) {
	case *corev1.Pod:
		return false, mw.mutatePod(ctx, v, vaultConfig, whcontext.GetAdmissionRequest(ctx).Namespace, whcontext.IsAdmissionRequestDryRun(ctx))

	case *corev1.Secret:
		return false, mw.mutateSecret(v, vaultConfig)

	case *corev1.ConfigMap:
		return false, mw.mutateConfigMap(v, vaultConfig)

	case *unstructured.Unstructured:
		return false, mw.mutateObject(v, vaultConfig)

	default:
		return false, nil
	}
}

func (mw *mutatingWebhook) getDataFromConfigmap(cmName string, ns string) (map[string]string, error) {
	configMap, err := mw.k8sClient.CoreV1().ConfigMaps(ns).Get(context.Background(), cmName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return configMap.Data, nil
}

func (mw *mutatingWebhook) getDataFromSecret(secretName string, ns string) (map[string][]byte, error) {
	secret, err := mw.k8sClient.CoreV1().Secrets(ns).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

func (mw *mutatingWebhook) lookForEnvFrom(envFrom []corev1.EnvFromSource, ns string) ([]corev1.EnvVar, error) {
	var envVars []corev1.EnvVar

	for _, ef := range envFrom {
		if ef.ConfigMapRef != nil {
			data, err := mw.getDataFromConfigmap(ef.ConfigMapRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (ef.ConfigMapRef.Optional != nil && *ef.ConfigMapRef.Optional) {
					continue
				} else {
					return envVars, err
				}
			}
			for key, value := range data {
				if hasVaultPrefix(value) {
					envFromCM := corev1.EnvVar{
						Name:  key,
						Value: value,
					}
					envVars = append(envVars, envFromCM)
				}
			}
		}
		if ef.SecretRef != nil {
			data, err := mw.getDataFromSecret(ef.SecretRef.Name, ns)
			if err != nil {
				if apierrors.IsNotFound(err) || (ef.SecretRef.Optional != nil && *ef.SecretRef.Optional) {
					continue
				} else {
					return envVars, err
				}
			}
			for key, value := range data {
				if hasVaultPrefix(string(value)) {
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

func (mw *mutatingWebhook) lookForValueFrom(env corev1.EnvVar, ns string) (*corev1.EnvVar, error) {
	if env.ValueFrom.ConfigMapKeyRef != nil {
		data, err := mw.getDataFromConfigmap(env.ValueFrom.ConfigMapKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		if hasVaultPrefix(data[env.ValueFrom.ConfigMapKeyRef.Key]) {
			fromCM := corev1.EnvVar{
				Name:  env.Name,
				Value: data[env.ValueFrom.ConfigMapKeyRef.Key],
			}
			return &fromCM, nil
		}
	}
	if env.ValueFrom.SecretKeyRef != nil {
		data, err := mw.getDataFromSecret(env.ValueFrom.SecretKeyRef.Name, ns)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		if hasVaultPrefix(string(data[env.ValueFrom.SecretKeyRef.Key])) {
			fromSecret := corev1.EnvVar{
				Name:  env.Name,
				Value: string(data[env.ValueFrom.SecretKeyRef.Key]),
			}
			return &fromSecret, nil
		}
	}
	return nil, nil
}

func (mw *mutatingWebhook) newVaultClient(vaultConfig VaultConfig) (*vault.Client, error) {
	clientConfig := vaultapi.DefaultConfig()
	if clientConfig.Error != nil {
		return nil, clientConfig.Error
	}

	clientConfig.Address = vaultConfig.Addr

	tlsConfig := vaultapi.TLSConfig{Insecure: vaultConfig.SkipVerify}
	err := clientConfig.ConfigureTLS(&tlsConfig)
	if err != nil {
		return nil, err
	}

	if vaultConfig.TLSSecret != "" {
		tlsSecret, err := mw.k8sClient.CoreV1().Secrets(mw.namespace).Get(
			context.Background(),
			vaultConfig.TLSSecret,
			metav1.GetOptions{},
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read Vault TLS Secret")
		}

		clientTLSConfig := clientConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig

		pool := x509.NewCertPool()

		ok := pool.AppendCertsFromPEM(tlsSecret.Data["ca.crt"])
		if !ok {
			return nil, errors.Errorf("error loading Vault CA PEM from TLS Secret: %s", tlsSecret.Name)
		}

		clientTLSConfig.RootCAs = pool
	}

	return vault.NewClientFromConfig(
		clientConfig,
		vault.ClientRole(vaultConfig.Role),
		vault.ClientAuthPath(vaultConfig.Path),
		vault.ClientAuthMethod(vaultConfig.AuthMethod),
		vault.ClientLogger(logrusadapter.NewFromEntry(mw.logger)),
	)
}

func newK8SClient() (kubernetes.Interface, error) {
	kubeConfig, err := kubernetesConfig.GetConfig()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(kubeConfig)
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}

func handlerFor(config mutating.WebhookConfig, mutator mutating.MutatorFunc, recorder metrics.Recorder, logger logrus.FieldLogger) http.Handler {
	webhook, err := mutating.NewWebhook(config, mutator, nil, recorder, logger)
	if err != nil {
		logger.Fatalf("error creating webhook: %s", err)
	}

	return whhttp.MustHandlerFor(webhook)
}

func (mw *mutatingWebhook) serveMetrics(addr string) {
	mw.logger.Infof("Telemetry on http://%s", addr)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(addr, mux)
	if err != nil {
		mw.logger.Fatalf("error serving telemetry: %s", err)
	}
}

func main() {
	var logger *logrus.Entry
	{
		log := logrus.New()

		if viper.GetBool("enable_json_log") {
			log.SetFormatter(&logrus.JSONFormatter{})
		}

		lvl, err := logrus.ParseLevel(viper.GetString("log_level"))
		if err != nil {
			lvl = logrus.InfoLevel
		}
		log.SetLevel(lvl)

		logger = log.WithField("app", "vault-secrets-webhook")
	}

	k8sClient, err := newK8SClient()
	if err != nil {
		logger.Fatalf("error creating k8s client: %s", err)
	}

	namespace, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		logger.Fatalf("error reading k8s namespace: %s", err)
	}

	mutatingWebhook := mutatingWebhook{
		k8sClient: k8sClient,
		namespace: string(namespace),
		registry:  registry.NewRegistry(),
		logger:    logger,
	}

	mutator := mutating.MutatorFunc(mutatingWebhook.vaultSecretsMutator)

	metricsRecorder := metrics.NewPrometheus(prometheus.DefaultRegisterer)

	podHandler := handlerFor(mutating.WebhookConfig{Name: "vault-secrets-pods", Obj: &corev1.Pod{}}, mutator, metricsRecorder, logger)
	secretHandler := handlerFor(mutating.WebhookConfig{Name: "vault-secrets-secret", Obj: &corev1.Secret{}}, mutator, metricsRecorder, logger)
	configMapHandler := handlerFor(mutating.WebhookConfig{Name: "vault-secrets-configmap", Obj: &corev1.ConfigMap{}}, mutator, metricsRecorder, logger)
	objectHandler := handlerFor(mutating.WebhookConfig{Name: "vault-secrets-object", Obj: &unstructured.Unstructured{}}, mutator, metricsRecorder, logger)

	mux := http.NewServeMux()
	mux.Handle("/pods", podHandler)
	mux.Handle("/secrets", secretHandler)
	mux.Handle("/configmaps", configMapHandler)
	mux.Handle("/objects", objectHandler)
	mux.Handle("/healthz", http.HandlerFunc(healthzHandler))

	telemetryAddress := viper.GetString("telemetry_listen_address")
	listenAddress := viper.GetString("listen_address")
	tlsCertFile := viper.GetString("tls_cert_file")
	tlsPrivateKeyFile := viper.GetString("tls_private_key_file")

	if len(telemetryAddress) > 0 {
		// Serving metrics without TLS on separated address
		go mutatingWebhook.serveMetrics(telemetryAddress)
	} else {
		mux.Handle("/metrics", promhttp.Handler())
	}

	if tlsCertFile == "" && tlsPrivateKeyFile == "" {
		logger.Infof("Listening on http://%s", listenAddress)
		err = http.ListenAndServe(listenAddress, mux)
	} else {
		logger.Infof("Listening on https://%s", listenAddress)
		err = http.ListenAndServeTLS(listenAddress, tlsCertFile, tlsPrivateKeyFile, mux)
	}

	if err != nil {
		logger.Fatalf("error serving webhook: %s", err)
	}
}
