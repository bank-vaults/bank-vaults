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
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	whhttp "github.com/slok/kubewebhook/v2/pkg/http"
	whlog "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	whmetrics "github.com/slok/kubewebhook/v2/pkg/metrics/prometheus"
	whwebhook "github.com/slok/kubewebhook/v2/pkg/webhook"
	"github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	kubernetesConfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/banzaicloud/bank-vaults/pkg/webhook"
)

func init() {
	webhook.SetConfigDefaults()
}

func newK8SClient() (kubernetes.Interface, error) {
	kubeConfig, err := kubernetesConfig.GetConfig()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(kubeConfig)
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
}

func handlerFor(config mutating.WebhookConfig, recorder whwebhook.MetricsRecorder) http.Handler {
	wh, err := mutating.NewWebhook(config)
	if err != nil {
		panic("error creating webhook: " + err.Error())
	}

	wh = whwebhook.NewMeasuredWebhook(recorder, wh)

	return whhttp.MustHandlerFor(whhttp.HandlerConfig{Webhook: wh, Logger: config.Logger})
}

func main() {
	var logger *logrus.Entry
	{
		l := logrus.New()

		if viper.GetBool("enable_json_log") {
			l.SetFormatter(&logrus.JSONFormatter{})
		}

		lvl, err := logrus.ParseLevel(viper.GetString("log_level"))
		if err != nil {
			lvl = logrus.InfoLevel
		}
		l.SetLevel(lvl)

		logger = l.WithField("app", "vault-secrets-webhook")
	}

	k8sClient, err := newK8SClient()
	if err != nil {
		logger.Fatalf("error creating k8s client: %s", err)
	}

	mutatingWebhook, err := webhook.NewMutatingWebhook(logger, k8sClient)
	if err != nil {
		logger.Fatalf("error creating mutating webhook: %s", err)
	}

	whLogger := whlog.NewLogrus(logger)

	mutator := webhook.ErrorLoggerMutator(mutatingWebhook.VaultSecretsMutator, whLogger)

	promRegistry := prometheus.NewRegistry()
	metricsRecorder, err := whmetrics.NewRecorder(whmetrics.RecorderConfig{Registry: promRegistry})
	if err != nil {
		logger.Fatalf("error creating metrics recorder: %s", err)
	}

	promHandler := promhttp.HandlerFor(promRegistry, promhttp.HandlerOpts{})
	podHandler := handlerFor(mutating.WebhookConfig{ID: "vault-secrets-pods", Obj: &corev1.Pod{}, Logger: whLogger, Mutator: mutator}, metricsRecorder)
	secretHandler := handlerFor(mutating.WebhookConfig{ID: "vault-secrets-secret", Obj: &corev1.Secret{}, Logger: whLogger, Mutator: mutator}, metricsRecorder)
	configMapHandler := handlerFor(mutating.WebhookConfig{ID: "vault-secrets-configmap", Obj: &corev1.ConfigMap{}, Logger: whLogger, Mutator: mutator}, metricsRecorder)
	objectHandler := handlerFor(mutating.WebhookConfig{ID: "vault-secrets-object", Obj: &unstructured.Unstructured{}, Logger: whLogger, Mutator: mutator}, metricsRecorder)

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
		go mutatingWebhook.ServeMetrics(telemetryAddress, promHandler)
	} else {
		mux.Handle("/metrics", promHandler)
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
