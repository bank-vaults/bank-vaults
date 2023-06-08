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

//go:build kubeall || helm
// +build kubeall helm

// Fire up a local Kubernetes cluster (`kind create cluster --config test/kind.yaml`)
// and run the acceptance tests against it (`go test -v -tags kubeall ./test`)

package test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/logger"
	"github.com/gruntwork-io/terratest/modules/retry"
)

var (
	vaultVersion    = "latest"
	operatorChart   = "oci://ghcr.io/bank-vaults/helm-charts/vault-operator"
	operatorVersion = "1.20.0"
)

// Installing the operator helm chart before testing
func TestMain(m *testing.M) {
	// Setting Vault version
	if os.Getenv("VAULT_VERSION") != "" {
		vaultVersion = os.Getenv("VAULT_VERSION")
	}

	// Run tests
	exitCode := m.Run()

	// Exit based on the test results
	os.Exit(exitCode)
}

func TestVaultHelmChart(t *testing.T) {
	releaseName := "vault"
	kubectlOptions := k8s.NewKubectlOptions("", "", "default")

	// Setup the args for helm.
	options := &helm.Options{
		KubectlOptions: kubectlOptions,
		SetValues: map[string]string{
			"unsealer.image.tag": "latest",
			"unsealer.args[0]":   "--mode",
			"unsealer.args[1]":   "k8s",
			"unsealer.args[2]":   "--k8s-secret-namespace",
			"unsealer.args[3]":   kubectlOptions.Namespace,
			"unsealer.args[4]":   "--k8s-secret-name",
			"unsealer.args[5]":   "bank-vaults",
			"ingress.enabled":    "true",
			"ingress.hosts[0]":   "localhost",
			"image.tag":          vaultVersion,
		},
	}

	// Deploy the chart using `helm install`
	helm.Install(t, options, "../charts/vault", releaseName)
	defer helm.Delete(t, options, releaseName, true)

	// Check the Vault pod to be up and running
	k8s.WaitUntilPodAvailable(t, kubectlOptions, "vault-0", 5, 10*time.Second)
}

func TestWebhook(t *testing.T) {
	// Create a different namespace for the webhook
	webhookKubectlOptions := k8s.NewKubectlOptions("", "", "webhook")
	k8s.CreateNamespace(t, webhookKubectlOptions, webhookKubectlOptions.Namespace)
	defer k8s.DeleteNamespace(t, webhookKubectlOptions, webhookKubectlOptions.Namespace)

	// Create a Vault instance with the operator
	defaultKubectlOptions := k8s.NewKubectlOptions("", "", "default")

	operatorReleaseName := "vault-operator"
	operatorHelmOptions := &helm.Options{
		Version:        operatorVersion,
		KubectlOptions: defaultKubectlOptions,
		SetValues: map[string]string{
			"image.tag":           "latest",
			"image.bankVaultsTag": "latest",
			"image.pullPolicy":    "IfNotPresent",
		},
	}

	helm.Install(t, operatorHelmOptions, operatorChart, operatorReleaseName)
	defer helm.Delete(t, operatorHelmOptions, operatorReleaseName, true)

	operatorPods := waitUntilPodsCreated(t, defaultKubectlOptions, operatorReleaseName, 10, 5*time.Second)
	k8s.WaitUntilPodAvailable(t, defaultKubectlOptions, operatorPods[0].GetName(), 5, 10*time.Second)

	// Create Vault and wait until vault-0 pod comes up healthy and secrets are populated
	k8s.KubectlApply(t, defaultKubectlOptions, "rbac.yaml")
	defer k8s.KubectlDelete(t, defaultKubectlOptions, "rbac.yaml")

	resources, err := prepareResources(vaultVersion, "operator.yaml")
	require.NoError(t, err)
	for _, resource := range resources {
		k8s.KubectlApplyFromString(t, defaultKubectlOptions, string(resource))
	}
	defer k8s.KubectlDelete(t, defaultKubectlOptions, "operator.yaml")

	k8s.WaitUntilPodAvailable(t, defaultKubectlOptions, "vault-0", 12, 10*time.Second)

	// Deploy webhook
	webhookHelmOptions := &helm.Options{
		KubectlOptions: webhookKubectlOptions,
		SetValues: map[string]string{
			"replicaCount":           "1",
			"image.tag":              "latest",
			"image.pullPolicy":       "IfNotPresent",
			"configMapMutation":      "true",
			"configmapFailurePolicy": "Fail",
			"podsFailurePolicy":      "Fail",
			"secretsFailurePolicy":   "Fail",
			"vaultEnv.tag":           "latest",
			"env.VAULT_IMAGE":        "vault:" + vaultVersion,
		},
	}
	webhookReleaseName := "vault-secrets-webhook"
	helm.Install(t, webhookHelmOptions, "../charts/vault-secrets-webhook", webhookReleaseName)
	defer helm.Delete(t, webhookHelmOptions, webhookReleaseName, true)

	// Wait until webhook pods are up and running
	webhookPods := waitUntilPodsCreated(t, webhookKubectlOptions, webhookReleaseName, 12, 5*time.Second)
	for _, webhookPod := range webhookPods {
		k8s.WaitUntilPodAvailable(t, webhookKubectlOptions, webhookPod.GetName(), 5, 10*time.Second)
	}

	// Test 1: Secret testing
	type v1 struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Auth     string `json:"auth"`
	}

	type auths struct {
		V1 v1 `json:"https://index.docker.io/v1/"`
	}

	type dockerconfig struct {
		Auths auths `json:"auths"`
	}

	k8s.KubectlApply(t, defaultKubectlOptions, "deploy/test-secret.yaml")
	time.Sleep(5 * time.Second)
	secret := k8s.GetSecret(t, defaultKubectlOptions, "sample-secret")
	var dockerconfigjson dockerconfig
	err = json.Unmarshal(secret.Data[".dockerconfigjson"], &dockerconfigjson)
	require.NoError(t, err)
	require.Equal(t, "dockerrepouser", dockerconfigjson.Auths.V1.Username)
	require.Equal(t, "dockerrepopassword", dockerconfigjson.Auths.V1.Password)
	require.Equal(t, "Inline: secretId AWS_ACCESS_KEY_ID", string(secret.Data["inline"]))
	k8s.KubectlDelete(t, defaultKubectlOptions, "deploy/test-secret.yaml")

	// Test 2: Configmap testing
	k8s.KubectlApply(t, defaultKubectlOptions, "deploy/test-configmap.yaml")
	time.Sleep(5 * time.Second)
	configMap := k8s.GetConfigMap(t, defaultKubectlOptions, "sample-configmap")
	require.Equal(t, "secretId", string(configMap.Data["aws-access-key-id"]))
	require.Equal(t, "AWS key in base64: c2VjcmV0SWQ=", string(configMap.Data["aws-access-key-id-formatted"]))
	require.Equal(t, "AWS_ACCESS_KEY_ID: secretId AWS_SECRET_ACCESS_KEY: s3cr3t", string(configMap.Data["aws-access-key-id-inline"]))
	require.Equal(t, "secretId", base64.StdEncoding.EncodeToString(configMap.BinaryData["aws-access-key-id-binary"]))
	k8s.KubectlDelete(t, defaultKubectlOptions, "deploy/test-configmap.yaml")

	// Test 3: File templating test
	k8s.KubectlApply(t, defaultKubectlOptions, "deploy/test-deploy-templating.yaml")
	templatingPods := waitUntilPodsCreated(t, defaultKubectlOptions, "test-templating", 12, 5*time.Second)
	time.Sleep(5 * time.Second)
	k8s.WaitUntilPodAvailable(t, defaultKubectlOptions, templatingPods[0].GetName(), 12, 10*time.Second)
	templatingPodLogs := k8s.GetPodLogs(t, defaultKubectlOptions, &templatingPods[0], "alpine")
	require.Equal(t, "\n    {\n      \"id\": \"secretId\",\n      \"key\": \"s3cr3t\"\n    }\n    \n  going to sleep...", templatingPodLogs)
	k8s.KubectlDelete(t, defaultKubectlOptions, "deploy/test-deploy-templating.yaml")

	// Test 4: Check deployment seccontext
	k8s.KubectlApply(t, defaultKubectlOptions, "deploy/test-deployment-seccontext.yaml")
	seccontextPods := waitUntilPodsCreated(t, defaultKubectlOptions, "hello-secrets-seccontext", 12, 5*time.Second)
	k8s.WaitUntilPodAvailable(t, defaultKubectlOptions, seccontextPods[0].GetName(), 12, 10*time.Second)
	k8s.KubectlDelete(t, defaultKubectlOptions, "deploy/test-deployment-seccontext.yaml")

	// Test 5: Check deployment
	k8s.KubectlApply(t, defaultKubectlOptions, "deploy/test-deployment.yaml")
	pods := waitUntilPodsCreated(t, defaultKubectlOptions, "hello-secrets", 12, 5*time.Second)
	k8s.WaitUntilPodAvailable(t, defaultKubectlOptions, pods[0].GetName(), 12, 10*time.Second)
	k8s.KubectlDelete(t, defaultKubectlOptions, "deploy/test-deployment.yaml")

	// Clean up
	clientset, err := k8s.GetKubernetesClientFromOptionsE(t, defaultKubectlOptions)
	require.NoError(t, err)
	clientset.CoreV1().Secrets(defaultKubectlOptions.Namespace).Delete(context.Background(), "vault-unseal-keys", metav1.DeleteOptions{})
}

func prepareResources(vaultVersion string, crd string) ([][]byte, error) {
	// Read file into byte slice
	data, err := os.ReadFile(crd)
	if err != nil {
		return nil, err
	}

	// Decode byte slices into individual yaml documents
	var documents []interface{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Slice of the individual resources found in the file
	for {
		var v interface{}
		err := dec.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		documents = append(documents, v)
	}

	// Iterate on yaml documents and change namespace name where necessary
	var resources [][]byte
	for _, v := range documents {
		if v.(map[string]interface{})["kind"] == "Vault" {
			if i, ok := v.(map[string]interface{})["spec"].(map[string]interface{}); ok {
				if i["image"] != "" {
					i["image"] = "vault:" + vaultVersion
				}
			}
		}

		resource, err := yaml.Marshal(v)
		if err != nil {
			return nil, err
		}

		resources = append(resources, resource)
	}
	return resources, nil
}

func waitUntilPodsCreated(t *testing.T, options *k8s.KubectlOptions, deploymentName string, retries int, sleepBetweenRetries time.Duration) []corev1.Pod {
	statusMsg := fmt.Sprintf("Wait for Pod(s) %s to be created.", deploymentName)
	podsInterface, err := retry.DoWithRetryInterfaceE(
		t,
		statusMsg,
		retries,
		sleepBetweenRetries,
		func() (interface{}, error) {
			pods := k8s.ListPods(t, options, metav1.ListOptions{LabelSelector: labels.Set(map[string]string{"app.kubernetes.io/name": deploymentName}).String()})
			if len(pods) == 0 {
				return nil, errors.New("Pod(s) not created yet")
			}
			return pods, nil
		},
	)
	if err != nil {
		logger.Logf(t, "Timedout waiting for Pod(s) to be created: %s", err)
		require.NoError(t, err)
	}
	logger.Logf(t, "Pod(s) created")

	var createdPods []corev1.Pod
	if pods, ok := podsInterface.([]corev1.Pod); ok {
		createdPods = pods
	}

	return createdPods
}
