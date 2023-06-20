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
	"os"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
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
