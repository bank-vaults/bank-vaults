// Copyright © 2023 Banzai Cloud
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

package cmd

import (
	"context"
	"os"

	"github.com/banzaicloud/bank-vaults/internal/collector"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// deployCmd represents the deploy command
var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Sync secrets of a deployment",
	//	Long: `A longer description that spans multiple lines and likely contains examples
	// and usage of using your command. For example:
	//
	// Cobra is a CLI library for Go that empowers applications.
	// This application is a tool to generate the needed files
	// to quickly create a Cobra application.`,
	Run: syncDeployment,
}

func init() {
	rootCmd.AddCommand(deployCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deployCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
}

func syncDeployment(cmd *cobra.Command, args []string) {
	var logger *logrus.Entry
	{
		l := logrus.New()
		l.SetLevel(logrus.DebugLevel)
		logger = l.WithField("app", "vault-secrets-syncer")
	}

	if len(args) != 1 {
		logger.Errorln("You must specify one argument")
		os.Exit(1)
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: clientcmd.RecommendedHomeFile},
		&clientcmd.ConfigOverrides{
			CurrentContext: "",
		}).ClientConfig()
	if err != nil {
		logger.Errorln(err)
		os.Exit(1)
	}

	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Errorln(err)
		os.Exit(1)
	}

	deployment, err := k8sClient.AppsV1().Deployments(cmd.Flag("namespace").Value.String()).Get(context.Background(), args[0], metav1.GetOptions{})
	if err != nil {
		logger.Errorln(err)
		os.Exit(1)
	}

	if deployment.GetAnnotations()["alpha.vault.security.banzaicloud.io/reload-on-secret-change"] != "true" {
		logger.Infoln("Reload on secret change is not enabled on this resource")
		os.Exit(0)
	}

	// Create a map to store used Vault secrets and their versions
	vaultSecrets := make(map[string]int)

	// 1. Collect environment variables that need to be injected from Vault
	err = collector.CollectDeploymentSecretsFromEnv(deployment, vaultSecrets)
	if err != nil {
		logger.Errorln(err)
		os.Exit(1)
	}
	logger.Debug("Collecting secrets from envs done")

	// 2. Collect secrets from vault.security.banzaicloud.io/vault-env-from-path annnotation
	collector.CollectSecretsFromAnnotation(deployment, vaultSecrets)
	logger.Debug("Collecting secrets from annotations done")

	if len(vaultSecrets) == 0 {
		logger.Infof("No secrets found for deployment %s.%s", deployment.Namespace, deployment.Name)
		os.Exit(0)
	}

	// Create a Vault client and get the current version of the secrets
	vaultClient, err := vault.NewClient("default")
	if err != nil {
		logger.Errorln(err)
		os.Exit(1)
	}
	defer vaultClient.Close()

	for secretPath := range vaultSecrets {
		currentVersion, err := collector.GetSecretVersionFromVault(vaultClient, secretPath)
		if err != nil {
			logger.Errorln(err)
			logger.Warnln(`Did you run the following commands?

				kubectl port-forward vault-0 8200:8200

				export VAULT_TOKEN=$(kubectl get secrets vault-unseal-keys -o jsonpath={.data.vault-root} | base64 --decode)

				kubectl get secret vault-tls -o jsonpath="{.data.ca\.crt}" | base64 --decode > $PWD/vault-ca.crt
				export VAULT_CACERT=$PWD/vault-ca.crt

				export VAULT_ADDR=https://127.0.0.1:8200`)
			os.Exit(1)
		}
		vaultSecrets[secretPath] = currentVersion
	}
	logger.Debugf("vaultSecrets: %+v", vaultSecrets)

	logger.Error("Syncing secrets from deployment failed")
	os.Exit(1)
}
