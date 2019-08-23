// Copyright © 2018 Banzai Cloud
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
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const cfgInitRootToken = "init-root-token"
const cfgStoreRootToken = "store-root-token"
const cfgPreFlightChecks = "pre-flight-checks"

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialise the target Vault instance",
	Long: `This command will verify the Cloud KMS service is accessible, then
run "vault init" against the target Vault instance, before encrypting and
storing the keys in the Cloud KMS keyring.

It will not unseal the Vault instance after initialising.`,
	Run: func(cmd *cobra.Command, args []string) {
		appConfig.BindPFlag(cfgInitRootToken, cmd.PersistentFlags().Lookup(cfgInitRootToken))
		appConfig.BindPFlag(cfgStoreRootToken, cmd.PersistentFlags().Lookup(cfgStoreRootToken))
		appConfig.BindPFlag(cfgPreFlightChecks, cmd.PersistentFlags().Lookup(cfgPreFlightChecks))

		store, err := kvStoreForConfig(appConfig)
		if err != nil {
			logrus.Fatalf("error creating kv store: %s", err.Error())
		}

		cl, err := vault.NewRawClient()
		if err != nil {
			logrus.Fatalf("error connecting to vault: %s", err.Error())
		}

		vaultConfig, err := vaultConfigForConfig(appConfig)
		if err != nil {
			logrus.Fatalf("error building vault config: %s", err.Error())
		}

		v, err := vault.New(store, cl, vaultConfig)
		if err != nil {
			logrus.Fatalf("error creating vault helper: %s", err.Error())
		}

		if err = v.Init(); err != nil {
			logrus.Fatalf("error initialising vault: %s", err.Error())
		}
	},
}

func init() {
	initCmd.PersistentFlags().String(cfgInitRootToken, "", "root token for the new vault cluster")
	initCmd.PersistentFlags().Bool(cfgStoreRootToken, true, "should the root token be stored in the key store")
	initCmd.PersistentFlags().Bool(cfgPreFlightChecks, true, "should the key store be tested first to validate access rights")

	rootCmd.AddCommand(initCmd)
}
