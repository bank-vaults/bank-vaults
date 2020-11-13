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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	internalVault "github.com/banzaicloud/bank-vaults/internal/vault"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

const cfgInitRootToken = "init-root-token"
const cfgStoreRootToken = "store-root-token"
const cfgPreFlightChecks = "pre-flight-checks"

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialise the target Vault instance",
	Long: `This command will verify the backend service is accessible, then
run "vault init" against the target Vault instance, before encrypting and
storing the keys in the given backend.

It will not unseal the Vault instance after initialising.`,
	Run: func(cmd *cobra.Command, args []string) {
		store, err := kvStoreForConfig(c)
		if err != nil {
			logrus.Fatalf("error creating kv store: %s", err.Error())
		}

		cl, err := vault.NewRawClient()
		if err != nil {
			logrus.Fatalf("error connecting to vault: %s", err.Error())
		}

		v, err := internalVault.New(store, cl, vaultConfigForConfig(c))
		if err != nil {
			logrus.Fatalf("error creating vault helper: %s", err.Error())
		}

		if err = v.Init(); err != nil {
			logrus.Fatalf("error initialising vault: %s", err.Error())
		}
	},
}

func init() {
	configStringVar(initCmd, cfgInitRootToken, "", "root token for the new vault cluster")
	configBoolVar(rootCmd, cfgStoreRootToken, true, "should the root token be stored in the key store")
	configBoolVar(rootCmd, cfgPreFlightChecks, true, "should the key store be tested first to validate access rights")

	rootCmd.AddCommand(initCmd)
}
