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
	"fmt"
	"log/slog"
	"os"

	"github.com/bank-vaults/vault-sdk/vault"
	"github.com/spf13/cobra"

	internalVault "github.com/bank-vaults/bank-vaults/internal/vault"
)

const (
	cfgInitRootToken   = "init-root-token"
	cfgStoreRootToken  = "store-root-token"
	cfgPreFlightChecks = "pre-flight-checks"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the target Vault instance",
	Long: `This command will verify the backend service is accessible, then
run "vault init" against the target Vault instance, before encrypting and
storing the keys in the given backend.

It will not unseal the Vault instance after initializing.`,
	Run: func(_ *cobra.Command, _ []string) {
		store, err := kvStoreForConfig(c)
		if err != nil {
			slog.Error(fmt.Sprintf("error creating kv store: %s", err.Error()))
			os.Exit(1)
		}

		cl, err := vault.NewRawClient()
		if err != nil {
			slog.Error(fmt.Sprintf("error connecting to vault: %s", err.Error()))
			os.Exit(1)
		}

		v, err := internalVault.New(store, cl, vaultConfigForConfig(c))
		if err != nil {
			slog.Error(fmt.Sprintf("error creating vault helper: %s", err.Error()))
			os.Exit(1)
		}

		if err = v.Init(); err != nil {
			slog.Error(fmt.Sprintf("error initializing vault: %s", err.Error()))
			os.Exit(1)
		}
	},
}

func init() {
	configStringVar(initCmd, cfgInitRootToken, "", "root token for the new vault cluster")
	configBoolVar(rootCmd, cfgStoreRootToken, true, "should the root token be stored in the key store")
	configBoolVar(rootCmd, cfgPreFlightChecks, true, "should the key store be tested first to validate access rights")

	rootCmd.AddCommand(initCmd)
}
