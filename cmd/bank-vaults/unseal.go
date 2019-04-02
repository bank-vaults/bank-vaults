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
	"os"
	"time"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const cfgUnsealPeriod = "unseal-period"
const cfgInit = "init"
const cfgOnce = "once"

type unsealCfg struct {
	unsealPeriod time.Duration
	proceedInit  bool
	runOnce      bool
}

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseals Vault with with unseal keys stored in one of the supported Cloud Provider options.",
	Long: `It will continuously attempt to unseal the target Vault instance, by retrieving unseal keys
from one of the followings:
- Google Cloud KMS keyring (backed by GCS)
- AWS KMS keyring (backed by S3)
- Azure Key Vault
- Alibaba KMS (backed by OSS)
- Kubernetes Secrets (should be used only for development purposes)`,
	Run: func(cmd *cobra.Command, args []string) {
		appConfig.BindPFlag(cfgUnsealPeriod, cmd.PersistentFlags().Lookup(cfgUnsealPeriod))
		appConfig.BindPFlag(cfgInit, cmd.PersistentFlags().Lookup(cfgInit))
		appConfig.BindPFlag(cfgOnce, cmd.PersistentFlags().Lookup(cfgOnce))
		appConfig.BindPFlag(cfgInitRootToken, cmd.PersistentFlags().Lookup(cfgInitRootToken))
		appConfig.BindPFlag(cfgStoreRootToken, cmd.PersistentFlags().Lookup(cfgStoreRootToken))

		var unsealConfig unsealCfg

		unsealConfig.unsealPeriod = appConfig.GetDuration(cfgUnsealPeriod)
		unsealConfig.proceedInit = appConfig.GetBool(cfgInit)
		unsealConfig.runOnce = appConfig.GetBool(cfgOnce)

		store, err := kvStoreForConfig(appConfig)

		if err != nil {
			logrus.Fatalf("error creating kv store: %s", err.Error())
		}

		cl, err := api.NewClient(nil)

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

		metrics := prometheusExporter{Vault: v, Mode: "unseal"}
		go metrics.Run()

		for {
			unseal(unsealConfig, v)

			// wait unsealPeriod before trying again
			time.Sleep(unsealConfig.unsealPeriod)
		}
	},
}

func unseal(unsealConfig unsealCfg, v vault.Vault) {
	if unsealConfig.proceedInit {
		logrus.Info("initializing vault...")
		if err := v.Init(); err != nil {
			logrus.Fatalf("error initializing vault: %s", err.Error())
		} else {
			unsealConfig.proceedInit = false
		}
	}

	logrus.Debug("checking if vault is sealed...")
	sealed, err := v.Sealed()
	if err != nil {
		logrus.Errorf("error checking if vault is sealed: %s", err.Error())
		exitIfNecessary(unsealConfig, 1)
		return
	}

	// If vault is not sealed, we stop here and wait another unsealPeriod
	if !sealed {
		logrus.Debug("vault is not sealed")
		exitIfNecessary(unsealConfig, 0)
		return
	}

	logrus.Info("vault is sealed, unsealing")

	if err = v.Unseal(); err != nil {
		logrus.Errorf("error unsealing vault: %s", err.Error())
		exitIfNecessary(unsealConfig, 1)
		return
	}

	logrus.Info("successfully unsealed vault")

	exitIfNecessary(unsealConfig, 0)
}

func exitIfNecessary(unsealConfig unsealCfg, code int) {
	if unsealConfig.runOnce {
		os.Exit(code)
	}
}

func init() {
	unsealCmd.PersistentFlags().Duration(cfgUnsealPeriod, time.Second*5, "How often to attempt to unseal the vault instance")
	unsealCmd.PersistentFlags().Bool(cfgInit, false, "Initialize vault instance if not yet initialized")
	unsealCmd.PersistentFlags().Bool(cfgOnce, false, "Run unseal only once")
	unsealCmd.PersistentFlags().String(cfgInitRootToken, "", "Root token for the new vault cluster (only if -init=true)")
	unsealCmd.PersistentFlags().Bool(cfgStoreRootToken, true, "Should the root token be stored in the key store (only if -init=true)")

	rootCmd.AddCommand(unsealCmd)
}
