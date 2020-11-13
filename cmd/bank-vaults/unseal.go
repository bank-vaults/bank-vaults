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

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	internalVault "github.com/banzaicloud/bank-vaults/internal/vault"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

const cfgUnsealPeriod = "unseal-period"
const cfgInit = "init"
const cfgOnce = "once"
const cfgAuto = "auto"
const cfgRaft = "raft"
const cfgRaftLeaderAddress = "raft-leader-address"
const cfgRaftSecondary = "raft-secondary"
const cfgRaftHAStorage = "raft-ha-storage"

type unsealCfg struct {
	unsealPeriod      time.Duration
	proceedInit       bool
	runOnce           bool
	auto              bool
	raft              bool
	raftLeaderAddress string
	raftSecondary     bool
	raftHAStorage     bool
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
		var unsealConfig unsealCfg

		unsealConfig.unsealPeriod = c.GetDuration(cfgUnsealPeriod)
		unsealConfig.proceedInit = c.GetBool(cfgInit)
		unsealConfig.runOnce = c.GetBool(cfgOnce)
		unsealConfig.auto = c.GetBool(cfgAuto)
		unsealConfig.raft = c.GetBool(cfgRaft)
		unsealConfig.raftLeaderAddress = c.GetString(cfgRaftLeaderAddress)
		unsealConfig.raftSecondary = c.GetBool(cfgRaftSecondary)
		unsealConfig.raftHAStorage = c.GetBool(cfgRaftHAStorage)

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

		metrics := prometheusExporter{Vault: v, Mode: "unseal"}
		go func() {
			err := metrics.Run()
			if err != nil {
				logrus.Fatalf("error creating prometheus exporter: %s", err.Error())
			}
		}()

		if unsealConfig.proceedInit && unsealConfig.raft {
			logrus.Info("joining leader vault...")

			initialized, err := v.RaftInitialized()
			if err != nil {
				sealed, sErr := v.Sealed()
				if sErr != nil || sealed {
					logrus.Fatalf("error checking if vault is initialized: %s", err.Error())
				}
				logrus.Warnf("error checking if vault is initialized, but vault is unsealed so continuing: %s", err.Error())
			}

			// If this is the first instance we have to init it, this happens once in the clusters lifetime
			if !initialized && !unsealConfig.raftSecondary {
				logrus.Info("initializing vault...")
				if err := v.Init(); err != nil {
					logrus.Fatalf("error initializing vault: %s", err.Error())
				}
			} else {
				logrus.Info("joining raft cluster...")
				if err := v.RaftJoin(unsealConfig.raftLeaderAddress); err != nil {
					logrus.Fatalf("error joining leader vault: %s", err.Error())
				}
			}
		} else if unsealConfig.proceedInit {
			logrus.Info("initializing vault...")
			if err := v.Init(); err != nil {
				logrus.Fatalf("error initializing vault: %s", err.Error())
			}
		}

		for {
			if !unsealConfig.auto {
				unseal(unsealConfig, v)
			}

			// wait unsealPeriod before trying again
			time.Sleep(unsealConfig.unsealPeriod)
		}
	},
}

func unseal(unsealConfig unsealCfg, v internalVault.Vault) {
	logrus.Debug("checking if vault is sealed...")
	sealed, err := v.Sealed()
	if err != nil {
		logrus.Errorf("error checking if vault is sealed: %s", err.Error())
		exitIfNecessary(unsealConfig, 1)
		return
	}

	// If vault is not sealed, we stop here and wait for another unsealPeriod
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

	if unsealConfig.raftHAStorage {
		if err = v.RaftJoin(""); err != nil {
			logrus.Fatalf("error joining leader vault: %s", err.Error())
			return
		}

		logrus.Info("successfully joined raft")
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
	configDurationVar(unsealCmd, cfgUnsealPeriod, time.Second*5, "How often to attempt to unseal the vault instance")
	configBoolVar(unsealCmd, cfgInit, false, "Initialize vault instance if not yet initialized")
	configBoolVar(unsealCmd, cfgOnce, false, "Run unseal only once")
	configBoolVar(unsealCmd, cfgRaft, false, "Join leader vault instance in raft mode")
	configStringVar(unsealCmd, cfgRaftLeaderAddress, "", "Address of leader vault instance in raft mode")
	configBoolVar(unsealCmd, cfgRaftSecondary, false, "This instance should always join a raft leader")
	configBoolVar(unsealCmd, cfgRaftHAStorage, false, "Join leader vault instance in raft HA storage mode")
	configStringVar(unsealCmd, cfgInitRootToken, "", "Root token for the new vault cluster (only if -init=true)")
	configBoolVar(unsealCmd, cfgStoreRootToken, true, "Should the root token be stored in the key store (only if -init=true)")
	configBoolVar(unsealCmd, cfgPreFlightChecks, true, "should the key store be tested first to validate access rights")
	configBoolVar(unsealCmd, cfgAuto, false, "Run in auto-unseal mode")

	rootCmd.AddCommand(unsealCmd)
}
