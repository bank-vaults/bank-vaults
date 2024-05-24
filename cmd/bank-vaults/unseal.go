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
	"time"

	"github.com/bank-vaults/vault-sdk/vault"
	"github.com/spf13/cobra"

	internalVault "github.com/bank-vaults/bank-vaults/internal/vault"
)

const (
	cfgInit              = "init"
	cfgAuto              = "auto"
	cfgRaft              = "raft"
	cfgRaftLeaderAddress = "raft-leader-address"
	cfgRaftSecondary     = "raft-secondary"
	cfgRaftHAStorage     = "raft-ha-storage"
)

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
	Short: "Unseals Vault with unseal keys stored in one of the supported Cloud Provider options.",
	Long: `It will continuously attempt to unseal the target Vault instance, by retrieving unseal keys
from one of the following:
- Google Cloud KMS keyring (backed by GCS)
- AWS KMS keyring (backed by S3)
- Azure Key Vault
- Alibaba KMS (backed by OSS)
- Kubernetes Secrets (should be used only for development purposes)`,
	Run: func(_ *cobra.Command, _ []string) {
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

		metrics := prometheusExporter{Vault: v, Mode: "unseal"}
		go func() {
			err := metrics.Run()
			if err != nil {
				slog.Error(fmt.Sprintf("error creating prometheus exporter: %s", err.Error()))
				os.Exit(1)
			}
		}()

		if unsealConfig.proceedInit && unsealConfig.raft {
			slog.Info("joining leader vault...")

			initialized, err := v.RaftInitialized()
			if err != nil {
				sealed, sErr := v.Sealed()
				if sErr != nil || sealed {
					slog.Error(fmt.Sprintf("error checking if vault is initialized: %s", err.Error()))
					os.Exit(1)
				}
				slog.Warn(fmt.Sprintf("error checking if vault is initialized, but vault is unsealed so continuing: %s", err.Error()))
			}

			// If this is the first instance we have to init it, this happens once in the clusters lifetime
			if !initialized && !unsealConfig.raftSecondary {
				slog.Info("initializing vault...")
				if err := v.Init(); err != nil {
					slog.Error(fmt.Sprintf("error initializing vault: %s", err.Error()))
					os.Exit(1)
				}
			} else {
				slog.Info("joining raft cluster...")
				if err := v.RaftJoin(unsealConfig.raftLeaderAddress); err != nil {
					slog.Error(fmt.Sprintf("error joining leader vault: %s", err.Error()))
					os.Exit(1)
				}
			}
		} else if unsealConfig.proceedInit {
			slog.Info("initializing vault...")
			if err := v.Init(); err != nil {
				slog.Error(fmt.Sprintf("error initializing vault: %s", err.Error()))
				os.Exit(1)
			}
		}

		raftEstablished := false
		for {
			if !unsealConfig.auto {
				unseal(unsealConfig, v)
			}

			if unsealConfig.raftHAStorage && !raftEstablished {
				raftEstablished = raftJoin(v)
			}

			// wait unsealPeriod before trying again
			time.Sleep(unsealConfig.unsealPeriod)
		}
	},
}

func unseal(unsealConfig unsealCfg, v internalVault.Vault) {
	slog.Debug("checking if vault is sealed...")
	sealed, err := v.Sealed()
	if err != nil {
		slog.Error(fmt.Sprintf("error checking if vault is sealed: %s", err.Error()))
		exitIfNecessary(unsealConfig, 1)
		return
	}

	// If vault is not sealed, we stop here and wait for another unsealPeriod
	if !sealed {
		slog.Debug("vault is not sealed")
		exitIfNecessary(unsealConfig, 0)
		return
	}

	slog.Info("vault is sealed, unsealing")

	if err = v.Unseal(); err != nil {
		slog.Error(fmt.Sprintf("error unsealing vault: %s", err.Error()))
		exitIfNecessary(unsealConfig, 1)
		return
	}

	slog.Info("successfully unsealed vault")

	exitIfNecessary(unsealConfig, 0)
}

func raftJoin(v internalVault.Vault) bool {
	leaderAddress, err := v.LeaderAddress()
	if err != nil {
		slog.Error(fmt.Sprintf("error checking leader vault: %s", err.Error()))
		return false
	}

	// If this instance can't tell the leaderAddress, it is not part of the cluster,
	// so we should ask it join.
	if leaderAddress == "" {
		if err = v.RaftJoin(""); err != nil {
			slog.Error(fmt.Sprintf("error joining leader vault: %s", err.Error()))
			return false
		}
	}

	return true
}

func exitIfNecessary(unsealConfig unsealCfg, code int) {
	if unsealConfig.runOnce {
		os.Exit(code)
	}
}

func init() {
	configBoolVar(unsealCmd, cfgInit, false, "Initialize vault instance if not yet initialized")
	configBoolVar(unsealCmd, cfgRaft, false, "Join leader vault instance in raft mode")
	configStringVar(unsealCmd, cfgRaftLeaderAddress, "", "Address of leader vault instance in raft mode")
	configBoolVar(unsealCmd, cfgRaftSecondary, false, "This instance should always join a raft leader")
	configBoolVar(unsealCmd, cfgRaftHAStorage, false, "Join leader vault instance in raft HA storage mode")
	configStringVar(unsealCmd, cfgInitRootToken, "", "Root token for the new vault cluster (only if -init=true)")
	configBoolVar(unsealCmd, cfgPreFlightChecks, true, "should the key store be tested first to validate access rights")
	configBoolVar(unsealCmd, cfgAuto, false, "Run in auto-unseal mode")

	rootCmd.AddCommand(unsealCmd)
}
