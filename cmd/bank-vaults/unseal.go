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
const cfgStepDownActive = "step-down-active"
const cfgActiveNodeAddress = "active-node-address"

type unsealCfg struct {
	unsealPeriod      time.Duration
	proceedInit       bool
	runOnce           bool
	stepDownActive    bool
	activeNodeAddress string
}

var unsealConfig unsealCfg

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseals Vault with with unseal keys stored in one of the supported Cloud Provider options.",
	Long: `It will continuously attempt to unseal the target Vault instance, by retrieving unseal keys
from one of the followings:
- Google Cloud KMS keyring (backed by GCS)
- AWS KMS keyring (backed by S3)
- Azure Key Vault
- Kubernetes Secrets (should be used only for development purposes)`,
	Run: func(cmd *cobra.Command, args []string) {
		appConfig.BindPFlag(cfgUnsealPeriod, cmd.PersistentFlags().Lookup(cfgUnsealPeriod))
		appConfig.BindPFlag(cfgInit, cmd.PersistentFlags().Lookup(cfgInit))
		appConfig.BindPFlag(cfgOnce, cmd.PersistentFlags().Lookup(cfgOnce))
		appConfig.BindPFlag(cfgInitRootToken, cmd.PersistentFlags().Lookup(cfgInitRootToken))
		appConfig.BindPFlag(cfgStoreRootToken, cmd.PersistentFlags().Lookup(cfgStoreRootToken))
		appConfig.BindPFlag(cfgStepDownActive, cmd.PersistentFlags().Lookup(cfgStepDownActive))
		appConfig.BindPFlag(cfgActiveNodeAddress, cmd.PersistentFlags().Lookup(cfgActiveNodeAddress))
		unsealConfig.unsealPeriod = appConfig.GetDuration(cfgUnsealPeriod)
		unsealConfig.proceedInit = appConfig.GetBool(cfgInit)
		unsealConfig.runOnce = appConfig.GetBool(cfgOnce)
		unsealConfig.stepDownActive = appConfig.GetBool(cfgStepDownActive)
		unsealConfig.activeNodeAddress = appConfig.GetString(cfgActiveNodeAddress)

		if unsealConfig.stepDownActive && unsealConfig.activeNodeAddress == "" {
			logrus.Fatalf("'%s' should be also set if '%s' is enabled", cfgActiveNodeAddress, cfgStepDownActive)
		}

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

		metrics := prometheusExporter{Vault: v}
		go metrics.Run()

		for {
			func() {
				if unsealConfig.proceedInit {
					logrus.Infof("initializing vault...")
					if err = v.Init(); err != nil {
						logrus.Fatalf("error initializing vault: %s", err.Error())
					} else {
						unsealConfig.proceedInit = false
					}
				}

				logrus.Infof("checking if vault is sealed...")
				sealed, err := v.Sealed()
				if err != nil {
					logrus.Errorf("error checking if vault is sealed: %s", err.Error())
					exitIfNecessary(1)
					return
				}

				logrus.Infof("vault sealed: %t", sealed)

				// If vault is not sealed, we stop here and wait another unsealPeriod
				if !sealed {
					exitIfNecessary(0)
					return
				}

				if err = v.Unseal(); err != nil {
					logrus.Errorf("error unsealing vault: %s", err.Error())
					exitIfNecessary(1)
					return
				}

				logrus.Infof("successfully unsealed vault")

				if unsealConfig.stepDownActive {
					err = v.StepDownActive(unsealConfig.activeNodeAddress)
					if err != nil {
						logrus.Warnf("failed to tell active instance to step down: %s", err.Error())
					}
				}

				exitIfNecessary(0)
			}()

			// wait unsealPeriod before trying again
			time.Sleep(unsealConfig.unsealPeriod)
		}
	},
}

func exitIfNecessary(code int) {
	if unsealConfig.runOnce {
		os.Exit(code)
	}
}

func init() {
	unsealCmd.PersistentFlags().Duration(cfgUnsealPeriod, time.Second*30, "How often to attempt to unseal the vault instance")
	unsealCmd.PersistentFlags().Bool(cfgInit, false, "Initialize vault instantce if not yet initialized")
	unsealCmd.PersistentFlags().Bool(cfgOnce, false, "Run unseal only once")
	unsealCmd.PersistentFlags().String(cfgInitRootToken, "", "root token for the new vault cluster (only if -init=true)")
	unsealCmd.PersistentFlags().Bool(cfgStoreRootToken, true, "should the root token be stored in the key store (only if -init=true)")
	unsealCmd.PersistentFlags().Bool(cfgStepDownActive, false, "should the active node be asked to step down")
	unsealCmd.PersistentFlags().String(cfgActiveNodeAddress, "", "the address of the active Vault node")

	rootCmd.AddCommand(unsealCmd)
}
