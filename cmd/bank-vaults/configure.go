package main

import (
	"time"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const cfgVaultConfigFile = "vault-config-file"

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configures a Hashicorp Vault based on a YAML/JSON configuration file",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command.`,
	Run: func(cmd *cobra.Command, args []string) {
		appConfig.BindPFlag(cfgUnsealPeriod, cmd.PersistentFlags().Lookup(cfgUnsealPeriod))
		appConfig.BindPFlag(cfgVaultConfigFile, cmd.PersistentFlags().Lookup(cfgVaultConfigFile))

		unsealConfig.unsealPeriod = appConfig.GetDuration(cfgUnsealPeriod)
		vaultConfigFile := appConfig.GetString(cfgVaultConfigFile)

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

		c := make(chan fsnotify.Event, 1)
		viper.SetConfigFile(vaultConfigFile)
		viper.WatchConfig()
		viper.OnConfigChange(func(e fsnotify.Event) {
			c <- e
		})
		err = viper.ReadInConfig()
		if err != nil {
			logrus.Fatalf("error reading vault config file: %s", err.Error())
		}

		c <- fsnotify.Event{Name: "Initial", Op: fsnotify.Create}

		for e := range c {
			logrus.Infoln("New config file change", e.String())
			func() {
				for {
					logrus.Infof("checking if vault is sealed...")
					sealed, err := v.Sealed()
					if err != nil {
						logrus.Errorf("error checking if vault is sealed: %s, waiting %s before trying again...", err.Error(), unsealConfig.unsealPeriod)
						time.Sleep(unsealConfig.unsealPeriod)
						continue
					}

					// If vault is not sealed, we stop here and wait another unsealPeriod
					if sealed {
						logrus.Infof("vault is sealed, waiting %s before trying again...", unsealConfig.unsealPeriod)
						time.Sleep(unsealConfig.unsealPeriod)
						continue
					}
					logrus.Infof("vault is not sealed, configuring...")

					if err = v.Configure(); err != nil {
						logrus.Errorf("error configuring vault: %s", err.Error())
						return
					}

					logrus.Infof("successfully configured vault")
					return
				}
			}()
		}
	},
}

func init() {
	configureCmd.PersistentFlags().Duration(cfgUnsealPeriod, time.Second*30, "How often to attempt to unseal the Vault instance")
	configureCmd.PersistentFlags().String(cfgVaultConfigFile, "vault-config.yml", "The filename of the YAML/JSON Vault configuraton")

	rootCmd.AddCommand(configureCmd)
}
