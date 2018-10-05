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
	"bytes"
	"path"
	"path/filepath"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
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
	Short: "Configures a Vault based on a YAML/JSON configuration file",
	Long: `This configuration is an extension to what is available through the Vault configuration:
			https://www.vaultproject.io/docs/configuration/index.html. With this it is possible to
			configure secret engines, auth methods, etc...`,
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

		parseConfiguration := func() {
			configTemplate := template.Must(
				template.New(path.Base(vaultConfigFile)).
					Funcs(sprig.TxtFuncMap()).
					Delims("${", "}").
					ParseFiles(vaultConfigFile))

			buffer := bytes.NewBuffer(nil)

			err := configTemplate.Execute(buffer, nil)
			if err != nil {
				logrus.Fatalf("error executing vault config template: %s", err.Error())
			}

			err = viper.ReadConfig(buffer)
			if err != nil {
				logrus.Fatalf("error reading vault config file: %s", err.Error())
			}
		}

		c := make(chan fsnotify.Event, 1)
		viper.SetConfigFile(vaultConfigFile)
		go func() {
			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				logrus.Fatal(err)
			}
			defer watcher.Close()

			// we have to watch the entire directory to pick up renames/atomic saves in a cross-platform way
			configFile := filepath.Clean(vaultConfigFile)
			configDir, _ := filepath.Split(configFile)

			done := make(chan bool)
			go func() {
				for {
					select {
					case event := <-watcher.Events:
						// we only care about the config file or the ConfigMap directory (if in Kubernetes)
						if filepath.Clean(event.Name) == configFile || filepath.Base(event.Name) == "..data" {
							if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
								err := viper.ReadInConfig()
								if err != nil {
									logrus.Println("error:", err)
								}
								parseConfiguration()
								c <- event
							}
						}
					case err := <-watcher.Errors:
						logrus.Println("error:", err)
					}
				}
			}()

			watcher.Add(configDir)
			<-done
		}()
		parseConfiguration()

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

					// If vault is sealed, we stop here and wait another unsealPeriod
					if sealed {
						logrus.Infof("vault is sealed, waiting %s before trying again...", unsealConfig.unsealPeriod)
						time.Sleep(unsealConfig.unsealPeriod)
						continue
					}

					logrus.Infof("checking if vault is active...")
					active, err := v.Active()
					if err != nil {
						logrus.Errorf("error checking if vault is active: %s, waiting %s before trying again...", err.Error(), 5*time.Second)
						time.Sleep(5 * time.Second)
						continue
					}

					// If vault is not active, we stop here and wait another 5 seconds
					if !active {
						logrus.Infof("vault is not active, waiting %s before trying again...", 5*time.Second)
						time.Sleep(5 * time.Second)
						continue
					}

					logrus.Infof("vault is unsealed and active, configuring...")

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
	configureCmd.PersistentFlags().String(cfgVaultConfigFile, vault.DefaultConfigFile, "The filename of the YAML/JSON Vault configuration")

	rootCmd.AddCommand(configureCmd)
}
