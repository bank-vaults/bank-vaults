// Copyright © 2019 Banzai Cloud
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
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/banzaicloud/bank-vaults/pkg/vault"
	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cfgVaultConfigFile = "vault-config-file"
	cfgFatal           = "fatal"
)

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configures a Vault based on a YAML/JSON configuration file",
	Long: `This configuration is an extension to what is available through the Vault configuration:
			https://www.vaultproject.io/docs/configuration/index.html. With this it is possible to
			configure secret engines, auth methods, etc...`,
	Run: func(cmd *cobra.Command, args []string) {
		appConfig.BindPFlag(cfgOnce, cmd.PersistentFlags().Lookup(cfgOnce))
		appConfig.BindPFlag(cfgFatal, cmd.PersistentFlags().Lookup(cfgFatal))
		appConfig.BindPFlag(cfgUnsealPeriod, cmd.PersistentFlags().Lookup(cfgUnsealPeriod))
		appConfig.BindPFlag(cfgVaultConfigFile, cmd.PersistentFlags().Lookup(cfgVaultConfigFile))

		var unsealConfig unsealCfg

		runOnce := appConfig.GetBool(cfgOnce)
		errorFatal := appConfig.GetBool(cfgFatal)
		unsealConfig.unsealPeriod = appConfig.GetDuration(cfgUnsealPeriod)
		vaultConfigFiles := appConfig.GetStringSlice(cfgVaultConfigFile)

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

		metrics := prometheusExporter{Vault: v, Mode: "configure"}
		go metrics.Run()

		configurations := make(chan *viper.Viper, len(vaultConfigFiles))

		for i, vaultConfigFile := range vaultConfigFiles {
			vaultConfigFiles[i] = filepath.Clean(vaultConfigFile)
			configurations <- parseConfiguration(vaultConfigFile)
		}

		if !runOnce {
			go watchConfigurations(vaultConfigFiles, configurations)
		} else {
			close(configurations)
		}

		for config := range configurations {

			logrus.Infoln("config file has changed:", config.ConfigFileUsed())

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

					logrus.Info("vault is unsealed, configuring...")

					if err = v.Configure(config); err != nil {
						logrus.Errorf("error configuring vault: %s", err.Error())
						if errorFatal {
							os.Exit(1)
						}
						failedConfigurationsCount++
						return
					}

					successfulConfigurationsCount++
					logrus.Info("successfully configured vault")
					return
				}
			}()
		}
	},
}

func stringInSlice(match string, list []string) bool {
	for _, item := range list {
		if item == match {
			return true
		}
	}
	return false
}

func watchConfigurations(vaultConfigFiles []string, configurations chan *viper.Viper) {
	watcher, err := fsnotify.NewWatcher()
	// Map used to match on kubernetes ..data to files inside of directory
	configFileDirs := make(map[string][]string)

	if err != nil {
		logrus.Fatal(err)
	}
	defer watcher.Close()

	for _, vaultConfigFile := range vaultConfigFiles {
		// we have to watch the entire directory to pick up renames/atomic saves in a cross-platform way
		configFile := vaultConfigFile
		configDir, _ := filepath.Split(configFile)
		configDirTrimmed := strings.TrimRight(configDir, "/")

		files := make([]string, 0)
		if len(configFileDirs[configDirTrimmed]) != 0 {
			files = configFileDirs[configDirTrimmed]
		}
		files = append(files, configFile)

		configFileDirs[configDirTrimmed] = files

		logrus.Infof("Watching Directory for changes: %s", configDir)
		watcher.Add(configDir)
	}

	for {
		select {
		case event := <-watcher.Events:
			// we only care about the config file or the ConfigMap directory (if in Kubernetes)
			// For real Files we only need to watch thw WRITE Event # TODO: Sometimes it triggers 2 WRITE when a file is edited and saved
			// For Kubernetes configMaps we need to watch for CREATE on the "..data"
			if event.Op&fsnotify.Write == fsnotify.Write && stringInSlice(filepath.Clean(event.Name), vaultConfigFiles) {
				logrus.Infof("File has changed: %s", event.Name)
				configurations <- parseConfiguration(filepath.Clean(event.Name))
			} else if event.Op&fsnotify.Create == fsnotify.Create && filepath.Base(event.Name) == "..data" {
				for _, fileName := range configFileDirs[filepath.Dir(event.Name)] {
					logrus.Infof("ConfgMap has changed, reparsing: %s", fileName)
					configurations <- parseConfiguration(fileName)
				}
			}
		case err := <-watcher.Errors:
			logrus.Errorf("Watcher Event Error: %s", err.Error())
		}
	}

}

func parseConfiguration(vaultConfigFile string) *viper.Viper {

	config := viper.New()

	templateName := filepath.Base(vaultConfigFile)

	configTemplate, err := template.New(templateName).
		Funcs(sprig.TxtFuncMap()).
		Delims("${", "}").
		ParseFiles(vaultConfigFile)

	if err != nil {
		logrus.Fatalf("error parsing vault config template: %s", err.Error())
	}

	buffer := bytes.NewBuffer(nil)

	err = configTemplate.ExecuteTemplate(buffer, templateName, nil)
	if err != nil {
		logrus.Fatalf("error executing vault config template: %s", err.Error())
	}

	config.SetConfigFile(vaultConfigFile)

	err = config.ReadConfig(buffer)
	if err != nil {
		logrus.Fatalf("error reading vault config file: %s", err.Error())
	}

	return config
}

func init() {
	configureCmd.PersistentFlags().Bool(cfgOnce, false, "Run configure only once")
	configureCmd.PersistentFlags().Bool(cfgFatal, false, "Make configuration errors fatal to the configurator")
	configureCmd.PersistentFlags().Duration(cfgUnsealPeriod, time.Second*5, "How often to attempt to unseal the Vault instance")
	configureCmd.PersistentFlags().StringSlice(cfgVaultConfigFile, []string{vault.DefaultConfigFile}, "The filename of the YAML/JSON Vault configuration")

	rootCmd.AddCommand(configureCmd)
}
