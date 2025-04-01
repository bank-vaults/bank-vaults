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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bank-vaults/vault-sdk/utils/templater"
	"github.com/bank-vaults/vault-sdk/vault"
	"github.com/fsnotify/fsnotify"
	"github.com/jpillora/backoff"
	"github.com/ramizpolic/multiparser"
	"github.com/ramizpolic/multiparser/parser"
	"github.com/spf13/cobra"

	internalVault "github.com/bank-vaults/bank-vaults/internal/vault"
)

const (
	cfgVaultConfigFile = "vault-config-file"
	cfgFatal           = "fatal"
	cfgDisableMetrics  = "disable-metrics"
)

type configFile struct {
	Path string
	Data map[string]interface{}
}

var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configures a Vault based on a YAML/JSON configuration file",
	Long: `This configuration is an extension to what is available through the Vault configuration:
			https://www.vaultproject.io/docs/configuration/index.html. With this it is possible to
			configure secret engines, auth methods, etc...`,
	Run: func(_ *cobra.Command, _ []string) {
		var unsealConfig unsealCfg

		runOnce := c.GetBool(cfgOnce)
		errorFatal := c.GetBool(cfgFatal)
		unsealConfig.unsealPeriod = c.GetDuration(cfgUnsealPeriod)
		vaultConfigFiles := c.GetStringSlice(cfgVaultConfigFile)
		disableMetrics := c.GetBool(cfgDisableMetrics)

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

		if !disableMetrics {
			metrics := prometheusExporter{Vault: v, Mode: "configure"}
			go func() {
				err := metrics.Run()
				if err != nil {
					slog.Error(fmt.Sprintf("error creating prometheus exporter: %s", err.Error()))
					os.Exit(1)
				}
			}()
		}

		// Create parsers
		parser, err := multiparser.New(parser.JSON, parser.YAML)
		if err != nil {
			slog.Error(fmt.Sprintf("error file parsers: %v", err))
			os.Exit(1)
		}

		configurations := make(chan *configFile, len(vaultConfigFiles))
		for i, vaultConfigFile := range vaultConfigFiles {
			vaultConfigFiles[i] = filepath.Clean(vaultConfigFile)
			configurations <- parseConfiguration(parser, vaultConfigFile)
		}

		if !runOnce {
			go func() {
				err := watchConfigurations(parser, vaultConfigFiles, configurations)
				if err != nil {
					slog.Error(fmt.Sprintf("error watching configuration: %v", err))
					os.Exit(1)
				}
			}()
		} else {
			close(configurations)
		}

		// Handle backoff for configuration errors
		b := &backoff.Backoff{
			Min:    500 * time.Millisecond,
			Max:    60 * time.Second,
			Factor: 2,
			Jitter: false,
		}

		for config := range configurations {
			slog.Info(fmt.Sprintf("applying config file: %s", config.Path))
			func() {
				for {
					slog.Info("checking if vault is sealed...")
					sealed, err := v.Sealed()
					if err != nil {
						slog.Error(fmt.Sprintf("error checking if vault is sealed: %s, waiting %s before trying again...", err.Error(), unsealConfig.unsealPeriod))
						time.Sleep(unsealConfig.unsealPeriod)

						continue
					}

					// If vault is sealed, we stop here and wait another unsealPeriod
					if sealed {
						slog.Info(fmt.Sprintf("vault is sealed, waiting %s before trying again...", unsealConfig.unsealPeriod))
						time.Sleep(unsealConfig.unsealPeriod)

						continue
					}
					slog.Info("vault is unsealed, configuring...")

					if err = v.Configure(config.Data); err != nil {
						slog.Error(fmt.Sprintf("error configuring vault: %s", err.Error()))
						if errorFatal {
							os.Exit(1)
						}

						failedConfigurationsCount++
						// Failed configuration handler - Increase the backoff sleep
						go handleConfigurationError(parser, config.Path, configurations, b.Duration())

						return
					}

					// On *any* successful configuration reset the backoff
					b.Reset()
					successfulConfigurationsCount++
					slog.Info("successfully configured vault")

					return
				}
			}()
		}
	},
}

func handleConfigurationError(parser multiparser.Parser, vaultConfigFile string, configurations chan<- *configFile, sleepTime time.Duration) {
	// This handler will sleep for a exponential backoff amount of time and re-inject the failed configuration into the
	// configurations channel to be re-applied to vault
	// Eventually consistent model - all recoverable errors (5xx and configs that depend on other configs) will be eventually fixed
	// non recoverable errors will be retried and keep failing every MAX BACKOFF seconds, increasing the error counters ont he vault-configurator pod.
	slog.Info(fmt.Sprintf("Failed applying configuration file: %s , sleeping for %s before trying again", vaultConfigFile, sleepTime))
	time.Sleep(sleepTime)
	configurations <- parseConfiguration(parser, vaultConfigFile)
}

func watchConfigurations(parser multiparser.Parser, vaultConfigFiles []string, configurations chan<- *configFile) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("cannot create watcher: %w", err)
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			slog.Error(fmt.Sprintf("error closing watcher: %s", err.Error()))
		}
	}()

	// Map used to match on kubernetes ..data to files inside of directory
	configFileDirs := make(map[string][]string)

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

		slog.Info(fmt.Sprintf("watching directory for changes: %s", configDir))
		err := watcher.Add(configDir)
		if err != nil {
			return fmt.Errorf("cannot watch %s: %w", configDir, err)
		}
	}

	for {
		select {
		case event := <-watcher.Events:
			// we only care about the config file or the ConfigMap directory (if in Kubernetes)
			// For real Files we only need to watch the WRITE Event # TODO: Sometimes it triggers 2 WRITE when a file is edited and saved
			// For Kubernetes configMaps we need to watch for CREATE on the "..data"
			if event.Op&fsnotify.Write == fsnotify.Write && stringInSlice(vaultConfigFiles, filepath.Clean(event.Name)) {
				slog.Info(fmt.Sprintf("file has changed: %s", event.Name))
				configurations <- parseConfiguration(parser, filepath.Clean(event.Name))
			} else if event.Op&fsnotify.Create == fsnotify.Create && filepath.Base(event.Name) == "..data" {
				for _, fileName := range configFileDirs[filepath.Dir(event.Name)] {
					slog.Info(fmt.Sprintf("ConfigMap has changed, reparsing: %s", fileName))
					configurations <- parseConfiguration(parser, fileName)
				}
			}

		case err := <-watcher.Errors:
			return fmt.Errorf("watcher exited with error: %w", err)
		}
	}
}

func parseConfiguration(parser multiparser.Parser, vaultConfigFile string) *configFile {
	// Read file
	vaultConfig, err := os.ReadFile(vaultConfigFile)
	if err != nil {
		slog.Error(fmt.Sprintf("error reading vault config template: %s", err.Error()))
		os.Exit(1)
	}

	// Replace env templating data
	templater := templater.NewTemplater(templater.DefaultLeftDelimiter, templater.DefaultRightDelimiter)
	buffer, err := templater.EnvTemplate(string(vaultConfig))
	if err != nil {
		slog.Error(fmt.Sprintf("error executing vault config template: %s", err.Error()))
		os.Exit(1)
	}

	// Load raw data into map
	var data map[string]interface{}
	if err := parser.Parse(buffer.Bytes(), &data); err != nil {
		slog.Error(fmt.Sprintf("error parsing vault config file: %v", err))
		os.Exit(1)
	}

	return &configFile{
		Path: vaultConfigFile,
		Data: data,
	}
}

func stringInSlice(list []string, match string) bool {
	for _, item := range list {
		if item == match {
			return true
		}
	}
	return false
}

func init() {
	configBoolVar(configureCmd, cfgFatal, false, "Make configuration errors fatal to the configurator")
	configStringSliceVar(configureCmd, cfgVaultConfigFile, []string{internalVault.DefaultConfigFile}, "The filename of the YAML/JSON Vault configuration")
	configBoolVar(configureCmd, cfgDisableMetrics, false, "Disable configurer metrics")

	rootCmd.AddCommand(configureCmd)
}
