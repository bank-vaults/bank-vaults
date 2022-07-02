// Copyright © 2022 Banzai Cloud
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

package vault

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"emperror.dev/errors"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"

	vaultpkg "github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

func isOverwriteProhibitedError(err error) bool {
	return strings.Contains(err.Error(), "delete them before reconfiguring")
}

// secretEnginesWihtoutNameConfig holds the secret engine types where
// the name shouldn't be part of the config path
var secretEnginesWihtoutNameConfig = map[string]bool{
	"ad":       true,
	"alicloud": true,
	"azure":    true,
	"gcp":      true,
	"gcpkms":   true,
	"kv":       true,
}

type secretEngine struct {
	Path          string                 `mapstructure:"path"`
	Type          string                 `mapstructure:"type"`
	Description   string                 `mapstructure:"description"`
	Configuration map[string]interface{} `mapstructure:"configuration"`
	Config        map[string]interface{} `mapstructure:"config"`
	Options       map[string]string      `mapstructure:"options"`
	PluginName    string                 `mapstructure:"plugin_name"`
	Local         bool                   `mapstructure:"local"`
	SealWrap      bool                   `mapstructure:"seal_wrap"`
}

func initSecretsEnginesConfig(configs []secretEngine) []secretEngine {
	for index, config := range configs {
		if config.Path == "" {
			configs[index].Path = config.Type
		}

		configs[index].Path = strings.Trim(configs[index].Path, "/")
	}

	return configs
}

func (se *secretEngine) getMountConfigInput() (api.MountConfigInput, error) {
	var mountConfigInput api.MountConfigInput

	if err := mapstructure.Decode(se.Config, &mountConfigInput); err != nil {
		return mountConfigInput, errors.Wrap(err, "error parsing config for secret engine")
	}

	// Bank-Vaults supported options outside config to be used options in the mount request
	// so for now, to preserve backward compatibility we overwrite the options inside config
	// with the options outside.
	mountConfigInput.Options = se.Options

	return mountConfigInput, nil
}

func (v *vault) mountExists(path string) (bool, error) {
	mounts, err := v.cl.Sys().ListMounts()
	if err != nil {
		return false, errors.Wrap(err, "error reading mounts from vault")
	}
	logrus.Debugf("already existing mounts: %+v", mounts)

	return mounts[path+"/"] != nil, nil
}

func (v *vault) rotateSecretEngineCredentials(secretEngineType, path, name, configPath string) error {
	var rotatePath string
	switch secretEngineType {
	case "aws":
		rotatePath = fmt.Sprintf("%s/config/rotate-root", path)
	case "database":
		rotatePath = fmt.Sprintf("%s/rotate-root/%s", path, name)
	case "gcp":
		rotatePath = fmt.Sprintf("%s/%s/rotate", path, name)
	default:
		return errors.Errorf("secret engine type '%s' doesn't support credential rotation", secretEngineType)
	}

	if _, ok := v.rotateCache[rotatePath]; !ok {
		logrus.Infoln("doing credential rotation at", rotatePath)

		_, err := v.writeWithWarningCheck(rotatePath, nil)
		if err != nil {
			return errors.Wrapf(err, "error rotating credentials for '%s' config in vault", configPath)
		}

		logrus.Infoln("credential got rotated at", rotatePath)

		v.rotateCache[rotatePath] = true
	} else {
		logrus.Infoln("credentials were rotated previously for", rotatePath)
	}

	return nil
}

// NOTE: Maybe we could convert "getExisting*" and "getUnmanaged*" methods to generic functions
// since probably they will be the same for all config types.

// getExistingSecretsEngines gets all secrets engines that are already in Vault.
func (v *vault) getExistingSecretsEngines() (map[string]bool, error) {
	existingSecretsEngines := make(map[string]bool)

	existingSecretsEnginesList, err := v.cl.Sys().ListMounts()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to list existing secrets engines")
	}

	for existingSecretEnginePath := range existingSecretsEnginesList {
		existingSecretsEngines[strings.Trim(existingSecretEnginePath, "/")] = true
	}

	return existingSecretsEngines, nil
}

// getUnmanagedSecretsEngines gets unmanaged secrets engines by comparing what's already in Vault
// and what's in the externalConfig.
func (v *vault) getUnmanagedSecretsEngines(managedSecretsEngines []secretEngine) map[string]bool {
	unmanagedSecretsEngines, _ := v.getExistingSecretsEngines()

	// Ignore system mounts.
	delete(unmanagedSecretsEngines, "sys")
	delete(unmanagedSecretsEngines, "identity")
	delete(unmanagedSecretsEngines, "cubbyhole")

	// Remove managed secret engine form the items since the reset will be removed.
	for _, managedSecretEngine := range managedSecretsEngines {
		delete(unmanagedSecretsEngines, managedSecretEngine.Path)
	}

	return unmanagedSecretsEngines
}

func configNeedsNoName(secretEngineType string, configOption string) bool {
	if configOption == "config" {
		_, ok := secretEnginesWihtoutNameConfig[secretEngineType]
		return ok
	}

	if secretEngineType == "aws" && configOption == "config/root" {
		return true
	}

	return false
}

func (v *vault) addManagedSecretsEngines(managedSecretsEngines []secretEngine) error {
	for _, secretEngine := range managedSecretsEngines {
		mountExists, err := v.mountExists(secretEngine.Path)
		if err != nil {
			return err
		}

		mountConfigInput, err := secretEngine.getMountConfigInput()
		if err != nil {
			return err
		}

		if !mountExists {
			// Mount the secret engine if it's not already there.
			mountInput := api.MountInput{
				Type:        secretEngine.Type,
				Description: secretEngine.Description,
				PluginName:  secretEngine.PluginName,
				Config:      mountConfigInput,
				Options:     mountConfigInput.Options, // options needs to be sent here first time
				Local:       secretEngine.Local,
				SealWrap:    secretEngine.SealWrap,
			}

			logrus.Infof("adding secret engine %s (%s)", secretEngine.Path, secretEngine.Type)
			logrus.Debugf("secret engine input %#v", mountInput)
			err = v.cl.Sys().Mount(secretEngine.Path, &mountInput)
			if err != nil {
				return errors.Wrapf(err, "error mounting %s into vault", secretEngine.Path)
			}
		} else {
			// If the secret engine is already mounted, only update its config in place.
			logrus.Infof("tuning already existing secret engine %s/", secretEngine.Path)
			err = v.cl.Sys().TuneMount(secretEngine.Path, mountConfigInput)
			if err != nil {
				return errors.Wrapf(err, "error tuning %s in vault", secretEngine.Path)
			}
		}

		// Configuration of the Secret Engine in a very generic manner, YAML config file should have the proper format
		for configOption, configData := range secretEngine.Configuration {
			configData, err := cast.ToSliceE(configData)
			if err != nil {
				return errors.Wrap(err, "error converting config data for secret engine")
			}
			for _, subConfigData := range configData {
				subConfigData, err := cast.ToStringMapE(subConfigData)
				if err != nil {
					return errors.Wrap(err, "error converting sub config data for secret engine")
				}

				name, ok := subConfigData["name"]
				if !ok && !configNeedsNoName(secretEngine.Type, configOption) {
					return errors.Errorf("error finding sub config data name for secret engine: %s/%s", secretEngine.Path, configOption)
				}

				// config data can have a child dict. But it will cause:
				// `json: unsupported type: map[interface {}]interface {}`
				// So check and replace by `map[string]interface{}` before using it.
				for k, v := range subConfigData {
					switch val := v.(type) {
					case map[interface{}]interface{}:
						subConfigData[k] = cast.ToStringMap(val)
					}
				}

				var configPath string
				if name != nil {
					configPath = fmt.Sprintf("%s/%s/%s", secretEngine.Path, configOption, name)
				} else {
					configPath = fmt.Sprintf("%s/%s", secretEngine.Path, configOption)
				}

				// Control if the configs should be updated or just Created once and skipped later on
				// This is a workaround to secrets backend like GCP that will destroy and recreate secrets at every iteration
				createOnly := cast.ToBool(subConfigData["create_only"])
				// Delete the create_only key from the map, so we don't push it to vault
				delete(subConfigData, "create_only")

				rotate := cast.ToBool(subConfigData["rotate"])
				// Delete the rotate key from the map, so we don't push it to vault
				delete(subConfigData, "rotate")

				saveTo := cast.ToString(subConfigData["save_to"])
				// Delete the rotate key from the map, so we don't push it to vault
				delete(subConfigData, "save_to")

				shouldUpdate := true
				if (createOnly || rotate) && mountExists {
					secretExists := false
					if configOption == "root/generate" { // the pki generate call is a different beast
						req := v.cl.NewRequest("GET", fmt.Sprintf("/v1/%s/ca", secretEngine.Path))
						resp, err := v.cl.RawRequestWithContext(context.Background(), req)
						if resp != nil {
							defer resp.Body.Close()
						}
						if err != nil {
							return errors.Wrapf(err, "failed to check pki CA")
						}
						if resp.StatusCode == http.StatusOK {
							secretExists = true
						}
					} else {
						secret, err := v.cl.Logical().Read(configPath)
						if err != nil {
							return errors.Wrapf(err, "error reading configPath %s", configPath)
						}
						if secret != nil && secret.Data != nil {
							secretExists = true
						}
					}

					if secretExists {
						reason := "rotate"
						if createOnly {
							reason = "create_only"
						}
						logrus.Infof("Secret at configpath %s already exists, %s was set so this will not be updated", configPath, reason)
						shouldUpdate = false
					}
				}

				if shouldUpdate {
					sec, err := v.writeWithWarningCheck(configPath, subConfigData)
					if err != nil {
						if isOverwriteProhibitedError(err) {
							logrus.Infoln("can't reconfigure", configPath, "please delete it manually")

							continue
						}
						return errors.Wrapf(err, "error configuring %s config in vault", configPath)
					}

					if saveTo != "" {
						_, err = v.writeWithWarningCheck(saveTo, vaultpkg.NewData(0, sec.Data))
						if err != nil {
							return errors.Wrapf(err, "error saving secret in vault to %s", saveTo)
						}
					}
				}

				// For secret engines where the root credentials are rotatable we don't wan't to reconfigure again
				// with the old credentials, because that would cause access denied issues. Currently these are:
				// - AWS
				// - Database
				if rotate && mountExists &&
					((secretEngine.Type == "database" && configOption == "config") ||
						(secretEngine.Type == "aws" && configOption == "config/root")) {
					// TODO we need to find out if it was rotated or not
					err = v.rotateSecretEngineCredentials(secretEngine.Type, secretEngine.Path, name.(string), configPath)
					if err != nil {
						return errors.Wrapf(err, "error rotating credentials for '%s' config in vault", configPath)
					}
				}
			}
		}
	}

	return nil
}

func (v *vault) removeUnmanagedSecretsEngines(unmanagedSecretsEngines map[string]bool) error {
	if len(unmanagedSecretsEngines) == 0 || !extConfig.PurgeUnmanagedConfig.Enabled ||
		extConfig.PurgeUnmanagedConfig.Exclude.Secrets {
		return nil
	}

	for secretEnginePath := range unmanagedSecretsEngines {
		logrus.Infof("removing secret engine path %s ", secretEnginePath)
		if err := v.cl.Sys().Unmount(secretEnginePath); err != nil {
			return errors.Wrapf(err, "error unmounting %s secret engine from vault", secretEnginePath)
		}
	}

	return nil
}

func (v *vault) configureSecretsEngines() error {
	managedSecretsEngines := initSecretsEnginesConfig(extConfig.Secrets)
	unmanagedSecretsEngines := v.getUnmanagedSecretsEngines(managedSecretsEngines)

	if err := v.addManagedSecretsEngines(managedSecretsEngines); err != nil {
		return errors.Wrap(err, "error adding secrets engines")
	}

	if err := v.removeUnmanagedSecretsEngines(unmanagedSecretsEngines); err != nil {
		return errors.Wrap(err, "error removing secrets engines")
	}

	return nil
}
