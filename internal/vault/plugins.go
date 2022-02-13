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
	"emperror.dev/errors"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/sirupsen/logrus"
)

// A non-exclusive map of Vault builtin plugins to avoid calling Vault API for each plugin.
// More details: https://www.vaultproject.io/docs/plugin-portal
// NOTE: At the moment it's not possible to find all builtin plugins via Vault API in one call. The builtin information
// is per plugin and calling the API for all plugins would be expensive.
// TODO: Think about a better approach to retrieve built in plugins from Vault.
var builtinPlugins = map[string]map[string]bool{
	"auth": {
		"alicloud": true, "app-id": true, "approle": true, "aws": true, "azure": true, "centrify": true, "cert": true,
		"cf": true, "gcp": true, "github": true, "jwt": true, "kerberos": true, "kubernetes": true, "ldap": true,
		"oci": true, "oidc": true, "okta": true, "pcf": true, "radius": true, "userpass": true,
	},
	"database": {
		"cassandra-database-plugin": true, "couchbase-database-plugin": true, "elasticsearch-database-plugin": true,
		"hana-database-plugin": true, "influxdb-database-plugin": true, "mongodb-database-plugin": true,
		"mongodbatlas-database-plugin": true, "mssql-database-plugin": true, "mysql-aurora-database-plugin": true,
		"mysql-database-plugin": true, "mysql-legacy-database-plugin": true, "mysql-rds-database-plugin": true,
		"postgresql-database-plugin": true, "redshift-database-plugin": true,
	},
	"secret": {
		"ad": true, "alicloud": true, "aws": true, "azure": true, "cassandra": true, "consul": true, "gcp": true,
		"gcpkms": true, "kv": true, "mongodb": true, "mongodbatlas": true, "mssql": true, "mysql": true, "nomad": true,
		"openldap": true, "pki": true, "postgresql": true, "rabbitmq": true, "ssh": true, "totp": true, "transit": true,
	},
}

type plugin struct {
	Name    string `mapstructure:"plugin_name"`
	Type    string `mapstructure:"type"`
	Command string `mapstructure:"command"`
	SHA256  string `mapstructure:"sha256"`
}

// getExistingPlugins gets all plugins that are already in Vault.
func (v *vault) getExistingPlugins() (map[string]map[string]bool, error) {
	existingPlugins := make(map[string]map[string]bool)

	existingPluginsList, err := v.cl.Sys().ListPlugins(&api.ListPluginsInput{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve list of plugins")
	}

	// Get only custom existing plugins and filter out the built-it plugins.
	for existingPluginType, existingPluginNames := range existingPluginsList.PluginsByType {
		if _, pluginTypeFound := existingPlugins[existingPluginType.String()]; !pluginTypeFound {
			existingPlugins[existingPluginType.String()] = make(map[string]bool)
		}
		for _, existingPluginName := range existingPluginNames {
			if !builtinPlugins[existingPluginType.String()][existingPluginName] {
				// Since the builtinPlugins map is non-exclusive, we still need to make sure that the existing plugin
				// is not builtin plugin (for example, if Vault got some more builtin plugins).
				// Hopfully that should be replaced when Vault exposes the builtin plugins only via the API.
				input := api.GetPluginInput{
					Name: existingPluginName,
					Type: existingPluginType,
				}

				logrus.Debugf("check if %s/%s is a builtin plugin or not", existingPluginType, existingPluginName)
				existingPlugin, err := v.cl.Sys().GetPlugin(&input)
				if err != nil {
					return nil, errors.Wrapf(err, "failed to retrieve plugin %s/%s", existingPluginType, existingPluginName)
				}
				if !existingPlugin.Builtin {
					existingPlugins[existingPluginType.String()][existingPluginName] = true
				}
			}
		}
	}

	return existingPlugins, nil
}

// getUnmanagedPlugins gets unmanaged plugins by comparing what's already in Vault
// and what's in the externalConfig.
func getUnmanagedPlugins(
	existingPlugins map[string]map[string]bool, managedPlugins []plugin,
) map[string]map[string]bool {
	for _, managedPlugin := range managedPlugins {
		delete(existingPlugins[managedPlugin.Type], managedPlugin.Name)
	}

	return existingPlugins
}

func (v *vault) addManagedPlugins(managedPlugins []plugin) error {
	for _, plugin := range managedPlugins {
		pluginType, err := consts.ParsePluginType(plugin.Type)
		if err != nil {
			return errors.Wrap(err, "error parsing type for plugin")
		}

		input := api.RegisterPluginInput{
			Name:    plugin.Name,
			Command: plugin.Command,
			SHA256:  plugin.SHA256,
			Type:    pluginType,
		}

		logrus.Infof("adding plugin %s (%s)", plugin.Name, plugin.Type)
		logrus.Debugf("plugin input %#v", input)
		if err = v.cl.Sys().RegisterPlugin(&input); err != nil {
			return errors.Wrapf(err, "error adding plugin %s/%s in vault", plugin.Type, plugin.Name)
		}
	}

	return nil
}

func (v *vault) removeUnmanagedPlugins(managedPlugins []plugin) error {
	if !extConfig.PurgeUnmanagedConfig.Enabled || extConfig.PurgeUnmanagedConfig.Exclude.Plugins {
		logrus.Debugf("purge config is disabled, no unmanaged plugins will be removed")
		return nil
	}

	existingPlugins, _ := v.getExistingPlugins()
	unmanagedPlugins := getUnmanagedPlugins(existingPlugins, managedPlugins)

	for existingPluginType, existingPluginNames := range unmanagedPlugins {
		for existingPluginName := range existingPluginNames {
			pluginType, err := consts.ParsePluginType(existingPluginType)
			if err != nil {
				return errors.Wrap(err, "error parsing type for plugin")
			}

			input := api.DeregisterPluginInput{
				Name: existingPluginName,
				Type: pluginType,
			}

			logrus.Infof("removing plugin %s (%s)", existingPluginName, existingPluginType)
			if err := v.cl.Sys().DeregisterPlugin(&input); err != nil {
				return errors.Wrapf(err, "error removing plugin %s/%s in vault", existingPluginType, existingPluginName)
			}
		}
	}

	return nil
}

func (v *vault) configurePlugins() error {
	managedPlugins := extConfig.Plugins

	if err := v.addManagedPlugins(managedPlugins); err != nil {
		return errors.Wrap(err, "error while adding plugins")
	}

	if err := v.removeUnmanagedPlugins(managedPlugins); err != nil {
		return errors.Wrap(err, "error while removing plugins")
	}

	return nil
}
