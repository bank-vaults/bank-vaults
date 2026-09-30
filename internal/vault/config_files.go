// Copyright © 2026 Bank-Vaults Maintainers
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
	"fmt"
	"log/slog"

	"emperror.dev/errors"
)

// LoadConfig decodes a configuration file and keeps it as the latest version of
// that file, replacing the previous one.
//
// Every file is applied on its own, but the purge of unmanaged configuration
// must keep what any loaded file declares. Loading every file before applying
// the first one prevents it from purging what the following ones declare.
//
// A file that cannot be decoded is kept as invalid: its content is unknown, so
// the purge is suspended until it is fixed.
func (v *vault) LoadConfig(path string, config map[string]interface{}) error {
	if v.loadedConfigs == nil {
		v.loadedConfigs = map[string]*externalConfig{}
	}

	if _, ok := v.loadedConfigs[path]; !ok {
		v.configFiles = append(v.configFiles, path)
	}

	loadedConfig, err := decodeExternalConfig(config)
	if err != nil {
		v.loadedConfigs[path] = nil

		return errors.Wrapf(err, "error loading config file %s", path)
	}

	v.loadedConfigs[path] = loadedConfig

	return nil
}

// managedConfig returns what every loaded file declares, which the purge of
// unmanaged configuration must keep.
//
// The purge is enabled as soon as one file enables it, and a category is
// excluded from it as soon as one file excludes it.
func (v *vault) managedConfig() *externalConfig {
	managed := &externalConfig{}

	for _, path := range v.configFiles {
		config := v.loadedConfigs[path]
		if config == nil {
			slog.Warn(fmt.Sprintf("config file %s is invalid, unmanaged configuration will not be purged until it is fixed", path))

			return &externalConfig{}
		}

		purge := config.PurgeUnmanagedConfig
		managed.PurgeUnmanagedConfig.Enabled = managed.PurgeUnmanagedConfig.Enabled || purge.Enabled

		exclude := &managed.PurgeUnmanagedConfig.Exclude
		exclude.Audit = exclude.Audit || purge.Exclude.Audit
		exclude.Auth = exclude.Auth || purge.Exclude.Auth
		exclude.Groups = exclude.Groups || purge.Exclude.Groups
		exclude.GroupAliases = exclude.GroupAliases || purge.Exclude.GroupAliases
		exclude.Plugins = exclude.Plugins || purge.Exclude.Plugins
		exclude.Policies = exclude.Policies || purge.Exclude.Policies
		exclude.Secrets = exclude.Secrets || purge.Exclude.Secrets

		managed.Audit = append(managed.Audit, config.Audit...)
		managed.Auth = append(managed.Auth, config.Auth...)
		managed.Groups = append(managed.Groups, config.Groups...)
		managed.GroupAliases = append(managed.GroupAliases, config.GroupAliases...)
		managed.Plugins = append(managed.Plugins, config.Plugins...)
		managed.Policies = append(managed.Policies, config.Policies...)
		managed.Secrets = append(managed.Secrets, config.Secrets...)
		managed.StartupSecrets = append(managed.StartupSecrets, config.StartupSecrets...)
	}

	return managed
}
