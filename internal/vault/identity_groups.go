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
	"fmt"
	"strings"

	"emperror.dev/errors"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

type group struct {
	Name     string                 `mapstructure:"name"`
	Type     string                 `mapstructure:"type"`
	Policies []string               `mapstructure:"policies"`
	Metadata map[string]interface{} `mapstructure:"metadata"`
}

type groupAlias struct {
	Name      string `mapstructure:"name"`
	MountPath string `mapstructure:"mountpath"`
	Group     string `mapstructure:"group"`
}

//
// Common functions.

func readVaultGroup(group string, client *api.Client) (secret *api.Secret, err error) {
	secret, err = client.Logical().Read(fmt.Sprintf("identity/group/name/%s", group))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read group %s by name", group)
	}
	if secret == nil {
		// No Data returned, Group does not exist
		return nil, nil
	}
	return secret, nil
}

func readVaultGroupAlias(id string, client *api.Client) (secret *api.Secret, err error) {
	secret, err = client.Logical().Read(fmt.Sprintf("identity/group-alias/id/%s", id))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read group alias by id %s", id)
	}
	if secret == nil {
		// No Data returned, Group does not exist
		return nil, nil
	}
	return secret, nil
}

func getVaultAuthMountAccessor(path string, client *api.Client) (accessor string, err error) {
	path = strings.TrimRight(path, "/") + "/"
	mounts, err := client.Sys().ListAuth()
	if err != nil {
		return "", errors.Wrapf(err, "failed to read auth mounts from vault")
	}
	if mounts[path] == nil {
		return "", errors.Errorf("auth mount path %s does not exist in vault", path)
	}
	return mounts[path].Accessor, nil
}

func getVaultGroupID(group string, client *api.Client) (id string, err error) {
	g, err := readVaultGroup(group, client)
	if err != nil {
		return "", errors.Wrapf(err, "error reading group %s", group)
	}
	if g == nil {
		return "", errors.Errorf("group %s does not exist", group)
	}
	return g.Data["id"].(string), nil
}

func getVaultGroupAliasName(aliasID string, client *api.Client) (id string, err error) {
	alias, err := readVaultGroupAlias(aliasID, client)
	if err != nil {
		return "", errors.Wrapf(err, "error reading group alias %s", aliasID)
	}
	if alias == nil {
		return "", errors.Errorf("group alias %s does not exist", aliasID)
	}
	return alias.Data["name"].(string), nil
}

func getVaultGroupAliasMount(aliasID string, client *api.Client) (id string, err error) {
	alias, err := readVaultGroupAlias(aliasID, client)
	if err != nil {
		return "", errors.Wrapf(err, "error reading group alias %s", aliasID)
	}
	if alias == nil {
		return "", errors.Errorf("group alias %s does not exist", aliasID)
	}
	return alias.Data["mount_accessor"].(string), nil
}

func findVaultGroupAliasIDFromNameAndMount(name string, accessor string, client *api.Client) (id string, err error) {
	aliases, err := client.Logical().List("identity/group-alias/id")
	if err != nil {
		return "", errors.Wrap(err, "error listing group aliases")
	}
	if aliases == nil {
		return "", nil
	}

	for _, alias := range aliases.Data["keys"].([]interface{}) {
		aliasName, err := getVaultGroupAliasName(cast.ToString(alias), client)
		if err != nil {
			return "", errors.Wrapf(err, "error fetching name for alias id: %s err", alias)
		}

		aliasMount, err := getVaultGroupAliasMount(cast.ToString(alias), client)
		if err != nil {
			return "", errors.Wrapf(err, "error fetching mount for alias id: %s err", alias)
		}

		if aliasName == name && aliasMount == accessor {
			return cast.ToString(alias), nil
		}
	}

	// Did not find any alias matching Name and MountPath
	return "", nil
}

//
// Groups.

func (v *vault) getExistingGroups() (map[string]bool, error) {
	existinGroups := make(map[string]bool)

	existingGroupsList, err := v.cl.Logical().ReadWithData("identity/group/name", map[string][]string{"list": {"true"}})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve list of groups")
	}

	if existingGroupsList == nil {
		logrus.Debugf("vault has no groups")
		return nil, nil
	}

	existingGroupsNames := cast.ToStringSlice(existingGroupsList.Data["keys"])
	for _, existingGroupName := range existingGroupsNames {
		existinGroups[existingGroupName] = true
	}

	return existinGroups, nil
}

func getUnmanagedGroups(existingGroups map[string]bool, managedGroups []group) map[string]bool {
	for _, managedGroup := range managedGroups {
		delete(existingGroups, managedGroup.Name)
	}

	return existingGroups
}

func (v *vault) addManagedGroups(managedGroups []group) error {
	for _, group := range managedGroups {
		g, err := readVaultGroup(group.Name, v.cl)
		if err != nil {
			return errors.Wrap(err, "error reading group")
		}

		// Currently does not support specifying members directly in the group config
		// Use group aliases for that
		if group.Type != "external" {
			return errors.Errorf("only external groups are supported for now")
		}

		config := map[string]interface{}{
			"name":     group.Name,
			"type":     group.Type,
			"policies": group.Policies,
			"metadata": group.Metadata,
		}

		if g == nil {
			logrus.Infof("adding group %s", group.Name)
			_, err = v.writeWithWarningCheck("identity/group", config)
			if err != nil {
				return errors.Wrapf(err, "failed to create group %s", group.Name)
			}
		} else {
			logrus.Infof("tuning already existing group: %s", group.Name)
			_, err = v.writeWithWarningCheck(fmt.Sprintf("identity/group/name/%s", group.Name), config)
			if err != nil {
				return errors.Wrapf(err, "failed to tune group %s", group.Name)
			}
		}
	}

	return nil
}

func (v *vault) removeUnmanagedGroups(managedGroups []group) error {
	if !extConfig.PurgeUnmanagedConfig.Enabled || extConfig.PurgeUnmanagedConfig.Exclude.Groups {
		logrus.Debugf("purge config is disabled, no unmanaged groups will be removed")
		return nil
	}

	existingGroups, err := v.getExistingGroups()
	if err != nil {
		return errors.Wrapf(err, "failed to get existing groups from vault")
	}

	unmanagedGroups := getUnmanagedGroups(existingGroups, managedGroups)
	for unmanagedGroupName := range unmanagedGroups {
		logrus.Infof("removing group %s", unmanagedGroupName)
		_, err := v.cl.Logical().Delete("identity/group/name/" + unmanagedGroupName)
		if err != nil {
			return errors.Wrapf(err, "error removing group %s from vault", unmanagedGroupName)
		}
	}

	return nil
}

//
// Group Aliases.

func (v *vault) addManagedGroupAliases(managedGroupAliases []groupAlias) error {
	// Group Aliases for External Groups might require to have the same Name when on different Mount/Path combinations
	// external groups can only have ONE alias so we need to make sure not to overwrite any
	for _, groupAlias := range managedGroupAliases {
		accessor, err := getVaultAuthMountAccessor(groupAlias.MountPath, v.cl)
		if err != nil {
			return errors.Wrapf(err, "error getting mount accessor for %s", groupAlias.MountPath)
		}

		id, err := getVaultGroupID(groupAlias.Group, v.cl)
		if err != nil {
			return errors.Wrapf(err, "error getting canonical_id for group %s", groupAlias.Group)
		}

		config := map[string]interface{}{
			"name":           groupAlias.Name,
			"mount_accessor": accessor,
			"canonical_id":   id,
		}

		// Find a matching alias for NAME and MOUNT
		ga, err := findVaultGroupAliasIDFromNameAndMount(groupAlias.Name, accessor, v.cl)
		if err != nil {
			return errors.Wrapf(err, "error finding group-alias %s", groupAlias.Name)
		}

		if ga == "" {
			logrus.Infof("adding group-alias: %s@%s", groupAlias.Name, accessor)
			_, err = v.writeWithWarningCheck("identity/group-alias", config)
			if err != nil {
				return errors.Wrapf(err, "failed to create group-alias %s", groupAlias.Name)
			}
		} else {
			logrus.Infof("tuning already existing group-alias: %s@%s - ID: %s", groupAlias.Name, accessor, ga)
			_, err = v.writeWithWarningCheck(fmt.Sprintf("identity/group-alias/id/%s", ga), config)
			if err != nil {
				return errors.Wrapf(err, "failed to tune group-alias %s", ga)
			}
		}
	}

	return nil
}

func (v *vault) getExistingGroupAliases() (map[string]string, error) {
	existinGroupAliases := make(map[string]string)

	existingGroupAliasesRaw, err := v.cl.Logical().ReadWithData(
		"identity/group-alias/id", map[string][]string{"list": {"true"}})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve list of group-alias")
	}

	if existingGroupAliasesRaw == nil {
		logrus.Debugf("vault has no group-aliases")
		return nil, nil
	}

	existingGroupAliasesData := cast.ToStringMap(existingGroupAliasesRaw.Data["key_info"])
	for existingGroupAliasID, existingGroupAliasRaw := range existingGroupAliasesData {
		existingGroupAlias := cast.ToStringMapString(existingGroupAliasRaw)
		existinGroupAliases[existingGroupAlias["name"]] = existingGroupAliasID
	}

	return existinGroupAliases, nil
}

func getUnmanagedGroupAliases(existingGroupAliases map[string]string, managedGroupAliases []groupAlias) map[string]string {
	for _, managedGroupAlias := range managedGroupAliases {
		delete(existingGroupAliases, managedGroupAlias.Name)
	}

	return existingGroupAliases
}

func (v *vault) removeUnmanagedGroupAliases(managedGroupAliases []groupAlias) error {
	if !extConfig.PurgeUnmanagedConfig.Enabled || extConfig.PurgeUnmanagedConfig.Exclude.GroupAliases {
		logrus.Debugf("purge config is disabled, no unmanaged group-alias will be removed")
		return nil
	}

	existingGroupAliases, err := v.getExistingGroupAliases()
	if err != nil {
		return errors.Wrapf(err, "failed to get existing group-alias from vault")
	}
	unmanagedGroupAliases := getUnmanagedGroupAliases(existingGroupAliases, managedGroupAliases)

	logrus.Infof("removing group-aliases ... %T", unmanagedGroupAliases)
	for unmanagedGroupAliasName, unmanagedGroupAliasID := range unmanagedGroupAliases {
		_, err := v.cl.Logical().Delete("identity/group-alias/id/" + unmanagedGroupAliasID)
		if err != nil {
			return errors.Wrapf(err, "error removing group-alias %s with ID %s from vault",
				unmanagedGroupAliasName, unmanagedGroupAliasID)
		}
	}

	return nil
}

//
// Configure groups and group-aliases.

func (v *vault) configureIdentityGroups() error {
	managedGroups := extConfig.Groups
	managedGroupAliases := extConfig.GroupAliases

	if err := v.addManagedGroups(managedGroups); err != nil {
		return errors.Wrap(err, "error while adding groups")
	}

	if err := v.addManagedGroupAliases(managedGroupAliases); err != nil {
		return errors.Wrap(err, "error while adding groups aliases")
	}

	if err := v.removeUnmanagedGroups(managedGroups); err != nil {
		return errors.Wrap(err, "error while removing groups")
	}

	if err := v.removeUnmanagedGroupAliases(managedGroupAliases); err != nil {
		return errors.Wrap(err, "error while removing group aliases")
	}

	return nil
}
