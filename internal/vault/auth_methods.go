// Copyright © 2021 Banzai Cloud
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

	"emperror.dev/errors"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

type auth struct {
	Type        string        `json:"type"`
	Path        string        `json:"path"`
	Description string        `json:"description"`
	Options     []interface{} `json:"options"`
	Config      []interface{} `json:"config"`
	Roles       []interface{} `json:"roles"`
}

// getExistingAuthMethods gets all auth methods that are already in Vault.
// The existing auth methods are in a map to make it easy to disable easily from it with "O(n)" complexity.
func (v *vault) getExistingAuthMethods() (map[string]*api.MountOutput, error) {
	existingAuthMethods := make(map[string]*api.MountOutput)

	existingAuthMethodsList, err := v.cl.Sys().ListAuth()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to list existing auth methods")
	}

	for _, existingAuthMethod := range existingAuthMethodsList {
		existingAuthMethods[existingAuthMethod.Type] = existingAuthMethod
	}

	return existingAuthMethods, nil
}

// getUnmanagedAuthMethods gets unmanaged auth methods by comparing what's already in Vault and what's in the externalConfig
func (v *vault) getUnmanagedAuthMethods(unmangedAuths map[string]*api.MountOutput, managedAuthMethods []auth) map[string]*api.MountOutput {
	// Remove managed auth methods form the items since the rest will be disabled.
	for _, mangedAuthMethod := range managedAuthMethods {
		delete(unmangedAuths, mangedAuthMethod.Type)
	}
	// Remove token auth method since it's the default
	delete(unmangedAuths, "token")

	return unmangedAuths
}

func (v *vault) configureAuthMethods() error {
	managedAuths := extConfig.Auth
	existingAuths, _ := v.getExistingAuthMethods()
	unManagedAuths := v.getUnmanagedAuthMethods(existingAuths, managedAuths)
	if len(managedAuths) == 0 {
		return nil
	}

	err := v.syncManagedAuthMethods(managedAuths, existingAuths)
	if err != nil {
		return errors.Wrap(err, "error configuring managed auth methods")
	}

	if extConfig.PurgeUnmanagedConfig.Enabled && !extConfig.PurgeUnmanagedConfig.Exclude.Auths {
		err := v.disableUnmanagedAuthMethods(unManagedAuths)
		if err != nil {
			return errors.Wrap(err, "disabling unmanaged auth methods")
		}
	}

	return nil
}

// Disables any auth method that's not managed if purgeUnmanagedConfig option is enabled
func (v *vault) disableUnmanagedAuthMethods(unManagedAuths map[string]*api.MountOutput) error {
	for authMethod := range unManagedAuths {
		err := v.cl.Sys().DisableAuth(authMethod)
		if err != nil {
			return errors.Wrapf(err, "error disabling %s auth method in vault", authMethod)
		}
	}
	return nil
}

func (v *vault) syncManagedAuthMethods(managedAuths []auth, existingAuths map[string]*api.MountOutput) error {
	for _, authMethod := range managedAuths {
		path := authMethod.Path
		if len(path) == 0 {
			path = authMethod.Type
		}

		description := fmt.Sprintf("%s backend", authMethod.Type)

		// get auth mount options
		// https://www.vaultproject.io/api/system/auth.html#config
		var authConfigInput api.AuthConfigInput
		hasMountOptions := authMethod.Options != nil
		// https://www.vaultproject.io/api/system/auth.html
		var options api.EnableAuthOptions
		if hasMountOptions {
			err := mapstructure.Decode(authMethod.Options, &authConfigInput)
			if err != nil {
				return errors.Wrap(err, "error parsing auth method options")
			}
			options = api.EnableAuthOptions{
				Type:        authMethod.Type,
				Description: description,
				Config:      authConfigInput,
			}
		} else {
			options = api.EnableAuthOptions{
				Type:        authMethod.Type,
				Description: description,
			}
		}

		if existingAuths[authMethod.Type] != nil {
			logrus.Debugf("enabling %s auth backend in vault...", authMethod.Type)
			err := v.cl.Sys().EnableAuthWithOptions(path, &options)
			if err != nil {
				return errors.Wrapf(err, "error enabling %s auth method in vault", authMethod.Type)
			}
		}

		// If auth method exists but has additional mount options
		// if hasMountOptions {
		// 	logrus.Debugf("tuning existing %s auth backend in vault...", path)
		// 	// all auth methods are mounted below auth/
		// 	tunePath := fmt.Sprintf("auth/%s", path)
		// 	err = v.cl.Sys().TuneMount(tunePath, authConfigInput)
		// 	if err != nil {
		// 		return errors.Wrapf(err, "error tuning %s auth method in vault", path)
		// 	}
		// }
	}
	// TODO:
	// If purge option is enabled then disable unmanaged auth methods
	// If not then do nothing
	logrus.Debug("synced auth methods succesfully")
	return nil
}

// func (v *vault) addAdditionalAuthMethodConfig(authMethod auth) {
// 	switch authMethod {
// 	case "kubernetes":
// 		config, err := getOrDefaultStringMap(authMethod, "config")
// 		if err != nil {
// 			return errors.Wrap(err, "error finding config block for kubernetes")
// 		}
// 		// If kubernetes_host is defined we are probably out of cluster, so don't read the default config
// 		if _, ok := config["kubernetes_host"]; !ok {
// 			defaultConfig, err := v.kubernetesAuthConfigDefault()
// 			if err != nil {
// 				return errors.Wrap(err, "error getting default kubernetes auth config for vault")
// 			}
// 			// merge the config blocks
// 			for k, v := range config {
// 				defaultConfig[k] = v
// 			}
// 			config = defaultConfig
// 		}
// 		err = v.configureGenericAuthConfig(authMethodType, path, config)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring kubernetes auth for vault")
// 		}
// 		roles, err := cast.ToSliceE(authMethod["roles"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding roles block for kubernetes")
// 		}
// 		err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring kubernetes auth roles for vault")
// 		}
// 	case "github":
// 		config, err := cast.ToStringMapE(authMethod["config"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding config block for github")
// 		}
// 		err = v.configureGenericAuthConfig(authMethodType, path, config)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring github auth for vault")
// 		}
// 		mappings, err := cast.ToStringMapE(authMethod["map"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding map block for github")
// 		}
// 		err = v.configureGithubMappings(path, mappings)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring github mappings for vault")
// 		}
// 	case "aws":
// 		config, err := cast.ToStringMapE(authMethod["config"])
// 		if err != nil {
// 			return errors.Wrapf(err, "error finding config block for aws")
// 		}
// 		err = v.configureAwsConfig(path, config)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring aws auth for vault")
// 		}
// 		if crossaccountroleRaw, ok := authMethod["crossaccountrole"]; ok {
// 			crossaccountrole, err := cast.ToSliceE(crossaccountroleRaw)
// 			if err != nil {
// 				return errors.Wrap(err, "error finding crossaccountrole block for aws")
// 			}
// 			err = v.configureAWSCrossAccountRoles(path, crossaccountrole)
// 			if err != nil {
// 				return errors.Wrap(err, "error configuring aws auth cross account roles for vault")
// 			}
// 		}
// 		roles, err := cast.ToSliceE(authMethod["roles"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding roles block for aws")
// 		}
// 		err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring aws auth roles for vault")
// 		}
// 	case "gcp", "oci":
// 		config, err := cast.ToStringMapE(authMethod["config"])
// 		if err != nil {
// 			return errors.Wrapf(err, "error finding config block for %s", authMethodType)
// 		}
// 		err = v.configureGenericAuthConfig(authMethodType, path, config)
// 		if err != nil {
// 			return errors.Wrapf(err, "error configuring %s auth for vault", authMethodType)
// 		}
// 		roles, err := cast.ToSliceE(authMethod["roles"])
// 		if err != nil {
// 			return errors.Wrapf(err, "error finding roles block for %s", authMethodType)
// 		}
// 		err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
// 		if err != nil {
// 			return errors.Wrapf(err, "error configuring %s auth roles for vault", authMethodType)
// 		}
// 	case "approle":
// 		roles, err := cast.ToSliceE(authMethod["roles"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding role block for approle")
// 		}
// 		err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring approle auth for vault")
// 		}
// 	case "jwt", "oidc":
// 		config, err := cast.ToStringMapE(authMethod["config"])
// 		if err != nil {
// 			return errors.Wrapf(err, "error finding config block for %s", authMethodType)
// 		}
// 		err = v.configureGenericAuthConfig(authMethodType, path, config)
// 		if err != nil {
// 			return errors.Wrapf(err, "error configuring %s auth on path %s for vault", authMethodType, path)
// 		}
// 		roles, err := cast.ToSliceE(authMethod["roles"])
// 		if err != nil {
// 			return errors.Wrapf(err, "error finding roles block for %s", authMethodType)
// 		}
// 		err = v.configureJwtRoles(path, roles)
// 		if err != nil {
// 			return errors.Wrapf(err, "error configuring %s roles on path %s for vault", authMethodType, path)
// 		}
// 	case "token":
// 		roles, err := cast.ToSliceE(authMethod["roles"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding roles block for token")
// 		}
// 		err = v.configureGenericAuthRoles(authMethodType, "token", "roles", roles)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring token roles for vault")
// 		}
// 	case "cert":
// 		config, err := cast.ToStringMapE(authMethod["config"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding config block for cert")
// 		}
// 		err = v.configureGenericAuthConfig(authMethodType, path, config)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring cert auth for vault")
// 		}
// 		roles, err := cast.ToSliceE(authMethod["roles"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding roles block for certs")
// 		}
// 		err = v.configureGenericAuthRoles(authMethodType, path, "certs", roles)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring certs auth roles for vault")
// 		}
// 	case "ldap", "okta":
// 		config, err := cast.ToStringMapE(authMethod["config"])
// 		if err != nil {
// 			return errors.Wrapf(err, "error finding config block for %s", authMethodType)
// 		}
// 		err = v.configureGenericAuthConfig(authMethodType, path, config)
// 		if err != nil {
// 			return errors.Wrapf(err, "error configuring %s auth on path %s for vault", authMethodType, path)
// 		}
// 		for _, usersOrGroupsKey := range []string{"groups", "users"} {
// 			if userOrGroupRaw, ok := authMethod[usersOrGroupsKey]; ok {
// 				userOrGroup, err := cast.ToStringMapE(userOrGroupRaw)
// 				if err != nil {
// 					return errors.Wrapf(err, "error finding %s block for %s", usersOrGroupsKey, authMethodType)
// 				}
// 				err = v.configureGenericUserAndGroupMappings(authMethodType, path, usersOrGroupsKey, userOrGroup)
// 				if err != nil {
// 					return errors.Wrapf(err, "error configuring %s %s for vault", authMethodType, usersOrGroupsKey)
// 				}
// 			}
// 		}
// 	case "userpass":
// 		users, err := cast.ToSliceE(authMethod["users"])
// 		if err != nil {
// 			return errors.Wrapf(err, "error finding users block for %s", authMethodType)
// 		}
// 		err = v.configureUserpassUsers(path, users)
// 		if err != nil {
// 			return errors.Wrapf(err, "error configuring users for userpass in vault")
// 		}
// 	case "azure":
// 		config, err := cast.ToStringMapE(authMethod["config"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding config block for azure")
// 		}
// 		err = v.configureGenericAuthConfig(authMethodType, path, config)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring azure auth for vault")
// 		}
// 		roles, err := cast.ToSliceE(authMethod["roles"])
// 		if err != nil {
// 			return errors.Wrap(err, "error finding roles block for azure")
// 		}
// 		err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
// 		if err != nil {
// 			return errors.Wrap(err, "error configuring azure auth roles for vault")
// 		}
// 	}
// }

// configureGenericAuthRoles supports a very generic configuration format for auth roles, which is followed by:
// https://www.vaultproject.io/api/auth/jwt/index.html partially
// https://www.vaultproject.io/api/auth/kubernetes/index.html
// https://www.vaultproject.io/api/auth/gcp/index.html
// https://www.vaultproject.io/api/auth/aws/index.html
// https://www.vaultproject.io/api/auth/approle/index.html
// https://www.vaultproject.io/api/auth/token/index.html
func (v *vault) configureGenericAuthRoles(method, path, roleSubPath string, roles []interface{}) error {
	for _, roleInterface := range roles {
		role, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return errors.Wrapf(err, "error converting roles for %s", method)
		}

		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/%s/%s", path, roleSubPath, role["name"]), role)
		if err != nil {
			return errors.Wrapf(err, "error putting %s %s role into vault", role["name"], method)
		}
	}

	return nil
}
