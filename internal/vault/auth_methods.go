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
	"log/slog"
	"os"
	"strings"

	"emperror.dev/errors"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/cast"
)

type auth struct {
	Type             string                 `mapstructure:"type"`
	Path             string                 `mapstructure:"path"`
	Description      string                 `mapstructure:"description"`
	UsersOrGroupsKey string                 `mapstructure:"usersOrGroupsKey"`
	Roles            []interface{}          `mapstructure:"roles"`
	Users            interface{}            `mapstructure:"users"`
	Crossaccountrole []interface{}          `mapstructure:"crossaccountrole"`
	Groups           map[string]interface{} `mapstructure:"groups"`
	Options          map[string]interface{} `mapstructure:"options"`
	Map              map[string]interface{} `mapstructure:"map"`
	Config           map[string]interface{} `mapstructure:"config"`
}

func initAuthConfig(auths []auth) []auth {
	for index, auth := range auths {
		// Use the type as a path in case the path is not set.
		if auth.Path == "" {
			auths[index].Path = auth.Type
		}

		// Convert `map[interface{}]interface{}` to `map[string]interface{}` before sending the config to Vault API.
		// That's because the config data can have a sub dict (like `provider_config` in JWT/OIDC).
		// Without this conversion, Vault API will return the following error:
		// `json: unsupported type: map[interface {}]interface {}`
		for key, value := range auths[index].Config {
			if val, ok := value.(map[interface{}]interface{}); ok {
				auths[index].Config[key] = cast.ToStringMap(val)
			}
		}
	}

	return auths
}

func (v *vault) addAdditionalAuthConfig(authMethod auth) error {
	switch authMethod.Type {
	case "kubernetes":
		if authMethod.Config == nil {
			authMethod.Config = map[string]interface{}{}
		}
		config := authMethod.Config

		if _, ok := config["kubernetes_host"]; !ok {
			config["kubernetes_host"] = fmt.Sprint("https://", os.Getenv("KUBERNETES_SERVICE_HOST"))
		}
		err := v.configureGenericAuthConfig(authMethod.Type, authMethod.Path, config)
		if err != nil {
			return errors.Wrap(err, "error configuring kubernetes auth for vault")
		}

		err = v.configureGenericAuthRoles(authMethod.Type, authMethod.Path, "role", authMethod.Roles)
		if err != nil {
			return errors.Wrap(err, "error configuring kubernetes auth roles for vault")
		}

	case "github":
		err := v.configureGenericAuthConfig(authMethod.Type, authMethod.Path, authMethod.Config)
		if err != nil {
			return errors.Wrap(err, "error configuring github auth for vault")
		}

		mappings, err := cast.ToStringMapE(authMethod.Map)
		if err != nil {
			return errors.Wrap(err, "error finding map block for github")
		}

		err = v.configureGithubMappings(authMethod.Path, mappings)
		if err != nil {
			return errors.Wrap(err, "error configuring github mappings for vault")
		}

	case "plugin":
		err := v.configureGenericAuthRoles(authMethod.Type, authMethod.Path, "role", authMethod.Roles)
		if err != nil {
			return errors.Wrap(err, "error configuring plugin auth roles for vault")
		}

	case "aws":
		err := v.configureAwsConfig(authMethod.Path, authMethod.Config)
		if err != nil {
			return errors.Wrap(err, "error configuring aws auth for vault")
		}

		if authMethod.Crossaccountrole != nil {
			err = v.configureAWSCrossAccountRoles(authMethod.Path, authMethod.Crossaccountrole)
			if err != nil {
				return errors.Wrap(err, "error configuring aws auth cross account roles for vault")
			}
		}

		err = v.configureGenericAuthRoles(authMethod.Type, authMethod.Path, "role", authMethod.Roles)
		if err != nil {
			return errors.Wrap(err, "error configuring aws auth roles for vault")
		}

	case "gcp", "oci":
		err := v.configureGenericAuthConfig(authMethod.Type, authMethod.Path, authMethod.Config)
		if err != nil {
			return errors.Wrapf(err, "error configuring %s auth for vault", authMethod.Type)
		}

		err = v.configureGenericAuthRoles(authMethod.Type, authMethod.Path, "role", authMethod.Roles)
		if err != nil {
			return errors.Wrapf(err, "error configuring %s auth roles for vault", authMethod.Type)
		}

	case "approle":
		err := v.configureGenericAuthRoles(authMethod.Type, authMethod.Path, "role", authMethod.Roles)
		if err != nil {
			return errors.Wrap(err, "error configuring approle auth for vault")
		}

	case "jwt", "oidc":
		err := v.configureGenericAuthConfig(authMethod.Type, authMethod.Path, authMethod.Config)
		if err != nil {
			return errors.Wrapf(err, "error configuring %s auth on path %s for vault", authMethod.Type, authMethod.Path)
		}

		roles, err := cast.ToSliceE(authMethod.Roles)
		if err != nil {
			return errors.Wrapf(err, "error finding roles block for %s", authMethod.Type)
		}

		err = v.configureJwtRoles(authMethod.Path, roles)
		if err != nil {
			return errors.Wrapf(err, "error configuring %s roles on path %s for vault", authMethod.Type, authMethod.Path)
		}

	case "token":
		err := v.configureGenericAuthRoles(authMethod.Type, "token", "roles", authMethod.Roles)
		if err != nil {
			return errors.Wrap(err, "error configuring token roles for vault")
		}

	case "cert":
		err := v.configureGenericAuthConfig(authMethod.Type, authMethod.Path, authMethod.Config)
		if err != nil {
			return errors.Wrap(err, "error configuring cert auth for vault")
		}

		roles, err := cast.ToSliceE(authMethod.Roles)
		if err != nil {
			return errors.Wrap(err, "error finding roles block for certs")
		}

		err = v.configureGenericAuthRoles(authMethod.Type, authMethod.Path, "certs", roles)
		if err != nil {
			return errors.Wrap(err, "error configuring certs auth roles for vault")
		}

	case "ldap", "okta":
		err := v.configureGenericAuthConfig(authMethod.Type, authMethod.Path, authMethod.Config)
		if err != nil {
			return errors.Wrapf(err, "error configuring %s auth on path %s for vault", authMethod.Type, authMethod.Path)
		}

		if authMethod.Users != nil {
			users, err := cast.ToStringMapE(authMethod.Users)
			if err != nil {
				return errors.Wrapf(err, "error finding users block for %s", authMethod.Type)
			}
			err = v.configureGenericUserAndGroupMappings(authMethod.Type, authMethod.Path, "users", users)
			if err != nil {
				return errors.Wrapf(err, "error configuring %s %s for vault", authMethod.Type, "users")
			}
		}
		if authMethod.Groups != nil {
			err = v.configureGenericUserAndGroupMappings(authMethod.Type, authMethod.Path, "groups", authMethod.Groups)
			if err != nil {
				return errors.Wrapf(err, "error configuring %s %s for vault", authMethod.Type, "groups")
			}
		}

	case "userpass":
		err := v.configureUserpassUsers(authMethod.Path, authMethod.Users)
		if err != nil {
			return errors.Wrapf(err, "error configuring users for userpass in vault")
		}

	case "azure":
		err := v.configureGenericAuthConfig(authMethod.Type, authMethod.Path, authMethod.Config)
		if err != nil {
			return errors.Wrap(err, "error configuring azure auth for vault")
		}

		err = v.configureGenericAuthRoles(authMethod.Type, authMethod.Path, "role", authMethod.Roles)
		if err != nil {
			return errors.Wrap(err, "error configuring azure auth roles for vault")
		}
	}

	return nil
}

func (v *vault) configureGithubMappings(path string, mappings map[string]interface{}) error {
	for mappingType, mapping := range mappings {
		mapping, err := cast.ToStringMapStringE(mapping)
		if err != nil {
			return errors.Wrap(err, "error converting mapping for github")
		}

		for userOrTeam, policy := range mapping {
			_, err := v.writeWithWarningCheck(fmt.Sprintf("auth/%s/map/%s/%s", path, mappingType, userOrTeam), map[string]interface{}{"value": policy})
			if err != nil {
				return errors.Wrapf(err, "error putting %s github mapping into vault", mappingType)
			}
		}
	}
	return nil
}

func (v *vault) configureAwsConfig(path string, config map[string]interface{}) error {
	// https://www.vaultproject.io/api/auth/aws/index.html
	_, err := v.writeWithWarningCheck(fmt.Sprintf("auth/%s/config/client", path), config)
	if err != nil {
		return errors.Wrap(err, "error putting aws config into vault")
	}

	return nil
}

func (v *vault) configureAwsIdentityIntegration(path string, config map[string]interface{}) error {
	// https://developer.hashicorp.com/vault/api-docs/auth/aws#configure-identity-integration
	_, err := v.writeWithWarningCheck(fmt.Sprintf("auth/%s/config/identity", path), config)
	if err != nil {
		return errors.Wrap(err, "error configuring aws identity integration into vault")
	}

	return nil
}

func (v *vault) configureUserpassUsers(path string, users interface{}) error {
	usersAsserted, _ := users.([]interface{})
	for _, userRaw := range usersAsserted {
		user, err := cast.ToStringMapE(userRaw)
		if err != nil {
			return errors.Wrapf(err, "error converting user for userpass")
		}

		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/%s/%s", path, "users", user["username"]), user)
		if err != nil {
			return errors.Wrapf(err, "error putting userpass %s user into vault", user["username"])
		}
	}

	return nil
}

func (v *vault) configureAWSCrossAccountRoles(path string, crossAccountRoles []interface{}) error {
	for _, roleInterface := range crossAccountRoles {
		crossAccountRole, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return errors.Wrap(err, "error converting cross account aws roles for aws")
		}

		stsAccount := fmt.Sprint(crossAccountRole["sts_account"])
		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/config/sts/%s", path, stsAccount), crossAccountRole)
		if err != nil {
			return errors.Wrapf(err, "error putting %s cross account aws role into vault", stsAccount)
		}
	}

	return nil
}

// TODO try to generalize this with configureGenericAuthRoles() fix the type flaw
func (v *vault) configureJwtRoles(path string, roles []interface{}) error {
	for _, roleInterface := range roles {
		role, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return errors.Wrap(err, "error converting roles for jwt")
		}

		// role can have a bound_claims or claim_mappings child dict. But it will cause:
		// `json: unsupported type: map[interface {}]interface {}`
		// So check and replace by `map[string]interface{}` before using it.
		if val, ok := role["bound_claims"]; ok {
			role["bound_claims"] = cast.ToStringMap(val)
		}
		if val, ok := role["claim_mappings"]; ok {
			role["claim_mappings"] = cast.ToStringMap(val)
		}

		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/role/%s", path, role["name"]), role)
		if err != nil {
			return errors.Wrapf(err, "error putting %s jwt role into vault", role["name"])
		}
	}

	return nil
}

func (v *vault) configureGenericUserAndGroupMappings(method, path string, mappingType string, mappings map[string]interface{}) error {
	for userOrGroup, policy := range mappings {
		mapping, err := cast.ToStringMapE(policy)
		if err != nil {
			return errors.Wrapf(err, "error converting mapping for %s", method)
		}

		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/%s/%s", path, mappingType, userOrGroup), mapping)
		if err != nil {
			return errors.Wrapf(err, "error putting %s %s mapping into vault", method, mappingType)
		}
	}

	return nil
}

// configureGenericAuthConfig supports a very generic configuration format, which is followed by:
// https://www.vaultproject.io/api/auth/jwt/index.html
// https://www.vaultproject.io/api/auth/kubernetes/index.html
// https://www.vaultproject.io/api/auth/okta/index.html
// https://www.vaultproject.io/api/auth/ldap/index.html
// https://www.vaultproject.io/api/auth/gcp/index.html
// https://www.vaultproject.io/api/auth/github/index.html
func (v *vault) configureGenericAuthConfig(method, path string, config map[string]interface{}) error {
	_, err := v.writeWithWarningCheck(fmt.Sprintf("auth/%s/config", path), config)
	if err != nil {
		return errors.Wrapf(err, "error putting %s auth config into vault", method)
	}

	return nil
}

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

func (v *vault) addManagedAuthMethods(managedAuths []auth) error {
	slog.Info("about to add managed auth methods")
	existingAuths, err := v.getExistingAuthMethods()
	if err != nil {
		return errors.Wrapf(err, "unable to list existing auth methods")
	}

	for _, authMethod := range managedAuths {
		slog.Info(fmt.Sprintf("checking auth method %s (%s)", authMethod.Path, authMethod.Type))
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

		// We have to filter all existing auths, not to re-enable them as that would raise an error
		if existingAuths[authMethod.Path] == nil {
			slog.Info(fmt.Sprintf("adding auth method %s (%s)", authMethod.Path, authMethod.Type))
			err := v.cl.Sys().EnableAuthWithOptions(authMethod.Path, &options)
			if err != nil {
				return errors.Wrapf(err, "error enabling %s auth method in vault", authMethod.Path)
			}
		}

		// If auth method exists but has additional mount options
		if hasMountOptions {
			slog.Info(fmt.Sprintf("tuning existing auth %s (%s)", authMethod.Path, authMethod.Type))
			// all auth methods are mounted below auth/
			tunePath := fmt.Sprintf("auth/%s", authMethod.Path)
			err := v.cl.Sys().TuneMount(tunePath, authConfigInput)
			if err != nil {
				return errors.Wrapf(err, "error tuning %s (%s) auth method in vault", authMethod.Path, authMethod.Type)
			}
		}

		err := v.addAdditionalAuthConfig(authMethod)
		if err != nil {
			return errors.Wrapf(err, "error while adding auth method config")
		}

		// This configuration only makes sense if authentication is done against AWS
		// However, AWS authentication can be configured using an "aws" or "plugin" backend.
		// Since it's not specific for only one backend type,
		// this code lives in this function rather than in addAdditionalAuthConfig
		if authMethod.Config != nil {
			for configOption, configDataRaw := range authMethod.Config {
				slog.Debug(fmt.Sprintf("Handling auth method config option: %s", configOption))
				switch configOption {
				case "aws-identity-integration":
					configData, err := cast.ToStringMapE(configDataRaw)
					if err != nil {
						return errors.Wrap(err, "error converting configDataRaw for aws-identity-integration configuration")
					}
					err = v.configureAwsIdentityIntegration(authMethod.Path, configData)
					if err != nil {
						return errors.Wrap(err, "error configuring plugin identity integration")
					}
				default:
					continue
				}
			}
		}
	}

	return nil
}

// getExistingAuthMethods gets all auth methods that are already in Vault.
// The existing auth methods are in a map to make it easy to disable easily from it with "O(n)" complexity.
func (v *vault) getExistingAuthMethods() (map[string]*api.MountOutput, error) {
	existingAuths := make(map[string]*api.MountOutput)

	existingAuthList, err := v.cl.Sys().ListAuth()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to list existing auth methods")
	}

	for path, existingAuthMethod := range existingAuthList {
		filteredPath := strings.Trim(path, "/")
		existingAuths[filteredPath] = existingAuthMethod
	}

	return existingAuths, nil
}

// getUnmanagedAuthMethods gets unmanaged auth methods by comparing what's already in Vault and what's in the externalConfig
func (v *vault) getUnmanagedAuthMethods(managedAuthMethods []auth) map[string]*api.MountOutput {
	unmanagedAuths, _ := v.getExistingAuthMethods()

	// Remove managed auth methods form the items since the rest will be disabled.
	for _, managedAuthMethod := range managedAuthMethods {
		delete(unmanagedAuths, managedAuthMethod.Path)
	}
	// Remove token auth method since it's the default
	delete(unmanagedAuths, "token")

	return unmanagedAuths
}

// Disables any auth method that's not managed if purgeUnmanagedConfig option is enabled
func (v *vault) removeUnmanagedAuthMethods(unmanagedAuths map[string]*api.MountOutput) error {
	if len(unmanagedAuths) == 0 || !v.externalConfig.PurgeUnmanagedConfig.Enabled || v.externalConfig.PurgeUnmanagedConfig.Exclude.Auth {
		return nil
	}

	for authMethod := range unmanagedAuths {
		slog.Info(fmt.Sprintf("removing auth method %s ", authMethod))
		err := v.cl.Sys().DisableAuth(authMethod)
		if err != nil {
			return errors.Wrapf(err, "error disabling %s auth method in vault", authMethod)
		}
	}

	return nil
}

func (v *vault) configureAuthMethods() error {
	slog.Info("configuring auth methods")
	managedAuths := initAuthConfig(v.externalConfig.Auth)
	unmanagedAuths := v.getUnmanagedAuthMethods(managedAuths)

	if err := v.addManagedAuthMethods(managedAuths); err != nil {
		return errors.Wrap(err, "error configuring managed auth methods")
	}

	if err := v.removeUnmanagedAuthMethods(unmanagedAuths); err != nil {
		return errors.Wrap(err, "error while disabling unmanaged auth methods")
	}

	return nil
}
