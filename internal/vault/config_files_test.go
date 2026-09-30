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
	"context"
	"testing"

	"github.com/ramizpolic/multiparser"
	"github.com/ramizpolic/multiparser/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseConfigFile is the configuration of the Vault CR: it holds the purge
// settings, but neither the oidc auth method nor the group aliases.
const baseConfigFile = `
purgeUnmanagedConfig:
  enabled: true
  exclude:
    secrets: true
policies:
  - name: secrets_ro
    rules: path "home/*" { capabilities = ["create", "read", "list"] }
  - name: admin
    rules: path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
auth:
  - type: kubernetes
    roles:
      - name: eso
        bound_service_account_names: ["eso-external-secrets"]
        bound_service_account_namespaces: ["eso"]
        policies: ["secrets_ro"]
        ttl: 1h
groups:
  - name: platform:admin
    policies: admin
    type: external
`

// oidcConfigFile is an optional configuration file rendered from a secret: it
// holds the oidc auth method and the group aliases resolving its accessor.
const oidcConfigFile = `
auth:
  - type: oidc
    config:
      oidc_discovery_url: https://auth.example.com/application/o/vault/
      oidc_client_id: fake-client-id
      oidc_client_secret: fake-client-secret
    roles:
      - name: admin
        oidc_scopes: ["openid", "profile", "email", "groups"]
        ttl: 1h
        allowed_redirect_uris:
          - "https://vault.example.com/ui/vault/auth/oidc/oidc/callback"
        user_claim: "sub"
        groups_claim: "groups"
        bound_claims:
          groups: ["platform:admin"]
        policies: "admin"
group-aliases:
  - name: "platform:admin"
    mountpath: oidc
    group: "platform:admin"
`

func parseTestConfig(t *testing.T, content string) map[string]interface{} {
	t.Helper()

	p, err := multiparser.New(parser.JSON, parser.YAML)
	require.NoError(t, err)

	var data map[string]interface{}
	require.NoError(t, p.Parse([]byte(content), &data))

	return data
}

func newConfigFilesTestVault(t *testing.T) *vault {
	t.Helper()

	v, err := New(context.Background(), nil, nil, Config{})
	require.NoError(t, err)

	return v.(*vault)
}

func authPaths(auths []auth) []string {
	paths := []string{}
	for _, a := range initAuthConfig(auths) {
		paths = append(paths, a.Path)
	}

	return paths
}

func policyNames(policies []policy) []string {
	names := []string{}
	for _, p := range policies {
		names = append(names, p.Name)
	}

	return names
}

// Every file passed with --vault-config-file is applied on its own, but the
// purge must keep what any of them declares: applying the base file must not
// remove the oidc auth method, and applying the oidc file must not remove the
// policies, groups and kubernetes auth method of the base file.
func TestManagedConfigKeepsEveryConfigFile(t *testing.T) {
	v := newConfigFilesTestVault(t)

	require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, baseConfigFile)))
	require.NoError(t, v.LoadConfig("oidc.yml", parseTestConfig(t, oidcConfigFile)))

	managed := v.managedConfig()

	assert.ElementsMatch(t, []string{"kubernetes", "oidc"}, authPaths(managed.Auth))
	assert.ElementsMatch(t, []string{"secrets_ro", "admin"}, policyNames(managed.Policies))
	require.Len(t, managed.Groups, 1)
	assert.Equal(t, "platform:admin", managed.Groups[0].Name)
	require.Len(t, managed.GroupAliases, 1)
	assert.Equal(t, "platform:admin", managed.GroupAliases[0].Name)

	purge := managed.PurgeUnmanagedConfig
	assert.True(t, purge.Enabled, "purge is enabled by the base file")
	assert.True(t, purge.Exclude.Secrets)
	assert.False(t, purge.Exclude.Auth, "auth methods do not need to be excluded from the purge anymore")
	assert.False(t, purge.Exclude.GroupAliases, "group aliases do not need to be excluded from the purge anymore")
}

// The purge is enabled as soon as one file enables it, whatever the order the
// files are loaded in: a file that does not declare purgeUnmanagedConfig does
// not disable it.
func TestManagedConfigPurgeIsEnabledByAnyFile(t *testing.T) {
	for _, files := range [][]string{{"base.yml", "oidc.yml"}, {"oidc.yml", "base.yml"}} {
		v := newConfigFilesTestVault(t)

		content := map[string]string{"base.yml": baseConfigFile, "oidc.yml": oidcConfigFile}
		for _, file := range files {
			require.NoError(t, v.LoadConfig(file, parseTestConfig(t, content[file])))
		}

		assert.True(t, v.managedConfig().PurgeUnmanagedConfig.Enabled, "files loaded in order %v", files)
	}
}

// A category is excluded from the purge as soon as one file excludes it.
func TestManagedConfigPurgeExclusionsAreCombined(t *testing.T) {
	v := newConfigFilesTestVault(t)

	require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, baseConfigFile)))
	require.NoError(t, v.LoadConfig("other.yml", parseTestConfig(t, `
purgeUnmanagedConfig:
  exclude:
    policies: true
`)))

	purge := v.managedConfig().PurgeUnmanagedConfig
	assert.True(t, purge.Enabled)
	assert.True(t, purge.Exclude.Secrets, "excluded by base.yml")
	assert.True(t, purge.Exclude.Policies, "excluded by other.yml")
	assert.False(t, purge.Exclude.Auth)
}

// Without any file enabling it, nothing is purged.
func TestManagedConfigPurgeIsDisabledByDefault(t *testing.T) {
	v := newConfigFilesTestVault(t)

	require.NoError(t, v.LoadConfig("oidc.yml", parseTestConfig(t, oidcConfigFile)))

	assert.False(t, v.managedConfig().PurgeUnmanagedConfig.Enabled)
}

// A file that cannot be decoded (a typo in a key, rejected by ErrorUnused) has
// no known content: purging anything while it is broken could delete what it
// declares. The purge is suspended until it is fixed.
func TestManagedConfigPurgeIsSuspendedWhileAFileIsInvalid(t *testing.T) {
	v := newConfigFilesTestVault(t)

	require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, baseConfigFile)))
	require.Error(t, v.LoadConfig("oidc.yml", parseTestConfig(t, `
authh:
  - type: oidc
`)))

	assert.False(t, v.managedConfig().PurgeUnmanagedConfig.Enabled, "purge must be suspended while oidc.yml is invalid")

	require.NoError(t, v.LoadConfig("oidc.yml", parseTestConfig(t, oidcConfigFile)))

	assert.True(t, v.managedConfig().PurgeUnmanagedConfig.Enabled, "purge must resume once oidc.yml is fixed")
}

// A file applied again (daemon mode) replaces its previous version: what it no
// longer declares is not managed anymore, what the other files declare still is.
func TestLoadConfigReplacesAReloadedFile(t *testing.T) {
	v := newConfigFilesTestVault(t)

	require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, baseConfigFile)))
	require.NoError(t, v.LoadConfig("oidc.yml", parseTestConfig(t, oidcConfigFile)))

	require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, `
purgeUnmanagedConfig:
  enabled: true
policies:
  - name: secrets_ro
    rules: path "home/*" { capabilities = ["read"] }
auth:
  - type: kubernetes
`)))

	managed := v.managedConfig()
	assert.ElementsMatch(t, []string{"secrets_ro"}, policyNames(managed.Policies), "admin was removed from base.yml")
	assert.ElementsMatch(t, []string{"kubernetes", "oidc"}, authPaths(managed.Auth), "each file is counted once")
	assert.Empty(t, managed.Groups, "the group was removed from base.yml")
	assert.Len(t, managed.GroupAliases, 1, "oidc.yml still declares the group alias")
	assert.False(t, managed.PurgeUnmanagedConfig.Exclude.Secrets, "the exclusion was removed from base.yml")
}
