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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/hashicorp/vault/api"
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

func parseTestConfig(t *testing.T, content string) map[string]any {
	t.Helper()

	p, err := multiparser.New(parser.JSON, parser.YAML)
	require.NoError(t, err)

	var data map[string]any
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

// Purging is opt-in: it stays disabled unless a file enables it.
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

// A file rewritten in place (cat new.yml > file.yml) is read empty before its
// content lands: it must suspend the purge, not purge everything it declared.
func TestManagedConfigPurgeIsSuspendedWhileAFileIsEmpty(t *testing.T) {
	for _, content := range []string{"", "# comment", "null", "---"} {
		v := newConfigFilesTestVault(t)

		require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, baseConfigFile)))
		require.NoError(t, v.LoadConfig("oidc.yml", parseTestConfig(t, oidcConfigFile)))
		require.Error(t, v.LoadConfig("oidc.yml", parseTestConfig(t, content)), "content %q", content)

		assert.False(t, v.managedConfig().PurgeUnmanagedConfig.Enabled, "purge must be suspended while oidc.yml is %q", content)
	}
}

// An explicit empty object cannot be a partial read: it is a valid config that
// declares nothing (externalConfig: {} in the Vault CR).
func TestLoadConfigAcceptsAnEmptyObject(t *testing.T) {
	v := newConfigFilesTestVault(t)

	require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, baseConfigFile)))
	require.NoError(t, v.LoadConfig("empty.yml", parseTestConfig(t, "{}")))

	assert.True(t, v.managedConfig().PurgeUnmanagedConfig.Enabled)
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

type rootTokenStore struct{}

func (rootTokenStore) Set(context.Context, string, []byte) error { return nil }

func (rootTokenStore) Get(context.Context, string) ([]byte, error) { return []byte("root"), nil }

// newPurgeTestVault returns a vault backed by a fake Vault server holding one
// managed and one stale resource of every purged category, and the paths the
// fake received a DELETE for.
func newPurgeTestVault(t *testing.T) (*vault, func() []string) {
	t.Helper()

	data := map[string]any{
		"/v1/sys/auth": map[string]any{
			"token/": map[string]any{"type": "token", "accessor": "auth_token_1"},
			"oidc/":  map[string]any{"type": "oidc", "accessor": "auth_oidc_1"},
			"stale/": map[string]any{"type": "userpass", "accessor": "auth_userpass_1"},
		},
		"/v1/sys/mounts": map[string]any{
			"sys/":       map[string]any{"type": "system"},
			"cubbyhole/": map[string]any{"type": "cubbyhole"},
			"identity/":  map[string]any{"type": "identity"},
			"app/":       map[string]any{"type": "kv"},
			"stale/":     map[string]any{"type": "kv"},
		},
		"/v1/sys/policies/acl": map[string]any{
			"keys": []string{"default", "root", "secrets_ro", "oidc_admin", "stale"},
		},
		"/v1/sys/audit": map[string]any{
			"file/":  map[string]any{"type": "file", "path": "file/"},
			"stale/": map[string]any{"type": "file", "path": "stale/"},
		},
		"/v1/sys/plugins/catalog": map[string]any{
			"auth": []string{"custom", "stale"},
		},
		"/v1/sys/plugins/catalog/auth/custom": map[string]any{"name": "custom", "builtin": false},
		"/v1/sys/plugins/catalog/auth/stale":  map[string]any{"name": "stale", "builtin": false},
		"/v1/identity/group/name": map[string]any{
			"keys": []string{"platform:admin", "stale"},
		},
		"/v1/identity/group-alias/id": map[string]any{
			"key_info": map[string]any{
				"ga1": map[string]any{"name": "platform:admin"},
				"ga2": map[string]any{"name": "stale"},
			},
		},
	}

	var mu sync.Mutex
	var deletes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletes = append(deletes, r.URL.Path)
			mu.Unlock()
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		d, ok := data[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": d}) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	cfg := api.DefaultConfig()
	cfg.Address = srv.URL
	cl, err := api.NewClient(cfg)
	require.NoError(t, err)

	vi, err := New(context.Background(), rootTokenStore{}, cl, Config{StoreRootToken: true})
	require.NoError(t, err)

	return vi.(*vault), func() []string {
		mu.Lock()
		defer mu.Unlock()

		return slices.Clone(deletes)
	}
}

// otherConfigFile declares one managed resource of every purged category; it is
// loaded but never applied by the purge tests.
const otherConfigFile = `
auth:
  - type: oidc
policies:
  - name: oidc_admin
    rules: path "*" { capabilities = ["read"] }
secrets:
  - path: app
    type: kv
audit:
  - type: file
plugins:
  - plugin_name: custom
    type: auth
    command: custom
    sha256: abc
groups:
  - name: platform:admin
    type: external
group-aliases:
  - name: platform:admin
    mountpath: oidc
    group: platform:admin
`

// Applying one file must not purge what another loaded file declares: every
// resource of other.yml survives applying base.yml, while what no file
// declares is purged.
func TestConfigurePurgesOnlyWhatNoFileDeclares(t *testing.T) {
	v, deletes := newPurgeTestVault(t)

	require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, `
purgeUnmanagedConfig:
  enabled: true
policies:
  - name: secrets_ro
    rules: path "home/*" { capabilities = ["read"] }
`)))
	require.NoError(t, v.LoadConfig("other.yml", parseTestConfig(t, otherConfigFile)))

	require.NoError(t, v.Configure(context.Background(), "base.yml"))

	assert.ElementsMatch(t, []string{
		"/v1/sys/auth/stale",
		"/v1/sys/mounts/stale",
		"/v1/sys/policies/acl/stale",
		"/v1/sys/audit/stale",
		"/v1/sys/plugins/catalog/auth/stale",
		"/v1/identity/group/name/stale",
		"/v1/identity/group-alias/id/ga2",
	}, deletes())
}

// The purge settings of a file apply to every file: applying empty.yml, which
// neither enables the purge nor excludes anything, purges as base.yml says.
func TestConfigureAppliesThePurgeSettingsOfEveryFile(t *testing.T) {
	staleDeletes := []string{
		"/v1/sys/auth/stale",
		"/v1/sys/mounts/stale",
		"/v1/sys/policies/acl/stale",
		"/v1/sys/audit/stale",
		"/v1/sys/plugins/catalog/auth/stale",
		"/v1/identity/group/name/stale",
		"/v1/identity/group-alias/id/ga2",
	}

	tests := map[string]struct {
		base    string
		deletes []string
	}{
		"enabled": {
			base: `
purgeUnmanagedConfig:
  enabled: true
`,
			// secrets_ro is declared by no file here
			deletes: append(slices.Clone(staleDeletes), "/v1/sys/policies/acl/secrets_ro"),
		},
		"every category excluded": {
			base: `
purgeUnmanagedConfig:
  enabled: true
  exclude:
    auth: true
    secrets: true
    policies: true
    audit: true
    plugins: true
    groups: true
    group-aliases: true
`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v, deletes := newPurgeTestVault(t)

			require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, test.base)))
			require.NoError(t, v.LoadConfig("other.yml", parseTestConfig(t, otherConfigFile)))
			require.NoError(t, v.LoadConfig("empty.yml", parseTestConfig(t, "{}")))

			require.NoError(t, v.Configure(context.Background(), "empty.yml"))

			assert.ElementsMatch(t, test.deletes, deletes())
		})
	}
}
