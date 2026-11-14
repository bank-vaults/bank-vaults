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
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplaceAccessor_SubstringCollision(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		mounts      map[string]*api.MountOutput
		expected    string
		description string
	}{
		{
			name:  "longer path with prefix collision",
			input: "__accessor__kubernetes_cluster",
			mounts: map[string]*api.MountOutput{
				"kubernetes/": {
					Accessor: "auth_kubernetes_12345",
				},
				"kubernetes_cluster/": {
					Accessor: "auth_kubernetes_cluster_67890",
				},
			},
			expected:    "auth_kubernetes_cluster_67890",
			description: "Should replace longer path first to avoid substring collision",
		},
		{
			name:  "shorter path with prefix collision",
			input: "__accessor__kubernetes",
			mounts: map[string]*api.MountOutput{
				"kubernetes/": {
					Accessor: "auth_kubernetes_12345",
				},
				"kubernetes_cluster/": {
					Accessor: "auth_kubernetes_cluster_67890",
				},
			},
			expected:    "auth_kubernetes_12345",
			description: "Should correctly replace shorter path when it's the target",
		},
		{
			name:  "no matching accessor",
			input: "__accessor__nonexistent",
			mounts: map[string]*api.MountOutput{
				"kubernetes/": {
					Accessor: "auth_kubernetes_12345",
				},
			},
			expected:    "__accessor__nonexistent",
			description: "Should return input unchanged when no match found",
		},
		{
			name:  "single mount",
			input: "__accessor__kubernetes",
			mounts: map[string]*api.MountOutput{
				"kubernetes/": {
					Accessor: "auth_kubernetes_12345",
				},
			},
			expected:    "auth_kubernetes_12345",
			description: "Should work correctly with single mount",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := replaceAccessor(tt.input, tt.mounts)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

// newRolePurgeTestVault returns a vault backed by a fake Vault server that
// serves the given LIST responses, and the paths it received a DELETE for.
func newRolePurgeTestVault(t *testing.T, lists map[string][]string) (*vault, func() []string) {
	t.Helper()

	var mu sync.Mutex
	var deletes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			mu.Lock()
			deletes = append(deletes, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet, "LIST":
			keys, ok := lists[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}}) //nolint:errcheck
		default:
			w.WriteHeader(http.StatusNoContent)
		}
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

const rolePurgeConfig = `
purgeUnmanagedConfig:
  enabled: true
secrets:
  - path: aws
    type: aws
    configuration:
      config/root:
        - access_key: key
          secret_key: secret
      roles:
        - name: role-1
          credential_type: assumed_role
  - path: db
    type: database
    configuration:
      static-roles:
        - name: app
          db_name: postgres
  - path: transit
    type: transit
    configuration:
      keys:
        - name: managed
`

func TestRemoveUnmanagedSecretsEngineRoles(t *testing.T) {
	lists := map[string][]string{
		"/v1/aws/roles":       {"role-1", "role-2"},
		"/v1/db/static-roles": {"app", "old-app"},
		"/v1/db/roles":        {"manual"},
		"/v1/transit/keys":    {"managed", "other"},
	}

	tests := map[string]struct {
		config  string
		deletes []string
	}{
		"purge enabled": {
			config: rolePurgeConfig,
			// db/roles and transit/keys aren't declared or purgeable, so they stay
			deletes: []string{"/v1/aws/roles/role-2", "/v1/db/static-roles/old-app"},
		},
		"secrets excluded": {
			config: strings.Replace(rolePurgeConfig, "enabled: true", "enabled: true\n  exclude:\n    secrets: true", 1),
		},
		"purge disabled": {
			config: `
secrets:
  - path: aws
    type: aws
    configuration:
      roles:
        - name: role-1
`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			v, deletes := newRolePurgeTestVault(t, lists)

			require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, test.config)))
			v.managed = v.managedConfig()

			require.NoError(t, v.removeUnmanagedSecretsEngineRoles())
			assert.ElementsMatch(t, test.deletes, deletes())
		})
	}
}

// Roles declared by another loaded config file must survive the purge.
func TestRemoveUnmanagedSecretsEngineRolesKeepsRolesOfOtherFiles(t *testing.T) {
	v, deletes := newRolePurgeTestVault(t, map[string][]string{
		"/v1/aws/roles": {"role-1", "role-2", "role-3"},
	})

	require.NoError(t, v.LoadConfig("base.yml", parseTestConfig(t, `
purgeUnmanagedConfig:
  enabled: true
secrets:
  - path: aws/
    type: aws
    configuration:
      roles:
        - name: role-1
`)))
	require.NoError(t, v.LoadConfig("other.yml", parseTestConfig(t, `
secrets:
  - path: aws
    type: aws
    configuration:
      roles:
        - name: role-2
`)))
	v.managed = v.managedConfig()

	require.NoError(t, v.removeUnmanagedSecretsEngineRoles())
	assert.Equal(t, []string{"/v1/aws/roles/role-3"}, deletes())
}
