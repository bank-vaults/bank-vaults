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

// The __accessor__ placeholder must be replaced in the SAN fields of a PKI
// role as well, not only in allowed_domains.
func TestAddManagedSecretsEnginesReplacesAccessorInSans(t *testing.T) {
	var mu sync.Mutex
	writes := map[string]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sys/mounts":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{ //nolint:errcheck
				"pki/": map[string]any{"type": "pki"},
			}})
		case r.Method == http.MethodPut || r.Method == http.MethodPost:
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			mu.Lock()
			writes[r.URL.Path] = body
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
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
	v := vi.(*vault)

	mounts := map[string]*api.MountOutput{
		"jwt/": {Accessor: "auth_jwt_123"},
	}
	engines := initSecretsEnginesConfig([]secretEngine{{
		Path: "pki",
		Type: "pki",
		Configuration: map[string]any{
			"roles": []any{map[string]any{
				"name":               "svid",
				"allowed_domains":    []any{"{{identity.entity.aliases.__accessor__jwt.metadata.ns}}.example.com"},
				"allowed_uri_sans":   []any{"spiffe://example.org/ns/{{identity.entity.aliases.__accessor__jwt.metadata.ns}}"},
				"allowed_other_sans": []any{"1.2.3.4;UTF8:{{identity.entity.aliases.__accessor__jwt.metadata.ns}}"},
				"max_ttl":            "1h",
			}},
		},
	}})

	require.NoError(t, v.addManagedSecretsEngines(context.Background(), engines, mounts))

	mu.Lock()
	defer mu.Unlock()
	role := writes["/v1/pki/roles/svid"]
	require.NotNil(t, role)
	assert.Equal(t, []any{"{{identity.entity.aliases.auth_jwt_123.metadata.ns}}.example.com"}, role["allowed_domains"])
	assert.Equal(t, []any{"spiffe://example.org/ns/{{identity.entity.aliases.auth_jwt_123.metadata.ns}}"}, role["allowed_uri_sans"])
	assert.Equal(t, []any{"1.2.3.4;UTF8:{{identity.entity.aliases.auth_jwt_123.metadata.ns}}"}, role["allowed_other_sans"])
	assert.Equal(t, "1h", role["max_ttl"])
}
