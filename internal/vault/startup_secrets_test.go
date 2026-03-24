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

func intPtr(i int) *int {
	return &i
}

func TestVaultKVMaxVersions(t *testing.T) {
	engines := []secretEngine{
		{Path: "staging/kv", Type: "kv", MaxVersions: intPtr(10)},
		{Path: "staging/kv/team", Type: "kv", MaxVersions: intPtr(5)},
		{Path: "secret", Type: "kv", MaxVersions: intPtr(15)},
		{Path: "prod/kv", Type: "kv"},
		{Path: "other", Type: "database"},
	}

	tests := []struct {
		name     string
		path     string
		expected *int
	}{
		{
			name:     "returns max_versions from matching engine",
			path:     "staging/kv/data/app1",
			expected: intPtr(10),
		},
		{
			name:     "returns nil when engine has no max_versions",
			path:     "prod/kv/data/app1",
			expected: nil,
		},
		{
			name:     "returns nil for non-kv engine",
			path:     "other/data/app1",
			expected: nil,
		},
		{
			name:     "returns nil for unmatched path",
			path:     "unknown/data/app1",
			expected: nil,
		},
		{
			name:     "prefix collision: secret should not match secret2",
			path:     "secret2/data/app1",
			expected: nil,
		},
		{
			name:     "more specific path matches: staging/kv/team over staging/kv",
			path:     "staging/kv/team/data/app1",
			expected: intPtr(5),
		},
		{
			name:     "exact prefix match with trailing slash",
			path:     "secret/data/app1",
			expected: intPtr(15),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vaultKVMaxVersions(tt.path, engines)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVaultKVVersion(t *testing.T) {
	engines := []secretEngine{
		{Path: "staging/kv", Type: "kv", Options: map[string]string{"version": "2"}},
		{Path: "staging/kv/team", Type: "kv", Options: map[string]string{"version": "2"}},
		{Path: "secret", Type: "kv", Options: map[string]string{"version": "2"}},
		{Path: "legacy/kv", Type: "kv", Options: map[string]string{"version": "1"}},
		{Path: "other", Type: "database"},
	}

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "returns version 2",
			path:     "staging/kv/data/app1",
			expected: "2",
		},
		{
			name:     "returns version 1",
			path:     "legacy/kv/data/app1",
			expected: "1",
		},
		{
			name:     "returns empty for non-kv",
			path:     "other/data/app1",
			expected: "",
		},
		{
			name:     "returns empty for unknown path",
			path:     "unknown/data/app1",
			expected: "",
		},
		{
			name:     "prefix collision: secret should not match secret2",
			path:     "secret2/data/app1",
			expected: "",
		},
		{
			name:     "more specific path matches: staging/kv/team over staging/kv",
			path:     "staging/kv/team/data/app1",
			expected: "2",
		},
		{
			name:     "exact prefix match with trailing slash",
			path:     "secret/data/app1",
			expected: "2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vaultKVVersion(tt.path, engines)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// writeRecord captures a write call to the fake Vault server.
type writeRecord struct {
	Path string
	Data map[string]interface{}
}

// newFakeVaultServer returns an httptest.Server that records writes and a slice to inspect them.
func newFakeVaultServer(t *testing.T) (*httptest.Server, *[]writeRecord, *sync.Mutex) {
	t.Helper()
	var writes []writeRecord
	var mu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			writes = append(writes, writeRecord{
				Path: r.URL.Path[len("/v1/"):], // strip /v1/ prefix
				Data: body,
			})
			mu.Unlock()
		}
		// Return a valid empty Vault response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{}) //nolint:errcheck
	})

	srv := httptest.NewServer(mux)
	return srv, &writes, &mu
}

func newTestVault(t *testing.T, serverURL string, secrets []secretEngine) *vault {
	t.Helper()
	cfg := api.DefaultConfig()
	cfg.Address = serverURL
	cl, err := api.NewClient(cfg)
	require.NoError(t, err)

	return &vault{
		cl: cl,
		externalConfig: &externalConfig{
			Secrets: secrets,
		},
	}
}

func TestHandleKVSecret_MaxVersionsOverride(t *testing.T) {
	engines := []secretEngine{
		{
			Path:        "staging/kv",
			Type:        "kv",
			Options:     map[string]string{"version": "2"},
			MaxVersions: intPtr(10),
		},
	}

	tests := []struct {
		name                 string
		startupSecret        startupSecret
		expectMetadataWrite  bool
		expectedMetadataPath string
		expectedDataPath     string
		expectedMaxVersions  float64 // JSON numbers decode as float64
	}{
		{
			name: "startup secret overrides engine max_versions",
			startupSecret: startupSecret{
				Type:        "kv",
				Path:        "staging/kv/data/app1",
				MaxVersions: intPtr(20),
				Data: struct {
					Data         map[string]interface{}   `mapstructure:"data"`
					Options      map[string]interface{}   `mapstructure:"options,omitempty"`
					SecretKeyRef []map[string]interface{} `mapstructure:"secretKeyRef"`
				}{
					Data: map[string]interface{}{"key": "value1"},
				},
			},
			expectMetadataWrite:  true,
			expectedMetadataPath: "staging/kv/metadata/app1",
			expectedDataPath:     "staging/kv/data/app1",
			expectedMaxVersions:  20,
		},
		{
			name: "uses engine default when startup has no max_versions",
			startupSecret: startupSecret{
				Type: "kv",
				Path: "staging/kv/data/app2",
				Data: struct {
					Data         map[string]interface{}   `mapstructure:"data"`
					Options      map[string]interface{}   `mapstructure:"options,omitempty"`
					SecretKeyRef []map[string]interface{} `mapstructure:"secretKeyRef"`
				}{
					Data: map[string]interface{}{"key": "value2"},
				},
			},
			expectMetadataWrite:  true,
			expectedMetadataPath: "staging/kv/metadata/app2",
			expectedDataPath:     "staging/kv/data/app2",
			expectedMaxVersions:  10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, writes, mu := newFakeVaultServer(t)
			defer srv.Close()

			v := newTestVault(t, srv.URL, engines)

			err := v.handleKVSecret(context.Background(), tt.startupSecret)
			require.NoError(t, err)

			mu.Lock()
			defer mu.Unlock()

			if tt.expectMetadataWrite {
				// Expect 2 writes: metadata first, then data
				require.Len(t, *writes, 2, "expected a metadata write and a data write")

				metadataWrite := (*writes)[0]
				assert.Equal(t, tt.expectedMetadataPath, metadataWrite.Path)
				assert.Equal(t, tt.expectedMaxVersions, metadataWrite.Data["max_versions"])

				dataWrite := (*writes)[1]
				assert.Equal(t, tt.expectedDataPath, dataWrite.Path)
			}
		})
	}
}

func TestHandleKVSecret_NoMaxVersions(t *testing.T) {
	engines := []secretEngine{
		{
			Path:    "staging/kv",
			Type:    "kv",
			Options: map[string]string{"version": "2"},
			// No MaxVersions set on engine
		},
	}

	secret := startupSecret{
		Type: "kv",
		Path: "staging/kv/data/app1",
		// No MaxVersions set on startup secret
		Data: struct {
			Data         map[string]interface{}   `mapstructure:"data"`
			Options      map[string]interface{}   `mapstructure:"options,omitempty"`
			SecretKeyRef []map[string]interface{} `mapstructure:"secretKeyRef"`
		}{
			Data: map[string]interface{}{"key": "value"},
		},
	}

	srv, writes, mu := newFakeVaultServer(t)
	defer srv.Close()

	v := newTestVault(t, srv.URL, engines)

	err := v.handleKVSecret(context.Background(), secret)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()

	// Only 1 write for the secret data, no metadata write
	assert.Len(t, *writes, 1, "expected only a data write, no metadata write")
}

func TestHandleKVSecret_KVv1RejectsMaxVersions(t *testing.T) {
	engines := []secretEngine{
		{
			Path:    "legacy/kv",
			Type:    "kv",
			Options: map[string]string{"version": "1"},
		},
	}

	secret := startupSecret{
		Type:        "kv",
		Path:        "legacy/kv/app1",
		MaxVersions: intPtr(5),
		Data: struct {
			Data         map[string]interface{}   `mapstructure:"data"`
			Options      map[string]interface{}   `mapstructure:"options,omitempty"`
			SecretKeyRef []map[string]interface{} `mapstructure:"secretKeyRef"`
		}{
			Data: map[string]interface{}{"key": "value"},
		},
	}

	srv, _, _ := newFakeVaultServer(t)
	defer srv.Close()

	v := newTestVault(t, srv.URL, engines)

	err := v.handleKVSecret(context.Background(), secret)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_versions is only supported for KV v2")
}

func TestHandleKVSecret_MissingDataSegmentRejectsMaxVersions(t *testing.T) {
	engines := []secretEngine{
		{
			Path:    "staging/kv",
			Type:    "kv",
			Options: map[string]string{"version": "2"},
		},
	}

	secret := startupSecret{
		Type:        "kv",
		Path:        "staging/kv/app1", // missing /data/ segment
		MaxVersions: intPtr(5),
		Data: struct {
			Data         map[string]interface{}   `mapstructure:"data"`
			Options      map[string]interface{}   `mapstructure:"options,omitempty"`
			SecretKeyRef []map[string]interface{} `mapstructure:"secretKeyRef"`
		}{
			Data: map[string]interface{}{"key": "value"},
		},
	}

	srv, _, _ := newFakeVaultServer(t)
	defer srv.Close()

	v := newTestVault(t, srv.URL, engines)

	err := v.handleKVSecret(context.Background(), secret)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot derive metadata path")
}
