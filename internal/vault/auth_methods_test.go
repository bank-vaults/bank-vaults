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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitAuthConfig(t *testing.T) {
	tests := []struct {
		name     string
		input    []auth
		expected []auth
	}{
		{
			name: "sets path to type when path is empty",
			input: []auth{
				{Type: "aws", Path: ""},
			},
			expected: []auth{
				{Type: "aws", Path: "aws"},
			},
		},
		{
			name: "preserves explicit path",
			input: []auth{
				{Type: "aws", Path: "custom-aws"},
			},
			expected: []auth{
				{Type: "aws", Path: "custom-aws"},
			},
		},
		{
			name: "handles multiple auth methods",
			input: []auth{
				{Type: "kubernetes", Path: ""},
				{Type: "aws", Path: "aws-prod"},
				{Type: "github", Path: ""},
			},
			expected: []auth{
				{Type: "kubernetes", Path: "kubernetes"},
				{Type: "aws", Path: "aws-prod"},
				{Type: "github", Path: "github"},
			},
		},
		{
			name:     "handles empty auth list",
			input:    []auth{},
			expected: []auth{},
		},
		{
			name: "converts nested map types in config",
			input: []auth{
				{
					Type: "jwt",
					Path: "jwt",
					Config: map[string]any{
						"oidc_discovery_url": "https://example.com",
						"provider_config": map[any]any{
							"provider": "azure",
						},
					},
				},
			},
			expected: []auth{
				{
					Type: "jwt",
					Path: "jwt",
					Config: map[string]any{
						"oidc_discovery_url": "https://example.com",
						"provider_config": map[string]any{
							"provider": "azure",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := initAuthConfig(tt.input)
			require.Len(t, result, len(tt.expected))
			for i := range result {
				assert.Equal(t, tt.expected[i].Type, result[i].Type)
				assert.Equal(t, tt.expected[i].Path, result[i].Path)
				assert.Equal(t, tt.expected[i].Config, result[i].Config)
			}
		})
	}
}

func TestFilterAwsClientConfig(t *testing.T) {
	tests := []struct {
		name         string
		input        map[string]any
		expectedKeys []string
		excludedKeys []string
	}{
		{
			name: "filters out aws-identity-integration",
			input: map[string]any{
				"access_key": "test-access-key",
				"secret_key": "test-secret-key",
				"aws-identity-integration": map[string]any{
					"iam_alias": "role_id",
				},
			},
			expectedKeys: []string{"access_key", "secret_key"},
			excludedKeys: []string{"aws-identity-integration"},
		},
		{
			name: "keeps all standard keys when no special keys present",
			input: map[string]any{
				"access_key":   "test-access-key",
				"secret_key":   "test-secret-key",
				"sts_endpoint": "https://sts.example.com",
				"iam_endpoint": "https://iam.example.com",
			},
			expectedKeys: []string{"access_key", "secret_key", "sts_endpoint", "iam_endpoint"},
			excludedKeys: []string{},
		},
		{
			name:         "handles empty config",
			input:        map[string]any{},
			expectedKeys: []string{},
			excludedKeys: []string{},
		},
		{
			name:         "handles nil config",
			input:        nil,
			expectedKeys: nil,
			excludedKeys: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterAwsClientConfig(tt.input)

			if tt.input == nil {
				assert.Equal(t, map[string]any{}, result)
				return
			}
			assert.NotNil(t, result)
			for _, key := range tt.expectedKeys {
				assert.Contains(t, result, key)
			}
			for _, key := range tt.excludedKeys {
				assert.NotContains(t, result, key)
			}
		})
	}
}
