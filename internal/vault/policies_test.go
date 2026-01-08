// Copyright © 2025 Bank-Vaults Maintainers
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

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
)

func TestInitPoliciesConfig_SubstringCollision(t *testing.T) {
	tests := []struct {
		name           string
		policies       []policy
		mounts         map[string]*api.MountOutput
		expectedRules  string
		description    string
	}{
		{
			name: "multiple accessors with prefix collision",
			policies: []policy{
				{
					Name: "test-policy",
					Rules: `path "secret/data/__accessor__kubernetes_cluster/*" {
  capabilities = ["read"]
}
path "secret/data/__accessor__kubernetes/*" {
  capabilities = ["read"]
}`,
				},
			},
			mounts: map[string]*api.MountOutput{
				"kubernetes/": {
					Accessor: "auth_kubernetes_12345",
				},
				"kubernetes_cluster/": {
					Accessor: "auth_kubernetes_cluster_67890",
				},
			},
			expectedRules: `path "secret/data/auth_kubernetes_cluster_67890/*" {
  capabilities = ["read"]
}
path "secret/data/auth_kubernetes_12345/*" {
  capabilities = ["read"]
}`,
			description: "Should replace longer path first to avoid substring collision",
		},
		{
			name: "single mount",
			policies: []policy{
				{
					Name:  "single-mount",
					Rules: `path "auth/__accessor__kubernetes/role" { capabilities = ["read"] }`,
				},
			},
			mounts: map[string]*api.MountOutput{
				"kubernetes/": {
					Accessor: "auth_kubernetes_12345",
				},
			},
			expectedRules: `path "auth/auth_kubernetes_12345/role" { capabilities = ["read"] }`,
			description:   "Should work correctly with single mount",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := initPoliciesConfig(tt.policies, tt.mounts)
			assert.NoError(t, err, tt.description)
			assert.Equal(t, tt.expectedRules, result[0].Rules, tt.description)

			// Verify RulesFormatted is set and contains replaced accessors
			assert.NotEmpty(t, result[0].RulesFormatted, "RulesFormatted should be set")
			assert.NotContains(t, result[0].RulesFormatted, "__accessor__", "RulesFormatted should not contain placeholders")
		})
	}
}

func TestInitPoliciesConfig_RulesFormatted(t *testing.T) {
	tests := []struct {
		name        string
		policies    []policy
		mounts      map[string]*api.MountOutput
		description string
	}{
		{
			name: "multiline HCL formatting",
			policies: []policy{
				{
					Name: "multiline-policy",
					Rules: `path "secret/data/__accessor__kubernetes/*" {
  capabilities = ["read", "list"]
}`,
				},
			},
			mounts: map[string]*api.MountOutput{
				"kubernetes/": {
					Accessor: "auth_kubernetes_12345",
				},
			},
			description: "Should handle multiline HCL formatting",
		},
		{
			name: "JSON policy rules (not HCL)",
			policies: []policy{
				{
					Name:  "json-policy",
					Rules: `{"path": {"auth/__accessor__kubernetes/role": {"capabilities": ["read"]}}}`,
				},
			},
			mounts: map[string]*api.MountOutput{
				"kubernetes/": {
					Accessor: "auth_kubernetes_12345",
				},
			},
			description: "Should handle JSON-formatted policies (HCL formatter fails but parsing succeeds)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := initPoliciesConfig(tt.policies, tt.mounts)
			assert.NoError(t, err, tt.description)

			// Verify RulesFormatted is populated
			assert.NotEmpty(t, result[0].RulesFormatted, "RulesFormatted should be set")

			// Verify it's valid (can be parsed as HCL or JSON)
			_, err = hcl.Parse(result[0].RulesFormatted)
			assert.NoError(t, err, "RulesFormatted should be valid HCL or JSON")
		})
	}
}

func TestInitPoliciesConfig_InvalidRules(t *testing.T) {
	tests := []struct {
		name          string
		policies      []policy
		mounts        map[string]*api.MountOutput
		expectedError string
		description   string
	}{
		{
			name: "invalid HCL syntax",
			policies: []policy{
				{
					Name:  "invalid-policy",
					Rules: `path "auth/kubernetes/role" { this is not valid HCL }`,
				},
			},
			mounts:        map[string]*api.MountOutput{},
			expectedError: "error parsing invalid-policy policy rules",
			description:   "Should return error for invalid HCL syntax",
		},
		{
			name: "completely malformed rules",
			policies: []policy{
				{
					Name:  "malformed-policy",
					Rules: `{{{{{ not valid at all`,
				},
			},
			mounts:        map[string]*api.MountOutput{},
			expectedError: "error parsing malformed-policy policy rules",
			description:   "Should return error for completely malformed rules",
		},
		{
			name: "empty rules",
			policies: []policy{
				{
					Name:  "empty-policy",
					Rules: ``,
				},
			},
			mounts:        map[string]*api.MountOutput{},
			expectedError: "",
			description:   "Should handle empty rules without error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := initPoliciesConfig(tt.policies, tt.mounts)

			if tt.expectedError != "" {
				assert.Error(t, err, tt.description)
				assert.Contains(t, err.Error(), tt.expectedError, tt.description)
				assert.Nil(t, result, "Result should be nil on error")
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, result, "Result should not be nil")
			}
		})
	}
}
