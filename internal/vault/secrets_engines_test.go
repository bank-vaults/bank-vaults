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

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
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
