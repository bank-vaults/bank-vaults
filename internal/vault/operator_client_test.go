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

// Two files passed with --vault-config-file are applied one after the other by
// the same process. Decoding the second one on top of the first used to merge
// their `auth` slices index by index: the oidc entry was decoded into the
// kubernetes entry, and was configured on path "kubernetes".
func TestDecodeExternalConfigDoesNotMergeFiles(t *testing.T) {
	kubernetesFile := map[string]interface{}{
		"auth": []interface{}{
			map[string]interface{}{
				"type": "kubernetes",
				"roles": []interface{}{
					map[string]interface{}{"name": "eso"},
				},
			},
		},
	}

	oidcFile := map[string]interface{}{
		"auth": []interface{}{
			map[string]interface{}{
				"type": "oidc",
				"config": map[string]interface{}{
					"oidc_discovery_url": "https://auth.example.com/",
				},
			},
		},
	}

	kubernetesConfig, err := decodeExternalConfig(kubernetesFile)
	require.NoError(t, err)
	initAuthConfig(kubernetesConfig.Auth)

	oidcConfig, err := decodeExternalConfig(oidcFile)
	require.NoError(t, err)
	initAuthConfig(oidcConfig.Auth)

	require.Len(t, oidcConfig.Auth, 1)
	assert.Equal(t, "oidc", oidcConfig.Auth[0].Type)
	assert.Equal(t, "oidc", oidcConfig.Auth[0].Path)
	assert.Empty(t, oidcConfig.Auth[0].Roles, "an auth method must not inherit the roles of another file")

	require.Len(t, kubernetesConfig.Auth, 1)
	assert.Equal(t, "kubernetes", kubernetesConfig.Auth[0].Type)
	assert.Equal(t, "kubernetes", kubernetesConfig.Auth[0].Path)
}
