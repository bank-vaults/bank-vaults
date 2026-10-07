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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCertPayloadOmitsSecretsFromErrors(t *testing.T) {
	const (
		rootToken = "hvs.CAESIJ_root_token_must_never_appear_in_errors"
		pemCert   = "-----BEGIN CERTIFICATE-----\nMIIBSECRETPEMDATA\n-----END CERTIFICATE-----"
		pemKey    = "-----BEGIN RSA PRIVATE KEY-----\nMIIESECRETKEYDATA\n-----END RSA PRIVATE KEY-----"
	)

	tests := []struct {
		name      string
		data      any
		wantErr   bool
		forbidden []string
	}{
		{
			name:      "cast failure on raw root token",
			data:      rootToken,
			wantErr:   true,
			forbidden: []string{rootToken},
		},
		{
			name:      "cast failure on raw PEM",
			data:      pemKey,
			wantErr:   true,
			forbidden: []string{pemKey, "SECRETKEYDATA"},
		},
		{
			name: "missing pair keeps PEM out of error",
			data: map[string]any{
				"certificate": pemCert,
			},
			wantErr:   true,
			forbidden: []string{pemCert, "SECRETPEMDATA", "BEGIN CERTIFICATE"},
		},
		{
			name: "valid cert and key",
			data: map[string]any{
				"certificate": pemCert,
				"private_key": pemKey,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := generateCertPayload(tt.data)
			if tt.wantErr {
				require.Error(t, err)
				msg := err.Error()
				for _, secret := range tt.forbidden {
					assert.NotContains(t, msg, secret)
				}
				return
			}
			require.NoError(t, err)
			bundle, ok := got["pem_bundle"].(string)
			require.True(t, ok)
			assert.True(t, strings.Contains(bundle, pemCert))
			assert.True(t, strings.Contains(bundle, pemKey))
		})
	}
}
