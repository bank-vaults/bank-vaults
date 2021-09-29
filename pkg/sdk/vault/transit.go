// Copyright © 2019 Banzai Cloud
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
	"encoding/base64"
	"path"
	"regexp"

	vaultapi "github.com/hashicorp/vault/api"
)

// Example: vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==
// ref: https://www.vaultproject.io/docs/secrets/transit/index.html#usage
var transitEncryptedVariable = regexp.MustCompile(`^vault:v\d+:.+$`)

// Transit is a wrapper for Transit Secret Engine
// ref: https://www.vaultproject.io/docs/secrets/transit/index.html
type Transit struct {
	client *vaultapi.Client
}

// IsEncrypted check with regexp that value encrypter by Vault transit secret engine
func (t *Transit) IsEncrypted(value string) bool {
	return transitEncryptedVariable.MatchString(value)
}

// Decrypt decrypts the ciphertext into a plaintext
// ref: https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
func (t *Transit) Decrypt(transitPath, keyID string, ciphertext []byte) ([]byte, error) {
	if len(transitPath) == 0 {
		// Rewrite to default if not defined, all examples from documentation
		// uses `transit` path
		transitPath = "transit"
	}
	out, err := t.client.Logical().Write(
		path.Join(transitPath, "decrypt", keyID),
		map[string]interface{}{
			"ciphertext": string(ciphertext),
		},
	)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Data["plaintext"].(string))
}
