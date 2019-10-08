// Copyright © 2018 Banzai Cloud
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
	"fmt"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
	"github.com/spf13/cast"
)

type VaultStorage struct {
	client *vault.Client
	path   string
}

// New creates a new kv.Service backed by Vault KV Version 2
func New(addr, unsealKeysPath, role, authPath, tokenPath, token string) (kv.Service, error) {

	client, err := vault.NewClientWithOptions(
		vault.ClientURL(addr),
		vault.ClientRole(role),
		vault.ClientAuthPath(authPath),
		vault.ClientTokenPath(tokenPath),
		vault.ClientToken(token))
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %s", err.Error())
	}

	return &VaultStorage{
		client: client,
		path:   unsealKeysPath,
	}, nil
}

func (v *VaultStorage) Set(key string, val []byte) error {
	// Done to prevent overwrite in Vault
	path := fmt.Sprintf("%s/%s", v.path, key)
	if _, err := v.client.RawClient().Logical().Write(
		path,
		map[string]interface{}{
			"data": map[string]interface{}{
				key: val,
			},
		},
	); err != nil {
		return fmt.Errorf("error writing key '%s' to vault addr %s and path '%s': '%s'", key, v.client.RawClient().Address(), v.path, err.Error())
	}
	return nil
}

func (v *VaultStorage) Get(key string) ([]byte, error) {
	path := fmt.Sprintf("%s/%s", v.path, key)
	secret, err := v.client.RawClient().Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("error getting object for key '%s': %s", key, err.Error())
	}
	if secret == nil {
		return nil, kv.NewNotFoundError("key not found under path: %s", key)
	}
	data, err := cast.ToStringMapE(secret.Data["data"])
	if err != nil {
		return nil, fmt.Errorf("error findind data under path '%s': %s", key, err.Error())
	}
	return base64.StdEncoding.DecodeString(data[key].(string))
}
