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
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

type VaultStorage struct {
	client *vaultapi.Client
	path   string
}

// New creates a new kv.Service backed by Vault
func New(addr, path string) (kv.Service, error) {

	config := vaultapi.DefaultConfig()
	config.Address = addr

	cli, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("err creating Vault Client: %s", err.Error())
	}

	credentialPath := os.Getenv("VAULT_CREDENTIAL_PATH")
	if credentialPath == "" {
		return nil, fmt.Errorf("No Credential path for vault storage set")
	}

	tokenbytes, err := ioutil.ReadFile(credentialPath)
	if err != nil {
		return nil, fmt.Errorf("err reading token from credentialFile: %s", err.Error())
	}
	token := strings.TrimSpace(string(tokenbytes))
	cli.SetToken(token)

	return &VaultStorage{
		client: cli,
		path:   path,
	}, nil
}

func (v *VaultStorage) Set(key string, val []byte) error {
	// Done to prevent overwrite in Vault
	path := fmt.Sprintf("%s/%s", v.path, key)
	if _, err := v.client.Logical().Write(
		path,
		map[string]interface{}{key: val},
	); err != nil {
		return fmt.Errorf("error writing key '%s' to vault addr %s and path '%s': '%s'", key, v.client.Address(), v.path, err.Error())
	}
	return nil
}

func (v *VaultStorage) Get(key string) ([]byte, error) {
	path := fmt.Sprintf("%s/%s", v.path, key)
	secret, err := v.client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("error getting object for key '%s': %s", key, err.Error())
	}
	return secret.Data[key].([]byte), nil
}
