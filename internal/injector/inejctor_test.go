// Copyright © 2020 Banzai Cloud
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

// +build integration

package injector

import (
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"

	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
	"github.com/sirupsen/logrus"
)

func TestSecretInjector(t *testing.T) {
	client, err := vault.NewClientFromConfig(vaultapi.DefaultConfig())
	assert.NoError(t, err)

	_, err = client.RawClient().Logical().Write("secret/data/account", vault.NewData(0, map[string]interface{}{"password": "secret"}))
	assert.NoError(t, err)

	defer func() {
		_, err := client.RawClient().Logical().Delete("secret/metadata/account")
		assert.NoError(t, err)
	}()

	injector := NewSecretInjector(Config{}, client, nil, logrus.New())

	// test correct path but missing secret
	// references := map[string]string{
	// 	"SECRET": "vault:secret/data/get/data#data",
	// }

	// test incorrect kv2 path
	// references := map[string]string{
	// 	"SECRET": "vault:secret/get/data#data",
	// }

	references := map[string]string{
		"ACCOUNT_PASSWORD": "vault:secret/data/account#password",
	}

	results := map[string]string{}
	injectFunc := func(key, value string) {
		results[key] = value
	}

	err = injector.InjectSecretsFromVault(references, injectFunc)
	assert.NoError(t, err)

	assert.Equal(t, map[string]string{"ACCOUNT_PASSWORD": "secret"}, results)
}
