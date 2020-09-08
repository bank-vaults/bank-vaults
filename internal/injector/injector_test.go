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
	"encoding/base64"
	"os"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"

	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
	"github.com/sirupsen/logrus"
)

func TestSecretInjector(t *testing.T) {
	os.Setenv("VAULT_ADDR", "http://localhost:8200")

	config := vaultapi.DefaultConfig()
	if config.Error != nil {
		assert.NoError(t, config.Error)
	}

	client, err := vault.NewClientFromConfig(config)
	assert.NoError(t, err)

	err = client.RawClient().Sys().Mount("transit", &vaultapi.MountInput{Type: "transit"})
	assert.NoError(t, err)

	_, err = client.RawClient().Logical().Write("transit/keys/mykey", nil)
	assert.NoError(t, err)

	secret, err := client.RawClient().Logical().Write("transit/encrypt/mykey", map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString([]byte("secret")),
	})
	assert.NoError(t, err)

	ciphertext := secret.Data["ciphertext"].(string)

	_, err = client.RawClient().Logical().Write("secret/data/account", vault.NewData(0, map[string]interface{}{"password": "secret"}))
	assert.NoError(t, err)

	defer func() {
		err = client.RawClient().Sys().Unmount("transit")
		assert.NoError(t, err)

		_, err = client.RawClient().Logical().Delete("secret/metadata/account")
		assert.NoError(t, err)
	}()

	injector := NewSecretInjector(Config{}, client, nil, logrus.New())

	t.Run("success", func(t *testing.T) {
		references := map[string]string{
			"ACCOUNT_PASSWORD": "vault:secret/data/account#password",
			"TRANSIT_SECRET":   `>>vault:transit/decrypt/mykey#${.plaintext | b64dec}#{"ciphertext":"` + ciphertext + `"}`,
		}

		results := map[string]string{}
		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVault(references, injectFunc)
		assert.NoError(t, err)

		assert.Equal(t, map[string]string{
			"ACCOUNT_PASSWORD": "secret",
			"TRANSIT_SECRET":   "secret",
		}, results)
	})

	t.Run("correct path but missing secret", func(t *testing.T) {
		references := map[string]string{
			"SECRET": "vault:secret/data/supersecret#password",
		}

		results := map[string]string{}
		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVault(references, injectFunc)
		assert.EqualError(t, err, "path not found: secret/data/supersecret")
	})

	t.Run("incorrect kv2 path", func(t *testing.T) {
		references := map[string]string{
			"SECRET": "vault:secret/get/data#data",
		}

		results := map[string]string{}
		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVault(references, injectFunc)
		assert.EqualError(t, err, "key 'data' not found under path: secret/get/data")
	})
}

func TestSecretInjectorFromPath(t *testing.T) {
	os.Setenv("VAULT_ADDR", "http://localhost:8200")

	config := vaultapi.DefaultConfig()
	if config.Error != nil {
		assert.NoError(t, config.Error)
	}

	client, err := vault.NewClientFromConfig(config)
	assert.NoError(t, err)

	_, err = client.RawClient().Logical().Write("secret/data/account", vault.NewData(0, map[string]interface{}{"password": "secret", "password2": "secret2"}))
	assert.NoError(t, err)

	_, err = client.RawClient().Logical().Write("secret/data/account2", vault.NewData(0, map[string]interface{}{"password3": "secret", "password4": "secret2"}))
	assert.NoError(t, err)

	defer func() {
		_, err = client.RawClient().Logical().Delete("secret/data/account")
		assert.NoError(t, err)
		_, err = client.RawClient().Logical().Delete("secret/data/account2")
		assert.NoError(t, err)
	}()

	injector := NewSecretInjector(Config{}, client, nil, logrus.New())

	t.Run("success", func(t *testing.T) {
		paths := "secret/data/account"

		results := map[string]string{}

		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVaultPath(paths, injectFunc)
		assert.NoError(t, err)

		assert.Equal(t, map[string]string{
			"password":  "secret",
			"password2": "secret2",
		}, results)
	})

	t.Run("success multiple paths", func(t *testing.T) {
		paths := "secret/data/account,secret/data/account2"
		results := map[string]string{}

		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVaultPath(paths, injectFunc)
		assert.NoError(t, err)

		assert.Equal(t, map[string]string{
			"password":  "secret",
			"password2": "secret2",
			"password3": "secret",
			"password4": "secret2",
		}, results)
	})

	t.Run("incorrect kv2 path", func(t *testing.T) {
		paths := "secret/data/doesnotexist"

		results := map[string]string{}
		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVaultPath(paths, injectFunc)
		assert.Equal(t, map[string]string{}, results)
	})
}
