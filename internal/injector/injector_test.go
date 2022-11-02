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

//go:build integration
// +build integration

package injector

import (
	"encoding/base64"
	"os"
	"reflect"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

func TestSecretInjector(t *testing.T) {
	t.Parallel()

	err := os.Setenv("VAULT_ADDR", "http://localhost:8200")
	assert.NoError(t, err)

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

	ciphertext := secret.Data["ciphertext"].(string) // nolint:forcetypeassert

	_, err = client.RawClient().Logical().Write("secret/data/account", vault.NewData(0, map[string]interface{}{"username": "superusername", "password": "secret"}))
	assert.NoError(t, err)

	err = client.RawClient().Sys().Mount("pki", &vaultapi.MountInput{Type: "pki"})
	assert.NoError(t, err)

	t.Cleanup(func() {
		err = client.RawClient().Sys().Unmount("transit")
		assert.NoError(t, err)

		_, err = client.RawClient().Logical().Delete("secret/metadata/account")
		assert.NoError(t, err)

		err = client.RawClient().Sys().Unmount("pki")
		assert.NoError(t, err)
	})

	injector := NewSecretInjector(Config{}, client, nil, logrus.New())

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		references := map[string]string{
			"ACCOUNT_PASSWORD":      "vault:secret/data/account#password",
			"TRANSIT_SECRET":        `>>vault:transit/decrypt/mykey#${.plaintext | b64dec}#{"ciphertext":"` + ciphertext + `"}`,
			"ROOT_CERT":             ">>vault:pki/root/generate/internal#certificate",
			"ROOT_CERT_CACHED":      ">>vault:pki/root/generate/internal#certificate",
			"INLINE_SECRET":         "scheme://${vault:secret/data/account#username}:${vault:secret/data/account#password}@127.0.0.1:8080",
			"INLINE_DYNAMIC_SECRET": "${>>vault:pki/root/generate/internal#certificate}__${>>vault:pki/root/generate/internal#certificate}",
		}

		results := map[string]string{}
		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVault(references, injectFunc)
		require.NoError(t, err)

		// This tests caching of dynamic secrets in calls. We can't predict
		// the value, but it is enough checking if they are present and equal.
		assert.NotNil(t, results["ROOT_CERT"])
		assert.Equal(t, results["ROOT_CERT"], results["ROOT_CERT_CACHED"])
		delete(results, "ROOT_CERT")
		delete(results, "ROOT_CERT_CACHED")

		inlineCerts := strings.Split(results["INLINE_DYNAMIC_SECRET"], "__")
		require.Equal(t, 2, len(inlineCerts), "two certs are expected")
		assert.Equal(t, inlineCerts[0], inlineCerts[1], "the two certs should be the same")
		delete(results, "INLINE_DYNAMIC_SECRET")

		assert.Equal(t, map[string]string{
			"ACCOUNT_PASSWORD": "secret",
			"TRANSIT_SECRET":   "secret",
			"INLINE_SECRET":    "scheme://superusername:secret@127.0.0.1:8080",
		}, results)
	})

	t.Run("correct path but missing secret", func(t *testing.T) {
		t.Parallel()

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
		t.Parallel()

		references := map[string]string{
			"SECRET": "vault:secret/get/data#data",
		}

		results := map[string]string{}
		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVault(references, injectFunc)
		assert.EqualError(t, err, "path not found: secret/get/data")
	})
}

func TestSecretInjectorFromPath(t *testing.T) {
	t.Parallel()

	err := os.Setenv("VAULT_ADDR", "http://localhost:8200")
	assert.NoError(t, err)

	config := vaultapi.DefaultConfig()
	if config.Error != nil {
		assert.NoError(t, config.Error)
	}

	client, err := vault.NewClientFromConfig(config)
	assert.NoError(t, err)

	_, err = client.RawClient().Logical().Write("secret/data/account1", vault.NewData(0, map[string]interface{}{"password": "secret", "password2": "secret2"}))
	assert.NoError(t, err)

	_, err = client.RawClient().Logical().Write("secret/data/account2", vault.NewData(0, map[string]interface{}{"password3": "secret", "password4": "secret2"}))
	assert.NoError(t, err)

	t.Cleanup(func() {
		_, err = client.RawClient().Logical().Delete("secret/metadata/account1")
		assert.NoError(t, err)
		_, err = client.RawClient().Logical().Delete("secret/metadata/account2")
		assert.NoError(t, err)
	})

	injector := NewSecretInjector(Config{}, client, nil, logrus.New())

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		paths := "secret/data/account1"

		results := map[string]string{}

		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVaultPath(paths, injectFunc)
		require.NoError(t, err)

		assert.Equal(t, map[string]string{
			"password":  "secret",
			"password2": "secret2",
		}, results)
	})

	t.Run("success multiple paths", func(t *testing.T) {
		t.Parallel()

		paths := "secret/data/account1,secret/data/account2"
		results := map[string]string{}

		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVaultPath(paths, injectFunc)
		require.NoError(t, err)

		assert.Equal(t, map[string]string{
			"password":  "secret",
			"password2": "secret2",
			"password3": "secret",
			"password4": "secret2",
		}, results)
	})

	t.Run("incorrect kv2 path", func(t *testing.T) {
		t.Parallel()

		paths := "secret/data/doesnotexist"

		results := map[string]string{}
		injectFunc := func(key, value string) {
			results[key] = value
		}

		err = injector.InjectSecretsFromVaultPath(paths, injectFunc)
		assert.EqualError(t, err, "path not found: secret/data/doesnotexist")

		assert.Equal(t, map[string]string{}, results)
	})
}

func TestPaginate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pageSize int
		secrets  []string
		want     [][]string
	}{
		{
			name:     "no secrets",
			pageSize: 1,
			secrets:  []string{},
			want:     [][]string{},
		},
		{
			name:     "page by more values then exist",
			pageSize: 100,
			secrets:  []string{"vault:v1:aGVsbG8="},
			want:     [][]string{{"vault:v1:aGVsbG8="}},
		},
		{
			name:     "pagination works",
			pageSize: 2,
			secrets:  []string{"vault:v1:aGVsbG8=", "vault:v2:aGVsbG8=", "vault:v3:aGVsbG8=", "vault:v4:aGVsbG8="},
			want:     [][]string{{"vault:v1:aGVsbG8=", "vault:v2:aGVsbG8="}, {"vault:v3:aGVsbG8=", "vault:v4:aGVsbG8="}},
		},
		{
			name:     "pagination with remeinder",
			pageSize: 3,
			secrets:  []string{"vault:v1:aGVsbG8=", "vault:v2:aGVsbG8=", "vault:v3:aGVsbG8=", "vault:v4:aGVsbG8="},
			want:     [][]string{{"vault:v1:aGVsbG8=", "vault:v2:aGVsbG8=", "vault:v3:aGVsbG8="}, {"vault:v4:aGVsbG8="}},
		},
		{
			name:     "page size 1",
			pageSize: 1,
			secrets:  []string{"vault:v1:aGVsbG8=", "vault:v2:aGVsbG8=", "vault:v3:aGVsbG8=", "vault:v4:aGVsbG8="},
			want:     [][]string{{"vault:v1:aGVsbG8="}, {"vault:v2:aGVsbG8="}, {"vault:v3:aGVsbG8="}, {"vault:v4:aGVsbG8="}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := paginate(tt.secrets, tt.pageSize)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("paginate() got = %v, want %v", got, tt.want)
			}
		})
	}
}
