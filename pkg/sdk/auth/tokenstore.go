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

package auth

import (
	"github.com/bank-vaults/vault-sdk/auth"

	"github.com/bank-vaults/bank-vaults/pkg/sdk/vault"
)

// Token represents an access token.
//
// Deprecated: use [auth.Token] instead.
type Token = auth.Token

// TokenStore is general interface for storing access tokens.
//
// Deprecated: use [auth.TokenStore] instead.
type TokenStore = auth.TokenStore

// NewToken Creates a new Token instance initialized ID and Name and CreatedAt fields.
//
// Deprecated: use [auth.NewToken] instead.
func NewToken(id, name string) *Token {
	return auth.NewToken(id, name)
}

// NewInMemoryTokenStore is a basic in-memory TokenStore implementation (thread-safe).
//
// Deprecated: use [auth.NewInMemoryTokenStore] instead.
func NewInMemoryTokenStore() TokenStore {
	return auth.NewInMemoryTokenStore()
}

// NewVaultTokenStore creates a new Vault backed token store.
//
// Deprecated: use [auth.NewVaultTokenStore] instead.
func NewVaultTokenStore(role string) TokenStore {
	return auth.NewVaultTokenStore(role)
}

// NewVaultTokenStoreFromClient creates a new Vault backed token store using a custom client.
//
// Deprecated: use [auth.NewVaultTokenStoreFromClient] instead.
func NewVaultTokenStoreFromClient(client *vault.Client) TokenStore {
	return auth.NewVaultTokenStoreFromClient(client)
}
