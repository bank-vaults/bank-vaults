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
	"fmt"
	"sync"
	"time"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cast"
)

// Verify tokenstores satisfy the correct interface
var _ TokenStore = (*inMemoryTokenStore)(nil)
var _ TokenStore = (*vaultTokenStore)(nil)

// Token represents an access token
type Token struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	CreatedAt *time.Time `json:"createdAt,omitempty"`
	Value     string     `json:"value,omitempty"`
}

// TokenStore is general interface for storing access tokens
type TokenStore interface {
	Store(userID string, token *Token) error
	Lookup(userID string, tokenID string) (*Token, error)
	Revoke(userID string, tokenID string) error
	List(userID string) ([]*Token, error)
	GC() error
}

// NewToken Creates a new Token instance initialized ID and Name and CreatedAt fields
func NewToken(id, name string) *Token {
	return &Token{ID: id, Name: name}
}

func parseToken(secret *vaultapi.Secret, showExpired bool) (*Token, error) {
	data := cast.ToStringMap(secret.Data["data"])
	metadata := cast.ToStringMap(secret.Data["metadata"])

	if tokenData, ok := data["token"]; ok {

		tokenData := tokenData.(map[string]interface{})
		token := Token{}

		expiresAtRaw := tokenData["expiresAt"]
		if expiresAtRaw != nil {
			expiresAt, err := time.Parse(time.RFC3339, expiresAtRaw.(string))
			if err != nil {
				return nil, err
			}
			// Token has expired, make it invisible
			if !showExpired && expiresAt.Before(time.Now()) {
				return nil, nil
			}
			token.ExpiresAt = &expiresAt
		}

		tokenID := tokenData["id"]
		if tokenID == nil {
			return nil, fmt.Errorf("Can't find \"token.id\" in Secret")
		}
		token.ID = tokenID.(string)

		tokenName := tokenData["name"]
		if tokenName == nil {
			return nil, fmt.Errorf("Can't find \"token.name\" in Secret")
		}
		token.Name = tokenName.(string)

		createdAt, err := time.Parse(time.RFC3339, metadata["created_time"].(string))
		if err != nil {
			return nil, err
		}
		token.CreatedAt = &createdAt

		tokenValue := tokenData["value"]
		if tokenValue != nil {
			token.Value = tokenValue.(string)
		}

		return &token, nil
	}
	return nil, fmt.Errorf("Can't find \"token\" in Secret")
}

// In-memory implementation

// NewInMemoryTokenStore is a basic in-memory TokenStore implementation (thread-safe)
func NewInMemoryTokenStore() TokenStore {
	return &inMemoryTokenStore{store: make(map[string]map[string]*Token)}
}

type inMemoryTokenStore struct {
	sync.RWMutex
	store map[string]map[string]*Token
}

func (tokenStore *inMemoryTokenStore) Store(userID string, token *Token) error {
	tokenStore.Lock()
	defer tokenStore.Unlock()
	var userTokens map[string]*Token
	var ok bool
	if userTokens, ok = tokenStore.store[userID]; !ok {
		userTokens = make(map[string]*Token)
	}
	userTokens[token.ID] = token
	tokenStore.store[userID] = userTokens
	return nil
}

func (tokenStore *inMemoryTokenStore) Lookup(userID, tokenID string) (*Token, error) {
	tokenStore.RLock()
	defer tokenStore.RUnlock()
	if userTokens, ok := tokenStore.store[userID]; ok {
		token, _ := userTokens[tokenID]
		return token, nil
	}
	return nil, nil
}

func (tokenStore *inMemoryTokenStore) Revoke(userID, tokenID string) error {
	tokenStore.Lock()
	defer tokenStore.Unlock()
	if userTokens, ok := tokenStore.store[userID]; ok {
		delete(userTokens, tokenID)
	}
	return nil
}

func (tokenStore *inMemoryTokenStore) List(userID string) ([]*Token, error) {
	tokenStore.Lock()
	defer tokenStore.Unlock()
	if userTokens, ok := tokenStore.store[userID]; ok {
		tokens := make([]*Token, len(userTokens))
		i := 0
		for _, v := range userTokens {
			tokens[i] = v
			i++
		}
		return tokens, nil
	}
	return nil, nil
}

func (tokenStore *inMemoryTokenStore) GC() error {
	// not implemented
	return nil
}

// Vault KV Version 2 based implementation

// A TokenStore implementation which stores tokens in Vault
// For local development:
// $ vault server -dev &
// $ export VAULT_ADDR='http://127.0.0.1:8200'
type vaultTokenStore struct {
	client  *vault.Client
	logical *vaultapi.Logical
}

//NewVaultTokenStore creates a new Vault backed token store
func NewVaultTokenStore(role string) TokenStore {
	client, err := vault.NewClient(role)
	if err != nil {
		panic(err)
	}
	logical := client.RawClient().Logical()
	return vaultTokenStore{client: client, logical: logical}
}

func tokenDataPath(userID, tokenID string) string {
	return fmt.Sprintf("secret/data/accesstokens/%s/%s", userID, tokenID)
}

func tokenMetadataPath(userID, tokenID string) string {
	return fmt.Sprintf("secret/metadata/accesstokens/%s/%s", userID, tokenID)
}

func (tokenStore vaultTokenStore) Store(userID string, token *Token) error {
	data := map[string]interface{}{"token": token}
	_, err := tokenStore.logical.Write(tokenDataPath(userID, token.ID), vault.NewData(0, data))
	return err
}

func (tokenStore vaultTokenStore) Lookup(userID, tokenID string) (*Token, error) {
	return tokenStore.lookup(userID, tokenID, false)
}

func (tokenStore vaultTokenStore) lookup(userID, tokenID string, showExpired bool) (*Token, error) {
	secret, err := tokenStore.logical.Read(tokenDataPath(userID, tokenID))
	if err != nil {
		return nil, err
	}
	// Token not found
	if secret == nil {
		return nil, nil
	}
	return parseToken(secret, showExpired)
}

func (tokenStore vaultTokenStore) Revoke(userID, tokenID string) error {
	_, err := tokenStore.logical.Delete(tokenMetadataPath(userID, tokenID))
	return err
}

func (tokenStore vaultTokenStore) List(userID string) ([]*Token, error) {
	return tokenStore.list(userID, false)
}

func (tokenStore vaultTokenStore) list(userID string, showExpired bool) ([]*Token, error) {
	secret, err := tokenStore.logical.List(fmt.Sprintf("secret/metadata/accesstokens/%s", userID))
	if err != nil {
		return nil, err
	}

	var tokenIDs []string
	if secret != nil {
		if keys := secret.Data["keys"]; keys != nil {
			tokenIDs = cast.ToStringSlice(keys)
		}
	}

	tokens := []*Token{}

	for _, tokenID := range tokenIDs {
		token, err := tokenStore.lookup(userID, tokenID, showExpired)
		if err != nil {
			return nil, err
		}
		// if token got removed in a race condition between list and lookup it becomes
		if token != nil {
			tokens = append(tokens, token)
		}
	}

	return tokens, nil
}

// GC removes expired tokens from all users
func (tokenStore vaultTokenStore) GC() error {
	secret, err := tokenStore.logical.List("secret/metadata/accesstokens")
	if err != nil {
		return err
	}

	var userIDs []string
	if secret != nil {
		if keys := secret.Data["keys"]; keys != nil {
			userIDs = cast.ToStringSlice(keys)
		}
	}

	for _, userID := range userIDs {
		tokens, err := tokenStore.list(userID, true)
		if err != nil {
			return err
		}
		for _, token := range tokens {
			if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
				err = tokenStore.Revoke(userID, token.ID)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
