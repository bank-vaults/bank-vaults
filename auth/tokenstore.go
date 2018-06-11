package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/spf13/cast"

	"github.com/banzaicloud/bank-vaults/vault"
	vaultapi "github.com/hashicorp/vault/api"
)

// Verify tokenstores satisfy the correct interface
var _ TokenStore = (*inMemoryTokenStore)(nil)
var _ TokenStore = (*vaultTokenStore)(nil)

// Token represents an access token
type Token struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt *time.Time `json:"createdAt,omitempty"`
}

// TokenStore is general interface for storing access tokens
type TokenStore interface {
	Store(userID string, token *Token) error
	Lookup(userID string, tokenID string) (*Token, error)
	Revoke(userID string, tokenID string) error
	List(userID string) ([]*Token, error)
}

// NewToken Creates a new Token instance initialized ID and Name and CreatedAt fields
func NewToken(id, name string) *Token {
	return &Token{ID: id, Name: name}
}

func parseToken(secret *vaultapi.Secret) (*Token, error) {
	if secret == nil {
		return nil, fmt.Errorf("Can't find Secret")
	}
	data := cast.ToStringMap(secret.Data["data"])
	metadata := cast.ToStringMap(secret.Data["metadata"])
	if tokenData, ok := data["token"]; ok {
		tokenData := tokenData.(map[string]interface{})
		token := &Token{}
		token.ID = tokenData["id"].(string)
		token.Name = tokenData["name"].(string)
		createdAt, err := time.Parse(time.RFC3339, metadata["created_time"].(string))
		if err != nil {
			return nil, err
		}
		token.CreatedAt = &createdAt
		return token, nil
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
	logical := client.Vault().Logical()
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
	secret, err := tokenStore.logical.Read(tokenDataPath(userID, tokenID))
	if err != nil {
		return nil, err
	}
	return parseToken(secret)
}

func (tokenStore vaultTokenStore) Revoke(userID, tokenID string) error {
	_, err := tokenStore.logical.Delete(tokenMetadataPath(userID, tokenID))
	return err
}

func (tokenStore vaultTokenStore) List(userID string) ([]*Token, error) {
	secret, err := tokenStore.logical.List(fmt.Sprintf("secret/metadata/accesstokens/%s", userID))
	if err != nil {
		return nil, err
	}

	var keys []interface{}
	if secret != nil {
		if keysi := secret.Data["keys"]; keysi != nil {
			keys = keysi.([]interface{})
		}
	}
	tokens := make([]*Token, len(keys))

	for i, tokenID := range keys {
		token, err := tokenStore.Lookup(userID, tokenID.(string))
		if err != nil {
			return nil, err
		}
		tokens[i] = token
	}
	return tokens, nil
}
