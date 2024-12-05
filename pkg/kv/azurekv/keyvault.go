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

package azurekv

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"unicode/utf16"

	"emperror.dev/errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/dimchansky/utfbom"

	"github.com/bank-vaults/bank-vaults/pkg/kv"
)

const AzureAuthLocation = "AZURE_AUTH_LOCATION"

// azureKeyVault is an implementation of the kv.Service interface, that encrypts
// and decrypts and stores data using Azure Key Vault.
type azureKeyVault struct {
	client *azsecrets.Client
}

type AuthConfig struct {
	TenantID     string `json:"tenantId"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

var _ kv.Service = &azureKeyVault{}

// New creates a new kv.Service backed by Azure Key Vault
func New(name string) (kv.Service, error) {
	if name == "" {
		return nil, errors.Errorf("invalid Key Vault specified: '%s'", name)
	}

	cred, err := NewAzureAuthCredentials()
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}

	// Establish a connection to the Key Vault client
	client, err := azsecrets.NewClient(fmt.Sprintf("https://%s.%s", name, "vault.azure.net"), cred, nil)
	if err != nil {
		log.Fatalf("failed to create Key Vault client: %v", err)
	}

	return &azureKeyVault{
		client: client,
	}, nil
}

func (a *azureKeyVault) Get(key string) ([]byte, error) {
	bundle, err := a.client.GetSecret(context.Background(), key, "", nil)
	if err != nil {
		var aerr *azcore.ResponseError
		if errors.As(err, &aerr) && aerr.StatusCode == http.StatusNotFound {
			return nil, kv.NewNotFoundError("error getting secret for key '%s': %s", key, err.Error())
		}

		return nil, errors.Wrapf(err, "failed to get key: %s", key)
	}

	return []byte(*bundle.Value), nil
}

func (a *azureKeyVault) Set(key string, val []byte) error {
	value := string(val)
	_, err := a.client.SetSecret(context.Background(), key, azsecrets.SetSecretParameters{Value: &value}, nil)
	return errors.Wrapf(err, "failed to set key: %s", key)
}

type AzureAuthCredentials struct {
	creds map[string]azcore.TokenCredential
}

func (d *AzureAuthCredentials) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	var errorMessages []string
	for name, cred := range d.creds {
		if cred != nil {
			token, err := cred.GetToken(ctx, options)
			if err != nil {
				errorMessages = append(errorMessages, name+": "+err.Error())
			} else {
				return token, nil
			}
		} else {
			errorMessages = append(errorMessages, name+": nil")
		}
	}

	return azcore.AccessToken{}, errors.Errorf("failed to obtain a token: %s", strings.Join(errorMessages, "\n"))
}

func NewAzureAuthCredentials() (*AzureAuthCredentials, error) {
	var errorMessages []string
	creds := make(map[string]azcore.TokenCredential)
	defaultCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		errorMessages = append(errorMessages, "DefaultCredential: "+err.Error())
	}
	creds["DefaultCredential"] = defaultCred

	fileBasedCred, err := NewFileBasedCredential()
	if err != nil {
		errorMessages = append(errorMessages, "FileBasedCredential: "+err.Error())
	}
	creds["FileBasedCredential"] = fileBasedCred

	if len(errorMessages) == 2 {
		return nil, errors.Errorf("failed to obtain a credential: %v", strings.Join(errorMessages, "\n"))
	}

	return &AzureAuthCredentials{creds: creds}, nil
}

func NewFileBasedCredential() (azcore.TokenCredential, error) {
	// Implementation based on github.com/Azure/go-autorest/autorest/azure/auth.GetSettingsFromFile()
	fileLocation := os.Getenv(AzureAuthLocation)
	if fileLocation == "" {
		return nil, errors.Errorf("environment variable %s is not set", AzureAuthLocation)
	}

	contents, err := os.ReadFile(fileLocation)
	if err != nil {
		return nil, err
	}

	// Auth file might be encoded
	decoded, err := decode(contents)
	if err != nil {
		return nil, err
	}

	var authFile AuthConfig
	err = json.Unmarshal(decoded, &authFile)
	if err != nil {
		return nil, err
	}

	cred, err := azidentity.NewClientSecretCredential(authFile.TenantID, authFile.ClientID, authFile.ClientSecret, nil)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

//nolint:exhaustive
func decode(b []byte) ([]byte, error) {
	reader, enc := utfbom.Skip(bytes.NewReader(b))
	switch enc {
	case utfbom.UTF16LittleEndian:
		u16 := make([]uint16, (len(b)/2)-1)
		err := binary.Read(reader, binary.LittleEndian, &u16)
		if err != nil {
			return nil, err
		}
		return []byte(string(utf16.Decode(u16))), nil

	case utfbom.UTF16BigEndian:
		u16 := make([]uint16, (len(b)/2)-1)
		err := binary.Read(reader, binary.BigEndian, &u16)
		if err != nil {
			return nil, err
		}
		return []byte(string(utf16.Decode(u16))), nil
	}

	return io.ReadAll(reader)
}
