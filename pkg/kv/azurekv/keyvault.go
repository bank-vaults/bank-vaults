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
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"emperror.dev/errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/Azure/go-autorest/autorest/azure/auth"

	"github.com/bank-vaults/bank-vaults/pkg/kv"
)

// azureKeyVault is an implementation of the kv.Service interface, that encrypts
// and decrypts and stores data using Azure Key Vault.
type azureKeyVault struct {
	client *azsecrets.Client
}

var _ kv.Service = &azureKeyVault{}

// New creates a new kv.Service backed by Azure Key Vault
func New(name string) (kv.Service, error) {
	if name == "" {
		return nil, errors.Errorf("invalid Key Vault specified: '%s'", name)
	}

	// File based auth is not supported in the new SDK, hence this workaround
	if _, ok := os.LookupEnv("AZURE_AUTH_LOCATION"); ok {
		settings, err := auth.GetSettingsFromFile()
		if err != nil {
			log.Fatal(err)
		}
		os.Setenv(auth.TenantID, settings.Values[auth.TenantID])
		os.Setenv(auth.ClientID, settings.Values[auth.ClientID])
		os.Setenv(auth.ClientSecret, settings.Values[auth.ClientSecret])
	}

	// Create a credential using the NewDefaultAzureCredential type.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}

	// Establish a connection to the Key Vault client
	vaultBaseURL := fmt.Sprintf("https://%s.%s", name, "vault.azure.net")
	client, err := azsecrets.NewClient(vaultBaseURL, cred, nil)
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
	parameters := azsecrets.SetSecretParameters{Value: &value}
	_, err := a.client.SetSecret(context.Background(), key, parameters, nil)
	return errors.Wrapf(err, "failed to set key: %s", key)
}
