package keyvault

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

// azureKeyVault is an implementation of the kv.Service interface, that encrypts
// and decrypts and stores data using Azure Key Vault.
type azureKeyVault struct {
	client       *keyvault.BaseClient
	vaultBaseURL string
}

var _ kv.Service = &azureKeyVault{}

func New(name string) (kv.Service, error) {
	keyClient := keyvault.New()
	authorizer, err := GetKeyvaultAuthorizer()
	if err != nil {
		return nil, err
	}
	keyClient.Authorizer = authorizer
	return &azureKeyVault{
		client:       &keyClient,
		vaultBaseURL: fmt.Sprintf("https://%s.vault.azure.net", name),
	}, nil
}

func (g *azureKeyVault) Get(key string) ([]byte, error) {

	bundle, err := g.client.GetSecret(context.Background(), g.vaultBaseURL, key, "")

	if err != nil {
		err := err.(autorest.DetailedError)
		if err.StatusCode == http.StatusNotFound {
			return nil, kv.NewNotFoundError("error getting secret for key '%s': %s", key, err.Error())
		}
		return nil, err
	}

	return []byte(*bundle.Value), nil
}

func (g *azureKeyVault) Set(key string, val []byte) error {

	value := string(val)
	parameters := keyvault.SecretSetParameters{
		Value: &value,
	}

	_, err := g.client.SetSecret(context.Background(), g.vaultBaseURL, key, parameters)

	return err
}

func (g *azureKeyVault) Test(key string) error {
	// TODO: Implement me properly
	return nil
}
