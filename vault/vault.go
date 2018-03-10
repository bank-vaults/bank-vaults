package vault

import (
	"io/ioutil"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
	"k8s.io/client-go/rest"
)

// Client is a Vault client with Kubernetes support and token automatic renewing
type Client struct {
	client       *vaultapi.Client
	logical      *vaultapi.Logical
	tokenRenewer *vaultapi.Renewer
}

// Creates a new Vault client
func NewClient(role string) (*Client, error) {
	return NewClientWithConfig(vaultapi.DefaultConfig(), role)
}

func NewClientWithConfig(config *vaultapi.Config, role string) (*Client, error) {
	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	logical := client.Logical()
	var tokenRenewer *vaultapi.Renewer

	if client.Token() == "" {

		token, err := ioutil.ReadFile(os.Getenv("HOME") + "/.vault-token")

		if err == nil {

			client.SetToken(string(token))

		} else {
			// If VAULT_TOKEN or ~/.vault-token wasn't provided let's suppose
			// we are in Kubernetes and try to get one with the ServiceAccount token

			k8sconfig, err := rest.InClusterConfig()
			if err != nil {
				return nil, err
			}

			data := map[string]interface{}{"jwt": k8sconfig.BearerToken, "role": role}
			secret, err := logical.Write("auth/kubernetes/login", data)
			if err != nil {
				return nil, err
			}

			tokenRenewer, err = client.NewRenewer(&vaultapi.RenewerInput{Secret: secret})
			if err != nil {
				return nil, err
			}

			// We never really want to stop this
			go tokenRenewer.Renew()

			// Finally set the first token from the response
			client.SetToken(secret.Auth.ClientToken)
		}
	}

	return &Client{client: client, logical: logical, tokenRenewer: tokenRenewer}, nil
}

func (client *Client) Vault() *vaultapi.Client {
	return client.client
}

// Close stops the token renewing process of this client
func (client *Client) Close() {
	if client.tokenRenewer != nil {
		client.tokenRenewer.Stop()
	}
}
