package vault

import (
	"io/ioutil"
	"log"
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

// NewClient creates a new Vault client
func NewClient(role string) (*Client, error) {
	return NewClientWithConfig(vaultapi.DefaultConfig(), role)
}

// NewClientWithConfig creates a new Vault client with custom configuration
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

			initialTokenArrived := make(chan string, 1)

			go func() {
				for {
					data := map[string]interface{}{"jwt": k8sconfig.BearerToken, "role": role}
					secret, err := logical.Write("auth/kubernetes/login", data)
					if err != nil {
						log.Println(err.Error())
						continue
					}

					log.Println("Received new Vault token")

					// Set the first token from the response
					client.SetToken(secret.Auth.ClientToken)

					initialTokenArrived <- secret.LeaseID

					// Start the renewing process
					tokenRenewer, err = client.NewRenewer(&vaultapi.RenewerInput{Secret: secret})
					if err != nil {
						log.Println(err.Error())
						continue
					}

					go tokenRenewer.Renew()

					runRenewChecker(tokenRenewer)
				}
			}()

			<-initialTokenArrived
		}
	}

	return &Client{client: client, logical: logical, tokenRenewer: tokenRenewer}, nil
}

func runRenewChecker(tokenRenewer *vaultapi.Renewer) {
	for {
		select {
		case err := <-tokenRenewer.DoneCh():
			if err != nil {
				log.Println("Renew error:", err.Error())
				return
			}
		case renewal := <-tokenRenewer.RenewCh():
			log.Printf("Successfully renewed at: %s", renewal.RenewedAt)
		}
	}
}

// Vault returns the underlying hashicorp Vault client
func (client *Client) Vault() *vaultapi.Client {
	return client.client
}

// Close stops the token renewing process of this client
func (client *Client) Close() {
	if client.tokenRenewer != nil {
		log.Println("Stopped Vault tokenRenewer")
		client.tokenRenewer.Stop()
	}
}
