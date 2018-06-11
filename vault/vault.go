package vault

import (
	"io/ioutil"
	"log"
	"os"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"
	"k8s.io/client-go/rest"
)

// NewData is a helper function for Vault KV Version two secret data creation
func NewData(cas int, data map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"options": map[string]interface{}{"cas": cas},
		"data":    data,
	}
}

// Client is a Vault client with Kubernetes support and token automatic renewing
type Client struct {
	sync.Mutex
	client       *vaultapi.Client
	logical      *vaultapi.Logical
	tokenRenewer *vaultapi.Renewer
	closed       bool
}

// NewClient creates a new Vault client
func NewClient(role string) (*Client, error) {
	return NewClientWithConfig(vaultapi.DefaultConfig(), role)
}

// NewClientWithConfig creates a new Vault client with custom configuration
func NewClientWithConfig(config *vaultapi.Config, role string) (*Client, error) {
	rawClient, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	logical := rawClient.Logical()
	var tokenRenewer *vaultapi.Renewer

	client := &Client{client: rawClient, logical: logical}

	if rawClient.Token() == "" {

		token, err := ioutil.ReadFile(os.Getenv("HOME") + "/.vault-token")

		if err == nil {

			rawClient.SetToken(string(token))

		} else {
			// If VAULT_TOKEN or ~/.vault-token wasn't provided let's suppose
			// we are in Kubernetes and try to get one with the ServiceAccount token

			k8sconfig, err := rest.InClusterConfig()
			if err != nil {
				return nil, err
			}

			initialTokenArrived := make(chan string, 1)
			initialTokenSent := false

			go func() {
				for {
					client.Lock()
					if client.closed {
						client.Unlock()
						break
					}
					client.Unlock()

					data := map[string]interface{}{"jwt": k8sconfig.BearerToken, "role": role}
					secret, err := logical.Write("auth/kubernetes/login", data)
					if err != nil {
						log.Println("Failed to request new Vault token", err.Error())
						continue
					}

					log.Println("Received new Vault token")

					// Set the first token from the response
					rawClient.SetToken(secret.Auth.ClientToken)

					if !initialTokenSent {
						initialTokenArrived <- secret.LeaseID
						initialTokenSent = true
					}

					// Start the renewing process
					tokenRenewer, err = rawClient.NewRenewer(&vaultapi.RenewerInput{Secret: secret})
					if err != nil {
						log.Println("Failed to renew Vault token", err.Error())
						continue
					}

					client.Lock()
					client.tokenRenewer = tokenRenewer
					client.Unlock()

					go tokenRenewer.Renew()

					runRenewChecker(tokenRenewer)
				}
				log.Println("Vault token renewal closed")
			}()

			<-initialTokenArrived
		}
	}

	return client, nil
}

func runRenewChecker(tokenRenewer *vaultapi.Renewer) {
	for {
		select {
		case err := <-tokenRenewer.DoneCh():
			if err != nil {
				log.Println("Vault token renewal error:", err.Error())
			}
			return
		case <-tokenRenewer.RenewCh():
			log.Printf("Renewed Vault Token")
		}
	}
}

// Vault returns the underlying hashicorp Vault client
func (client *Client) Vault() *vaultapi.Client {
	return client.client
}

// Close stops the token renewing process of this client
func (client *Client) Close() {
	client.Lock()
	defer client.Unlock()
	if client.tokenRenewer != nil {
		client.closed = true
		client.tokenRenewer.Stop()
	}
}
