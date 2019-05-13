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

package vault

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/vault/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
)

const (
	serviceAccountFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	initialTokenTimeout = 10 * time.Second
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
	client       *vaultapi.Client
	logical      *vaultapi.Logical
	tokenRenewer *vaultapi.Renewer
	closed       bool
	watch        *fsnotify.Watcher
	mu           sync.Mutex
}

// NewClient creates a new Vault client
func NewClient(role string) (*Client, error) {
	return NewClientWithConfig(vaultapi.DefaultConfig(), role, "kubernetes")
}

// NewClientWithConfig creates a new Vault client with custom configuration
func NewClientWithConfig(config *vaultapi.Config, role, path string) (*Client, error) {
	rawClient, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}

	client, err := NewClientFromRawClient(rawClient, role, path)
	if err != nil {
		return nil, err
	}

	caCertPath := os.Getenv(vaultapi.EnvVaultCACert)
	caCertReload := os.Getenv("VAULT_CACERT_RELOAD") != "false"

	if caCertPath != "" && caCertReload {
		watch, err := fsnotify.NewWatcher()
		if err != nil {
			return nil, err
		}

		caCertFile := filepath.Clean(caCertPath)
		configDir, _ := filepath.Split(caCertFile)

		_ = watch.Add(configDir)

		go func() {
			for {
				client.mu.Lock()
				if client.closed {
					client.mu.Unlock()
					break
				}
				client.mu.Unlock()

				select {
				case event := <-watch.Events:
					// we only care about the CA cert file or the Secret mount directory (if in Kubernetes)
					if filepath.Clean(event.Name) == caCertFile || filepath.Base(event.Name) == "..data" {
						if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
							err := config.ReadEnvironment()
							if err != nil {
								logrus.Println("failed to reload Vault config:", err)
							} else {
								logrus.Println("CA certificate reloaded")
							}
						}
					}
				case err := <-watch.Errors:
					logrus.Println("watcher error:", err)
				}
			}
		}()

		client.watch = watch
	}

	return client, nil
}

// NewClientFromRawClient creates a new Vault client from custom raw client.
func NewClientFromRawClient(rawClient *vaultapi.Client, role, path string) (*Client, error) {
	logical := rawClient.Logical()
	var tokenRenewer *vaultapi.Renewer

	client := &Client{client: rawClient, logical: logical}

	if rawClient.Token() == "" {
		tokenPath := os.Getenv("HOME") + "/.vault-token"
		if env, ok := os.LookupEnv("VAULT_TOKEN_PATH"); ok {
			tokenPath = env
		}

		token, err := ioutil.ReadFile(tokenPath)
		if err == nil {
			rawClient.SetToken(string(token))
		} else {
			// If VAULT_TOKEN, VAULT_TOKEN_PATH or ~/.vault-token wasn't provided let's
			// suppose we are in Kubernetes and try to get one with the ServiceAccount token.

			// Check that we are in Kubernetes
			_, err := rest.InClusterConfig()
			if err != nil {
				return nil, err
			}

			jwt, err := ioutil.ReadFile(serviceAccountFile)
			if err != nil {
				return nil, err
			}

			initialTokenArrived := make(chan string, 1)
			initialTokenSent := false

			go func() {
				for {
					client.mu.Lock()
					if client.closed {
						client.mu.Unlock()
						break
					}
					client.mu.Unlock()

					data := map[string]interface{}{"jwt": string(jwt), "role": role}

					secret, err := logical.Write(fmt.Sprintf("auth/%s/login", path), data)
					if err != nil {
						log.Println("Failed to request new Vault token", err.Error())
						time.Sleep(1 * time.Second)
						continue
					}

					if secret == nil {
						log.Println("Received empty answer from Vault, retrying")
						time.Sleep(1 * time.Second)
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

					client.mu.Lock()
					client.tokenRenewer = tokenRenewer
					client.mu.Unlock()

					go tokenRenewer.Renew()

					runRenewChecker(tokenRenewer)
				}
				log.Println("Vault token renewal closed")
			}()

			select {
			case <-initialTokenArrived:
				log.Println("Initial Vault token arrived")

			case <-time.After(initialTokenTimeout):
				client.Close()
				return nil, fmt.Errorf("timeout [%s] during waiting for Vault token", initialTokenTimeout)
			}
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

// Vault returns the underlying hashicorp Vault client.
// Deprecated: use RawClient instead.
func (client *Client) Vault() *vaultapi.Client {
	return client.RawClient()
}

// RawClient returns the underlying raw Vault client.
func (client *Client) RawClient() *vaultapi.Client {
	return client.client
}

// Close stops the token renewing process of this client
func (client *Client) Close() {
	client.mu.Lock()
	defer client.mu.Unlock()

	if client.tokenRenewer != nil {
		client.closed = true
		client.tokenRenewer.Stop()
	}

	if client.watch != nil {
		_ = client.watch.Close()
	}
}

// NewRawClient creates a new raw Vault client.
func NewRawClient() (*api.Client, error) {
	config := vaultapi.DefaultConfig()
	if config.Error != nil {
		return nil, config.Error
	}

	config.HttpClient.Transport.(*http.Transport).TLSHandshakeTimeout = 5 * time.Second

	return vaultapi.NewClient(config)
}
