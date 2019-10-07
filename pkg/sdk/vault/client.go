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
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/vault/api"
	vaultapi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
)

const (
	serviceAccountFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	initialTokenTimeout = 10 * time.Second
)

var logger *log.Logger

// NewData is a helper function for Vault KV Version two secret data creation
func NewData(cas int, data map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"options": map[string]interface{}{"cas": cas},
		"data":    data,
	}
}

type clientOptions struct {
	url       string
	role      string
	authPath  string
	tokenPath string
	token     string
}

// ClientOption configures a Vault client using the functional options paradigm popularized by Rob Pike and Dave Cheney.
// If you're unfamiliar with this style,
// see https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html and
// https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis.
type ClientOption interface {
	apply(o *clientOptions)
}

// ClientURL is the vault url EX: https://my-vault.vault.org
type ClientURL string

func (co ClientURL) apply(o *clientOptions) {
	o.url = string(co)
}

// ClientRole is the vault role which the client would like to receive
type ClientRole string

func (co ClientRole) apply(o *clientOptions) {
	o.role = string(co)
}

// ClientAuthPath is the mount path where the auth method is enabled.
type ClientAuthPath string

func (co ClientAuthPath) apply(o *clientOptions) {
	o.authPath = string(co)
}

// ClientTokenPath file where the Vault token can be found.
type ClientTokenPath string

func (co ClientTokenPath) apply(o *clientOptions) {
	o.tokenPath = string(co)
}

// ClientToken is a Vault token.
type ClientToken string

func (co ClientToken) apply(o *clientOptions) {
	o.token = string(co)
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

// NewClient creates a new Vault client.
func NewClient(role string) (*Client, error) {
	return NewClientWithOptions(ClientRole(role))
}

// NewClientWithOptions creates a new Vault client with custom options.
func NewClientWithOptions(opts ...ClientOption) (*Client, error) {
	return NewClientFromConfig(vaultapi.DefaultConfig(), opts...)
}

// NewClientWithConfig creates a new Vault client with custom configuration.
// Deprecated: use NewClientFromConfig instead.
func NewClientWithConfig(config *vaultapi.Config, role, path string) (*Client, error) {
	return NewClientFromConfig(config, ClientRole(role), ClientAuthPath(path))
}

// NewClientFromConfig creates a new Vault client from custom configuration.
func NewClientFromConfig(config *vaultapi.Config, opts ...ClientOption) (*Client, error) {
	enableJSONLog := os.Getenv("VAULT_JSON_LOG")

	logger = log.New()
	if enableJSONLog == "true" {
		logger.SetFormatter(&log.JSONFormatter{})
	}

	rawClient, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}

	client, err := NewClientFromRawClient(rawClient, opts...)
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
								logger.Println("failed to reload Vault config:", err)
							} else {
								logger.Println("CA certificate reloaded")
							}
						}
					}
				case err := <-watch.Errors:
					logger.Println("watcher error:", err)
				}
			}
		}()

		client.watch = watch
	}

	return client, nil
}

// NewClientFromRawClient creates a new Vault client from custom raw client.
func NewClientFromRawClient(rawClient *vaultapi.Client, opts ...ClientOption) (*Client, error) {
	logical := rawClient.Logical()
	client := &Client{client: rawClient, logical: logical}

	var tokenRenewer *vaultapi.Renewer

	o := &clientOptions{}

	for _, opt := range opts {
		opt.apply(o)
	}

	// Default URL
	if o.url == "" {
		o.url = vaultapi.DefaultConfig().Address
	}

	// Default role
	if o.role == "" {
		o.role = "default"
	}

	// Default auth path
	if o.authPath == "" {
		o.authPath = "kubernetes"
	}

	// Default token path
	if o.tokenPath == "" {
		o.tokenPath = os.Getenv("HOME") + "/.vault-token"
		if env, ok := os.LookupEnv("VAULT_TOKEN_PATH"); ok {
			o.tokenPath = env
		}
	}

	rawClient.SetAddress(o.url)

	// Add token if set
	if o.token != "" {
		rawClient.SetToken(o.token)

	} else if rawClient.Token() == "" {
		token, err := ioutil.ReadFile(o.tokenPath)
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

					data := map[string]interface{}{"jwt": string(jwt), "role": o.role}

					secret, err := logical.Write(fmt.Sprintf("auth/%s/login", o.authPath), data)
					if err != nil {
						logger.Println("Failed to request new Vault token", err.Error())
						time.Sleep(1 * time.Second)
						continue
					}

					if secret == nil {
						logger.Println("Received empty answer from Vault, retrying")
						time.Sleep(1 * time.Second)
						continue
					}

					logger.Println("Received new Vault token")

					// Set the first token from the response
					rawClient.SetToken(secret.Auth.ClientToken)

					if !initialTokenSent {
						initialTokenArrived <- secret.LeaseID
						initialTokenSent = true
					}

					// Start the renewing process
					tokenRenewer, err = rawClient.NewRenewer(&vaultapi.RenewerInput{Secret: secret})
					if err != nil {
						logger.Println("Failed to renew Vault token", err.Error())
						continue
					}

					client.mu.Lock()
					client.tokenRenewer = tokenRenewer
					client.mu.Unlock()

					go tokenRenewer.Renew()

					runRenewChecker(tokenRenewer)
				}
				logger.Println("Vault token renewal closed")
			}()

			select {
			case <-initialTokenArrived:
				logger.Println("Initial Vault token arrived")

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
				logger.Println("Vault token renewal error:", err.Error())
			}
			return
		case <-tokenRenewer.RenewCh():
			logger.Printf("Renewed Vault Token")
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
