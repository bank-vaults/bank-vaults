// Copyright © 2020 Banzai Cloud
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
	"context"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/vault/api"
	vaultapi "github.com/hashicorp/vault/api"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
	"k8s.io/client-go/rest"
)

const (
	awsEC2PKCS7Url = "http://169.254.169.254/latest/dynamic/instance-identity/pkcs7"
	defaultJWTFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// NewData is a helper function for Vault KV Version two secret data creation
func NewData(cas int, data map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"options": map[string]interface{}{"cas": cas},
		"data":    data,
	}
}

type clientOptions struct {
	url        string
	role       string
	authPath   string
	tokenPath  string
	token      string
	timeout    time.Duration
	logger     Logger
	authMethod ClientAuthMethod
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

// ClientTimeout after which the client fails.
type ClientTimeout time.Duration

func (co ClientTimeout) apply(o *clientOptions) {
	o.timeout = time.Duration(co)
}

// ClientLogger wraps a logur.Logger compatible logger to be used in the client.
func ClientLogger(logger Logger) clientLogger {
	return clientLogger{logger: logger}
}

type clientLogger struct {
	logger Logger
}

func (co clientLogger) apply(o *clientOptions) {
	o.logger = co.logger
}

// ClientAuthMethod file where the Vault token can be found.
type ClientAuthMethod string

func (co ClientAuthMethod) apply(o *clientOptions) {
	o.authMethod = co
}

const (
	// AWSEC2AuthMethod is used for the Vault AWS EC2 auth method
	// as described here: https://www.vaultproject.io/docs/auth/aws#ec2-auth-method
	AWSEC2AuthMethod ClientAuthMethod = "aws-ec2"

	// GCPGCEAuthMethod is used for the Vault GCP GCE auth method
	// as described here: https://www.vaultproject.io/docs/auth/gcp#gce-login
	GCPGCEAuthMethod ClientAuthMethod = "gcp-gce"

	// JWTAuthMethod is used for the Vault JWT/OIDC/GCP/Kubernetes auth methods
	// as describe here:
	// - https://www.vaultproject.io/docs/auth/jwt
	// - https://www.vaultproject.io/docs/auth/kubernetes
	// - https://www.vaultproject.io/docs/auth/gcp
	JWTAuthMethod ClientAuthMethod = "jwt"
)

// Client is a Vault client with Kubernetes support, token automatic renewing and
// access to Transit Secret Engine wrapper
type Client struct {
	// Easy to use wrapper for transit secret engine calls
	Transit *Transit

	client       *vaultapi.Client
	logical      *vaultapi.Logical
	tokenRenewer *vaultapi.Renewer
	closed       bool
	watch        *fsnotify.Watcher
	mu           sync.Mutex
	logger       Logger
}

// NewClient creates a new Vault client.
func NewClient(role string) (*Client, error) {
	return NewClientWithOptions(ClientRole(role))
}

// NewClientWithOptions creates a new Vault client with custom options.
func NewClientWithOptions(opts ...ClientOption) (*Client, error) {
	config := vaultapi.DefaultConfig()
	if config.Error != nil {
		return nil, config.Error
	}
	return NewClientFromConfig(config, opts...)
}

// NewClientWithConfig creates a new Vault client with custom configuration.
// Deprecated: use NewClientFromConfig instead.
func NewClientWithConfig(config *vaultapi.Config, role, path string) (*Client, error) {
	return NewClientFromConfig(config, ClientRole(role), ClientAuthPath(path))
}

// NewClientFromConfig creates a new Vault client from custom configuration.
func NewClientFromConfig(config *vaultapi.Config, opts ...ClientOption) (*Client, error) {
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
								client.logger.Error("failed to reload Vault config", map[string]interface{}{"err": err})
							} else {
								client.logger.Info("CA certificate reloaded")
							}
						}
					}
				case err := <-watch.Errors:
					client.logger.Error("watcher error", map[string]interface{}{"err": err})
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
	transit := &Transit{
		client: rawClient,
	}
	client := &Client{
		Transit: transit,
		client:  rawClient,
		logical: logical,
		logger:  noopLogger{},
	}

	var tokenRenewer *vaultapi.Renewer

	o := &clientOptions{}

	for _, opt := range opts {
		opt.apply(o)
	}

	// Set logger
	if o.logger != nil {
		client.logger = o.logger
	}

	// Set URL if defined
	if o.url != "" {
		err := rawClient.SetAddress(o.url)
		if err != nil {
			return nil, err
		}
	}

	// Default role
	if o.role == "" {
		o.role = "default"
	}

	// Default auth path
	if o.authPath == "" {
		o.authPath = "kubernetes"
	}

	if o.authMethod == "" {
		o.authMethod = JWTAuthMethod
	}

	// Default token path
	if o.tokenPath == "" {
		o.tokenPath = os.Getenv("HOME") + "/.vault-token"
		if env, ok := os.LookupEnv("VAULT_TOKEN_PATH"); ok {
			o.tokenPath = env
		}
	}

	// Default timeout
	if o.timeout == 0 {
		o.timeout = 10 * time.Second
		if env, ok := os.LookupEnv("VAULT_CLIENT_TIMEOUT"); ok {
			var err error
			if o.timeout, err = time.ParseDuration(env); err != nil {
				return nil, errors.Wrap(err, "could not parse timeout duration")
			}
		}
	}

	// Add token if set
	if o.token != "" {
		rawClient.SetToken(o.token)
	} else if rawClient.Token() == "" {
		token, err := ioutil.ReadFile(o.tokenPath)
		if err == nil {
			rawClient.SetToken(string(token))
		} else {
			// If VAULT_TOKEN, VAULT_TOKEN_PATH or ~/.vault-token wasn't provided let's
			// suppose we are in Kubernetes and try to get one with the Kubernetes ServiceAccount JWT.
			//
			// This logic works for for Vault GCP authentication as well, see:
			// https://www.vaultproject.io/api/auth/gcp#login

			// Check that we are in Kubernetes
			_, err := rest.InClusterConfig()
			if err != nil {
				return nil, err
			}

			jwtFile := defaultJWTFile
			if file := os.Getenv("KUBERNETES_SERVICE_ACCOUNT_TOKEN"); file != "" {
				jwtFile = file
			} else if file := os.Getenv("VAULT_JWT_FILE"); file != "" {
				jwtFile = file
			}

			var loginDataFunc func() (map[string]interface{}, error)

			switch o.authMethod {
			case AWSEC2AuthMethod:
				loginDataFunc = func() (map[string]interface{}, error) {
					resp, err := http.Get(awsEC2PKCS7Url)
					if err != nil {
						return nil, err
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						return nil, errors.Errorf("failed to get EC2 instance metadata: %s", resp.Status)
					}

					pkcs7Data, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						return nil, err
					}

					pkcs7 := strings.ReplaceAll(string(pkcs7Data), "\n", "")

					jwt, err := ioutil.ReadFile(jwtFile)
					if err != nil {
						return nil, err
					}

					nonce := fmt.Sprintf("%x", sha256.Sum256(jwt))

					return map[string]interface{}{
						"pkcs7": pkcs7,
						"nonce": nonce,
						"role":  o.role,
					}, nil
				}

			case GCPGCEAuthMethod:
				loginDataFunc = func() (map[string]interface{}, error) {
					tokenSource, err := google.DefaultTokenSource(context.TODO(), iam.CloudPlatformScope)
					if err != nil {
						return nil, err
					}

					jwt, err := tokenSource.Token()
					if err != nil {
						return nil, err
					}

					return map[string]interface{}{
						"jwt":  jwt,
						"role": o.role,
					}, nil
				}

			default:
				loginDataFunc = func() (map[string]interface{}, error) {
					// Projected SA JWTs do expire, so we need to move the reading logic into the loop
					jwt, err := ioutil.ReadFile(jwtFile)
					if err != nil {
						return nil, err
					}

					return map[string]interface{}{
						"jwt":  string(jwt),
						"role": o.role,
					}, nil
				}
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

					// Projected SA JWTs do expire, so we need to move the reading logic into the loop
					loginData, err := loginDataFunc()
					if err != nil {
						client.logger.Error("failed to read login data", map[string]interface{}{
							"err":  err,
							"type": o.authMethod,
						})
						continue
					}

					secret, err := logical.Write(fmt.Sprintf("auth/%s/login", o.authPath), loginData)
					if err != nil {
						client.logger.Error("failed to request new Vault token", map[string]interface{}{"err": err})
						time.Sleep(1 * time.Second)
						continue
					}

					if secret == nil {
						client.logger.Debug("received empty answer from Vault, retrying")
						time.Sleep(1 * time.Second)
						continue
					}

					client.logger.Info("received new Vault token")

					// Set the first token from the response
					rawClient.SetToken(secret.Auth.ClientToken)

					if !initialTokenSent {
						initialTokenArrived <- secret.LeaseID
						initialTokenSent = true
					}

					// Start the renewing process
					tokenRenewer, err = rawClient.NewRenewer(&vaultapi.RenewerInput{Secret: secret})
					if err != nil {
						client.logger.Error("failed to renew Vault token", map[string]interface{}{"err": err})
						continue
					}

					client.mu.Lock()
					client.tokenRenewer = tokenRenewer
					client.mu.Unlock()

					go tokenRenewer.Renew()

					client.runRenewChecker(tokenRenewer)
				}

				client.logger.Info("Vault token renewal closed")
			}()

			select {
			case <-initialTokenArrived:
				client.logger.Info("initial Vault token arrived")

			case <-time.After(o.timeout):
				client.Close()
				return nil, errors.Errorf("timeout [%s] during waiting for Vault token", o.timeout)
			}
		}
	}

	return client, nil
}

func (client *Client) runRenewChecker(tokenRenewer *vaultapi.Renewer) {
	for {
		select {
		case err := <-tokenRenewer.DoneCh():
			if err != nil {
				client.logger.Error("error in Vault token renewal", map[string]interface{}{"err": err})
			}
			return
		case o := <-tokenRenewer.RenewCh():
			ttl, _ := o.Secret.TokenTTL()
			client.logger.Info("renewed Vault token", map[string]interface{}{"ttl": ttl})
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

	client.closed = true

	if client.tokenRenewer != nil {
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

// NewInsecureRawClient creates a new raw Vault client with insecure TLS.
func NewInsecureRawClient() (*api.Client, error) {
	config := vaultapi.DefaultConfig()
	if config.Error != nil {
		return nil, config.Error
	}

	config.HttpClient.Transport.(*http.Transport).TLSHandshakeTimeout = 5 * time.Second
	config.HttpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true

	return vaultapi.NewClient(config)
}
