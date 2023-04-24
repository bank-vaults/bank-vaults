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
	vaultapi "github.com/hashicorp/vault/api"

	"github.com/bank-vaults/vault-sdk/vault"
)

// NewData is a helper function for Vault KV Version two secret data creation.
//
// Deprecated: use [vault.NewData] instead.
func NewData(cas int, data map[string]interface{}) map[string]interface{} {
	return vault.NewData(cas, data)
}

// ClientOption configures a Vault client using the functional options paradigm popularized by Rob Pike and Dave Cheney.
// If you're unfamiliar with this style,
// see https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html and
// https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis.
//
// Deprecated: use [vault.ClientOption] instead.
type ClientOption = vault.ClientOption

// ClientURL is the vault url EX: https://my-vault.vault.org
//
// Deprecated: use [vault.ClientURL] instead.
type ClientURL = vault.ClientURL

// ClientRole is the vault role which the client would like to receive.
//
// Deprecated: use [vault.ClientRole] instead.
type ClientRole = vault.ClientRole

// ClientAuthPath is the mount path where the auth method is enabled.
//
// Deprecated: use [vault.ClientAuthPath] instead.
type ClientAuthPath = vault.ClientAuthPath

// ClientTokenPath file where the Vault token can be found.
//
// Deprecated: use [vault.ClientTokenPath] instead.
type ClientTokenPath = vault.ClientTokenPath

// ClientToken is a Vault token.
//
// Deprecated: use [vault.ClientToken] instead.
type ClientToken = vault.ClientToken

// ClientTimeout after which the client fails.
//
// Deprecated: use [vault.ClientTimeout] instead.
type ClientTimeout = vault.ClientTimeout

// ClientLogger wraps a logur.Logger compatible logger to be used in the client.
//
// Deprecated: use [vault.ClientLogger] instead.
func ClientLogger(logger Logger) ClientOption {
	return vault.ClientLogger(logger)
}

// ClientAuthMethod file where the Vault token can be found.
//
// Deprecated: use [vault.ClientAuthMethod] instead.
type ClientAuthMethod = vault.ClientAuthMethod

// Deprecated: use [vault.ExistingSecret] instead.
type ExistingSecret = vault.ExistingSecret

// Vault Enterprise Namespace (not Kubernetes namespace).
//
// Deprecated: use [vault.VaultNamespace] instead.
type VaultNamespace = vault.VaultNamespace

const (
	// AWSEC2AuthMethod is used for the Vault AWS EC2 auth method
	// as described here: https://www.vaultproject.io/docs/auth/aws#ec2-auth-method
	//
	// Deprecated: use [vault.AWSEC2AuthMethod] instead.
	AWSEC2AuthMethod ClientAuthMethod = vault.AWSEC2AuthMethod

	// AWSIAMAuthMethod is used for the Vault AWS IAM auth method
	// as described here: https://www.vaultproject.io/docs/auth/aws#iam-auth-method
	//
	// Deprecated: use [vault.AWSIAMAuthMethod] instead.
	AWSIAMAuthMethod ClientAuthMethod = vault.AWSIAMAuthMethod

	// GCPGCEAuthMethod is used for the Vault GCP GCE auth method
	// as described here: https://www.vaultproject.io/docs/auth/gcp#gce-login
	//
	// Deprecated: use [vault.GCPGCEAuthMethod] instead.
	GCPGCEAuthMethod ClientAuthMethod = vault.GCPGCEAuthMethod

	// GCPIAMAuthMethod is used for the Vault GCP IAM auth method
	// as described here: https://www.vaultproject.io/docs/auth/gcp#iam
	//
	// Deprecated: use [vault.GCPIAMAuthMethod] instead.
	GCPIAMAuthMethod ClientAuthMethod = vault.GCPIAMAuthMethod

	// JWTAuthMethod is used for the Vault JWT/OIDC/GCP/Kubernetes auth methods
	// as describe here:
	// - https://www.vaultproject.io/docs/auth/jwt
	// - https://www.vaultproject.io/docs/auth/kubernetes
	// - https://www.vaultproject.io/docs/auth/gcp
	//
	// Deprecated: use [vault.JWTAuthMethod] instead.
	JWTAuthMethod ClientAuthMethod = vault.JWTAuthMethod

	// AzureMSIAuthMethod is used for the vault Azure auth method
	// as described here:
	// - https://www.vaultproject.io/docs/auth/azure
	//
	// Deprecated: use [vault.AzureMSIAuthMethod] instead.
	AzureMSIAuthMethod ClientAuthMethod = vault.AzureMSIAuthMethod

	// NamespacedSecretAuthMethod is used for per namespace secrets
	//
	// Deprecated: use [vault.NamespacedSecretAuthMethod] instead.
	NamespacedSecretAuthMethod ClientAuthMethod = vault.NamespacedSecretAuthMethod
)

// Client is a Vault client with Kubernetes support, token automatic renewing and
// access to Transit Secret Engine wrapper.
//
// Deprecated: use [vault.Client] instead.
type Client = vault.Client

// NewClient creates a new Vault client.
//
// Deprecated: use [vault.NewClient] instead.
func NewClient(role string) (*Client, error) {
	return vault.NewClient(role)
}

// NewClientWithOptions creates a new Vault client with custom options.
//
// Deprecated: use [vault.NewClientWithOptions] instead.
func NewClientWithOptions(opts ...ClientOption) (*Client, error) {
	return vault.NewClientWithOptions(opts...)
}

// NewClientWithConfig creates a new Vault client with custom configuration.
//
// Deprecated: use [vault.NewClientWithConfig] instead.
func NewClientWithConfig(config *vaultapi.Config, role, path string) (*Client, error) {
	return vault.NewClientWithConfig(config, role, path)
}

// NewClientFromConfig creates a new Vault client from custom configuration.
//
// Deprecated: use [vault.NewClientFromConfig] instead.
func NewClientFromConfig(config *vaultapi.Config, opts ...ClientOption) (*Client, error) {
	return vault.NewClientFromConfig(config, opts...)
}

// NewClientFromRawClient creates a new Vault client from custom raw client.
//
// Deprecated: use [vault.NewClientFromRawClient] instead.
func NewClientFromRawClient(rawClient *vaultapi.Client, opts ...ClientOption) (*Client, error) {
	return vault.NewClientFromRawClient(rawClient, opts...)
}

// NewRawClient creates a new raw Vault client.
//
// Deprecated: use [vault.NewRawClient] instead.
func NewRawClient() (*vaultapi.Client, error) {
	return vault.NewRawClient()
}

// NewInsecureRawClient creates a new raw Vault client with insecure TLS.
//
// Deprecated: use [vault.NewInsecureRawClient] instead.
func NewInsecureRawClient() (*vaultapi.Client, error) {
	return vault.NewInsecureRawClient()
}
