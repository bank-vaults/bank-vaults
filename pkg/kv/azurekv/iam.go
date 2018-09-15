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
	"log"
	"net/url"
	"os"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

var (
	// for service principal and device
	clientID           string
	oauthConfig        *adal.OAuthConfig
	keyvaultAuthorizer autorest.Authorizer

	// for service principal
	subscriptionID string
	tenantID       string
	clientSecret   string
)

func init() {
	err := parseArgs()
	if err != nil {
		log.Fatalf("failed to parse args: %s\n", err)
	}
}

// https://github.com/Azure/azure-sdk-for-node/issues/1932#issuecomment-253946276
func parseArgs() (err error) {
	tenantID = os.Getenv("AZURE_TENANT_ID")
	clientID = os.Getenv("AZURE_CLIENT_ID")
	clientSecret = os.Getenv("AZURE_CLIENT_SECRET")

	oauthConfig, err = adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, tenantID)
	return
}

// ClientID gets the client ID
func ClientID() string {
	return clientID
}

// TenantID gets the client ID
func TenantID() string {
	return tenantID
}

// ClientSecret gets the client secret
func ClientSecret() string {
	return clientSecret
}

// GetResourceManagementTokenHybrid retrieves auth token for hybrid environment
func GetResourceManagementTokenHybrid(activeDirectoryEndpoint, tokenAudience string) (adal.OAuthTokenProvider, error) {
	var token adal.OAuthTokenProvider
	oauthConfig, err := adal.NewOAuthConfig(activeDirectoryEndpoint, tenantID)
	token, err = adal.NewServicePrincipalToken(
		*oauthConfig,
		clientID,
		clientSecret,
		tokenAudience)

	return token, err
}

func getAuthorizer(endpoint string) (a autorest.Authorizer, err error) {
	token, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, endpoint)
	if err != nil {
		return a, err
	}
	a = autorest.NewBearerAuthorizer(token)
	return
}

// GetKeyvaultAuthorizer gets an authorizer for the keyvault dataplane
func GetKeyvaultAuthorizer() (a autorest.Authorizer, err error) {
	if keyvaultAuthorizer != nil {
		return keyvaultAuthorizer, nil
	}

	vaultEndpoint := "https://vault.azure.net"
	config, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, tenantID)
	updatedAuthorizeEndpoint, err := url.Parse("https://login.windows.net/" + tenantID + "/oauth2/token")
	config.AuthorizeEndpoint = *updatedAuthorizeEndpoint
	if err != nil {
		return
	}

	token, err := adal.NewServicePrincipalToken(*config, clientID, clientSecret, vaultEndpoint)
	if err != nil {
		return a, err
	}
	a = autorest.NewBearerAuthorizer(token)

	if err == nil {
		keyvaultAuthorizer = a
	}

	return
}
