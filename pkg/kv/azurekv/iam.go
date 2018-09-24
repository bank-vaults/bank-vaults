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
	"encoding/json"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

type credentials struct {
	ClientID       string `json:"clientId,omitempty"`
	ClientSecret   string `json:"clientSecret,omitempty"`
	SubscriptionID string `json:"subscriptionId,omitempty"`
	TenantID       string `json:"tenantId,omitempty"`
}

var (
	// for service principal and device
	keyvaultAuthorizer autorest.Authorizer
	creds              credentials
)

func init() {
	if _, ok := os.LookupEnv("AZURE_AUTH_LOCATION"); ok {

		fileLocation := os.Getenv("AZURE_AUTH_LOCATION")
		if fileLocation == "" {
			log.Fatal("auth file not found. Environment variable AZURE_AUTH_LOCATION is not set")
		}

		contents, err := ioutil.ReadFile(fileLocation)
		if err != nil {
			log.Fatal(err.Error())
		}

		err = json.Unmarshal(contents, &creds)
		if err != nil {
			log.Fatal(err.Error())
		}
	} else {
		// https://github.com/Azure/azure-sdk-for-node/issues/1932#issuecomment-253946276
		creds.TenantID = os.Getenv("AZURE_TENANT_ID")
		creds.ClientID = os.Getenv("AZURE_CLIENT_ID")
		creds.ClientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	}
}

// GetKeyvaultAuthorizer gets an authorizer for the keyvault dataplane
func GetKeyvaultAuthorizer() (a autorest.Authorizer, err error) {
	if keyvaultAuthorizer != nil {
		return keyvaultAuthorizer, nil
	}

	config, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, creds.TenantID)
	updatedAuthorizeEndpoint, err := url.Parse("https://login.windows.net/" + creds.TenantID + "/oauth2/token")
	config.AuthorizeEndpoint = *updatedAuthorizeEndpoint
	if err != nil {
		return
	}

	token, err := adal.NewServicePrincipalToken(*config, creds.ClientID, creds.ClientSecret, strings.TrimSuffix(azure.PublicCloud.KeyVaultEndpoint, "/"))
	if err != nil {
		return a, err
	}
	a = autorest.NewBearerAuthorizer(token)

	if err == nil {
		keyvaultAuthorizer = a
	}

	return
}
