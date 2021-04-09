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
	"os"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

// for service principal and device
var keyvaultAuthorizer autorest.Authorizer

func init() {
	var err error
	resource := strings.TrimSuffix(azure.PublicCloud.KeyVaultEndpoint, "/")
	if _, ok := os.LookupEnv("AZURE_AUTH_LOCATION"); ok {
		keyvaultAuthorizer, err = auth.NewAuthorizerFromFileWithResource(resource)
	} else {
		keyvaultAuthorizer, err = auth.NewAuthorizerFromEnvironmentWithResource(resource)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// GetKeyvaultAuthorizer gets an authorizer for the keyvault dataplane
func GetKeyvaultAuthorizer() autorest.Authorizer {
	return keyvaultAuthorizer
}
