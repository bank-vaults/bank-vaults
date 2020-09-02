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

package main

import (
	"log"
	"os"

	database "github.com/banzaicloud/bank-vaults/pkg/sdk/db"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	logrusadapter "logur.dev/adapter/logrus"
)

func vaultExample() {
	vaultPath := "kubernetes"
	if path := os.Getenv("VAULT_PATH"); path != "" {
		vaultPath = path
	}

	config := api.DefaultConfig()
	if config.Error != nil {
		log.Fatal(config.Error)
	}

	client, err := vault.NewClientFromConfig(
		config,
		vault.ClientAuthPath(vaultPath),
		vault.ClientLogger(logrusadapter.New(logrus.New())),
	)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Created Vault client")

	secret, err := client.RawClient().Logical().List("secret/metadata/accounts")
	if err != nil {
		log.Fatal(err)
	}
	if secret != nil {
		for _, v := range secret.Data {
			log.Printf("-> %+v", v)
			for _, v := range v.([]interface{}) {
				log.Printf("  -> %+v", v)
			}
		}

		log.Println("Finished reading Vault")

	} else {
		log.Fatal("Found no data in vault")
	}
}

func gormExample() {
	secretSource, err := database.DynamicSecretDataSource("mysql", "my-role@tcp(127.0.0.1:3306)/sparky?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("use this with GORM:\ndb, err := gorm.Open(\"mysql\", \"%s\")", secretSource)
}

// REQUIRED to start a Vault dev server with:
// vault server -dev &
func main() {
	os.Setenv("VAULT_ADDR", "https://vault.default:8200")
	os.Setenv("VAULT_SKIP_VERIFY", "true")
	vaultExample()
}
