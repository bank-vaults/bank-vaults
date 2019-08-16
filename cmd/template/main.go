// Copyright © 2019 Banzai Cloud
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
	"flag"
	"io/ioutil"
	"os"

	"github.com/banzaicloud/bank-vaults/internal/configuration"

	log "github.com/sirupsen/logrus"
)

// template is an internal CLI command and not supported for direct consumption.
func main() {

	filename := flag.String("file", "/vault/config/vault.json", "location of the templated config file")

	flag.Parse()

	vaultConfig := os.Getenv("VAULT_LOCAL_CONFIG")

	buffer, err := configuration.EnvTemplate(vaultConfig)
	if err != nil {
		log.Fatalf("error executing config template: %s", err.Error())
	}

	err = ioutil.WriteFile(*filename, buffer.Bytes(), 0600)
	if err != nil {
		log.Fatalf("error writing config file: %s", err.Error())
	}
}
