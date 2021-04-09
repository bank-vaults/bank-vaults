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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/banzaicloud/bank-vaults/internal/configuration"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)

	return nil
}

// template is an internal CLI command and not supported for direct consumption.
func main() {
	var filename string
	var delimiters string
	var templates arrayFlags

	flag.StringVar(&delimiters, "delims", "${:}", "delimiters delimited by :")
	flag.StringVar(&filename, "file", "/vault/config/vault.json", "the destination file templated from VAULT_LOCAL_CONFIG")
	flag.Var(&templates, "template", "template filename pairs delimited by :")

	flag.Parse()

	delimitersArray := strings.Split(delimiters, ":")
	if len(delimitersArray) != 2 {
		log.Fatal("delims must be two mnemonics delimited by a :")
	}

	leftDelimiter := delimitersArray[0]
	rightDelimiter := delimitersArray[1]

	templater := configuration.NewTemplater(leftDelimiter, rightDelimiter)

	vaultConfig := os.Getenv("VAULT_LOCAL_CONFIG")

	if vaultConfig != "" {
		buffer, err := templater.EnvTemplate(vaultConfig)
		if err != nil {
			log.Fatalf("error executing template: %s", err.Error())
		}

		err = ioutil.WriteFile(filename, buffer.Bytes(), 0600)
		if err != nil {
			log.Fatalf("error writing template file: %s", err.Error())
		}
	} else {
		for _, t := range templates {
			templateArray := strings.Split(t, ":")
			if len(templateArray) != 2 {
				log.Fatal("template must be two filenames delimited by a :")
			}

			source := templateArray[0]
			destination := templateArray[1]

			templateText, err := ioutil.ReadFile(source)
			if err != nil {
				log.Fatalf("error reading template file: %s", err.Error())
			}

			templatedText, err := templater.EnvTemplate(string(templateText))
			if err != nil {
				log.Fatalf("error executing template: %s", err.Error())
			}

			err = ioutil.WriteFile(destination, templatedText.Bytes(), 0600)
			if err != nil {
				log.Fatalf("error writing template file %q: %s", destination, err.Error())
			}
		}
	}
}
