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
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/bank-vaults/vault-sdk/utils/templater"
)

var Version = "dev"

const delimiterCount = 2

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
	if len(delimitersArray) != delimiterCount {
		slog.Error("delims must be two mnemonics delimited by a :")
		os.Exit(1)
	}

	leftDelimiter := delimitersArray[0]
	rightDelimiter := delimitersArray[1]
	templater := templater.NewTemplater(leftDelimiter, rightDelimiter)

	vaultConfig := os.Getenv("VAULT_LOCAL_CONFIG")
	if vaultConfig != "" {
		buffer, err := templater.EnvTemplate(vaultConfig)
		if err != nil {
			slog.Error(fmt.Sprintf("error executing template: %s", err.Error()))
			os.Exit(1)
		}

		err = os.WriteFile(filename, buffer.Bytes(), 0o600)
		if err != nil {
			slog.Error(fmt.Sprintf("error writing template file: %s", err.Error()))
			os.Exit(1)
		}
	} else {
		for _, t := range templates {
			templateArray := strings.Split(t, ":")
			if len(templateArray) != delimiterCount {
				slog.Error("template must be two filenames delimited by a :")
				os.Exit(1)
			}

			source := templateArray[0]
			destination := templateArray[1]
			templateText, err := os.ReadFile(source)
			if err != nil {
				slog.Error(fmt.Sprintf("error reading template file: %s", err.Error()))
				os.Exit(1)
			}

			templatedText, err := templater.EnvTemplate(string(templateText))
			if err != nil {
				slog.Error(fmt.Sprintf("error executing template: %s", err.Error()))
				os.Exit(1)
			}

			err = os.WriteFile(destination, templatedText.Bytes(), 0o600)
			if err != nil {
				slog.Error(fmt.Sprintf("error writing template file %q: %s", destination, err.Error()))
				os.Exit(1)
			}
		}
	}
}
