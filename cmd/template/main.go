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

// renderInlineConfig templates the inline VAULT_LOCAL_CONFIG payload and writes the result
// to filename with the given file mode.
func renderInlineConfig(t *templater.Templater, vaultConfig, filename string, mode os.FileMode) error {
	buffer, err := t.EnvTemplate(vaultConfig)
	if err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	if err := os.WriteFile(filename, buffer.Bytes(), mode); err != nil {
		return fmt.Errorf("writing template file: %w", err)
	}

	return nil
}

// renderTemplates reads each source:destination pair, runs it through the templater, and
// writes the rendered output to destination with the given file mode.
func renderTemplates(t *templater.Templater, templates []string, mode os.FileMode) error {
	for _, pair := range templates {
		parts := strings.Split(pair, ":")
		if len(parts) != delimiterCount {
			return fmt.Errorf("template must be two filenames delimited by a :, got %q", pair)
		}

		source, destination := parts[0], parts[1]
		templateText, err := os.ReadFile(source)
		if err != nil {
			return fmt.Errorf("reading template file %q: %w", source, err)
		}

		templatedText, err := t.EnvTemplate(string(templateText))
		if err != nil {
			return fmt.Errorf("executing template %q: %w", source, err)
		}

		if err := os.WriteFile(destination, templatedText.Bytes(), mode); err != nil {
			return fmt.Errorf("writing template file %q: %w", destination, err)
		}
	}

	return nil
}

// template is an internal CLI command and not supported for direct consumption.
func main() {
	var filename string
	var delimiters string
	var templates arrayFlags
	var fileMode uint

	flag.StringVar(&delimiters, "delims", "${:}", "delimiters delimited by :")
	flag.StringVar(&filename, "file", "/vault/config/vault.json", "the destination file templated from VAULT_LOCAL_CONFIG")
	flag.Var(&templates, "template", "template filename pairs delimited by :")
	// Default is 0o640 so files written here can be read by other containers in the
	// same pod via a shared fsGroup. Override to 0o600 if running single-container,
	// or to 0o644 if the consumer runs without a shared group.
	flag.UintVar(&fileMode, "mode", 0o640, "file mode (octal) for output files")
	flag.Parse()

	delimitersArray := strings.Split(delimiters, ":")
	if len(delimitersArray) != delimiterCount {
		slog.Error("delims must be two mnemonics delimited by a :")
		os.Exit(1)
	}

	outMode := os.FileMode(fileMode)

	leftDelimiter := delimitersArray[0]
	rightDelimiter := delimitersArray[1]
	tmpl := templater.NewTemplater(leftDelimiter, rightDelimiter)

	vaultConfig := os.Getenv("VAULT_LOCAL_CONFIG")
	if vaultConfig != "" {
		if err := renderInlineConfig(&tmpl, vaultConfig, filename, outMode); err != nil {
			slog.Error(err.Error())
			os.Exit(1)
		}

		return
	}

	if err := renderTemplates(&tmpl, templates, outMode); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}
