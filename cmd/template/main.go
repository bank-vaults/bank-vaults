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
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
)

// template is an internal CLI command and not supported for direct consumption.
func main() {

	filename := flag.String("file", "/vault/config/vault.json", "location of the templated config file")

	flag.Parse()

	vaultConfig := os.Getenv("VAULT_LOCAL_CONFIG")

	configTemplate, err := template.New("config").
		Funcs(sprig.TxtFuncMap()).
		Delims("${", "}").
		Parse(vaultConfig)

	if err != nil {
		log.Fatalf("error parsing config template: %s", err.Error())
	}

	var env struct {
		Env map[string]string
	}
	env.Env = make(map[string]string, len(os.Environ()))

	for _, v := range os.Environ() {
		split := strings.Split(v, "=")
		env.Env[split[0]] = split[1]
	}

	buffer := bytes.NewBuffer(nil)
	err = configTemplate.ExecuteTemplate(buffer, "config", &env)
	if err != nil {
		log.Fatalf("error executing config template: %s", err.Error())
	}

	err = ioutil.WriteFile(*filename, buffer.Bytes(), 0600)
	if err != nil {
		log.Fatalf("error writing config file: %s", err.Error())
	}
}
