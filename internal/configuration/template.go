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

package configuration

import (
	"bytes"
	"os"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/goph/emperror"
)

const templateName = "config"

// EnvTemplate interpolates environment variables in a configuration text
func EnvTemplate(config string) (*bytes.Buffer, error) {

	configTemplate, err := template.New(templateName).
		Funcs(sprig.TxtFuncMap()).
		Delims("${", "}").
		Parse(config)

	if err != nil {
		return nil, emperror.Wrapf(err, "error parsing config template")
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

	err = configTemplate.ExecuteTemplate(buffer, templateName, &env)
	if err != nil {
		return nil, emperror.Wrapf(err, "error executing config template")
	}

	return buffer, nil
}
