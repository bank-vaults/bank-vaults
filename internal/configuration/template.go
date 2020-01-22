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

const DefaultLeftDelimiter = "${"
const DefaultRightDelimiter = "}"

const templateName = "config"

type Templater struct {
	leftDelimiter  string
	rightDelimiter string
}

func NewTemplater(leftDelimiter, rightDelimiter string) Templater {
	return Templater{
		leftDelimiter:  leftDelimiter,
		rightDelimiter: rightDelimiter,
	}
}

// EnvTemplate interpolates environment variables in a configuration text
func (t Templater) EnvTemplate(templateText string) (*bytes.Buffer, error) {

	var env struct {
		Env map[string]string
	}
	env.Env = make(map[string]string, len(os.Environ()))

	for _, v := range os.Environ() {
		split := strings.Split(v, "=")
		env.Env[split[0]] = split[1]
	}

	return t.Template(templateText, env)
}

// Template interpolates a data structure in a template
func (t Templater) Template(templateText string, data interface{}) (*bytes.Buffer, error) {

	configTemplate, err := template.New(templateName).
		Funcs(sprig.TxtFuncMap()).
		Delims(t.leftDelimiter, t.rightDelimiter).
		Parse(templateText)

	if err != nil {
		return nil, emperror.Wrapf(err, "error parsing template")
	}

	buffer := bytes.NewBuffer(nil)

	err = configTemplate.ExecuteTemplate(buffer, templateName, data)
	if err != nil {
		return nil, emperror.Wrapf(err, "error executing template")
	}

	return buffer, nil
}

// IsGoTemplate returns true if s is probably a Go Template
func (t Templater) IsGoTemplate(templateText string) bool {
	return strings.Contains(templateText, t.leftDelimiter) && strings.Contains(templateText, t.rightDelimiter)
}
