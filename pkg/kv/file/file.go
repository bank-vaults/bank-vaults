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

package file

import (
	"io/ioutil"
	"os"
	"path"

	"emperror.dev/errors"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

type file struct {
	path string
}

// New creates a new kv.Service backed by files, without any encryption
func New(path string) (service kv.Service, err error) {
	service = &file{path: path}

	return
}

func (f *file) Set(key string, val []byte) error {
	return ioutil.WriteFile(path.Join(f.path, key), val, 0600)
}

func (f *file) Get(key string) ([]byte, error) {
	val, err := ioutil.ReadFile(path.Join(f.path, key))
	if os.IsNotExist(err) {
		return nil, kv.NewNotFoundError("key '%s' is not present in file", key)
	}

	return val, errors.WrapIff(err, "failed to read file for key: %s", key)
}
