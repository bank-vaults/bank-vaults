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

package dev

import (
	"io/ioutil"
	"os"

	"emperror.dev/errors"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

type dev struct {
	rootToken []byte
}

// New creates a new kv.Service backed by memory, only the root token is stored, should be used with: vault server -dev
func New() (service kv.Service, err error) {
	rootToken := []byte(os.Getenv("VAULT_TOKEN"))

	if len(rootToken) == 0 {
		rootToken, err = ioutil.ReadFile(os.Getenv("HOME") + "/.vault-token")
		if err != nil {
			return nil, errors.Wrap(err, "error creating dev client")
		}
	}

	service = &dev{rootToken}

	return
}

func (d *dev) Set(key string, val []byte) error {
	return nil
}

func (d *dev) Get(key string) ([]byte, error) {
	if key == "vault-root" {
		return d.rootToken, nil
	}

	return nil, kv.NewNotFoundError("key '%s' is not present in dev mode, only visible in server logs", key)
}
