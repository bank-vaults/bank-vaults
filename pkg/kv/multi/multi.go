// Copyright © 2020 Banzai Cloud
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

package multi

import (
	"emperror.dev/errors"
	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"github.com/sirupsen/logrus"
)

type multi struct {
	services []kv.Service
}

// New creates a new kv.Service backed by multiple kv.Services in a multi-write and single-read fashion.
func New(services []kv.Service) kv.Service {
	return &multi{services: services}
}

func (f *multi) Set(key string, val []byte) error {
	for _, service := range f.services {
		err := service.Set(key, val)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *multi) Get(key string) ([]byte, error) {
	multiErr := errors.NewPlain("Can't find key in any of the backends")
	for _, service := range f.services {
		val, err := service.Get(key)
		if err != nil {
			// Not found error means that they given object is not present, that is a hard error.
			if notFoundError, ok := err.(*kv.NotFoundError); ok && notFoundError.NotFound() {
				return nil, err
			}
			logrus.Infof("error finding key %q in key/value Service, trying next one: %s", key, err)
			errors.Append(multiErr, err)
		} else {
			return val, nil
		}
	}
	return nil, multiErr
}
