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

// +build integration

package hsm

import (
	"runtime"
	"testing"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"github.com/stretchr/testify/assert"
)

type inMemoryStorage struct {
	data map[string][]byte
}

func (s *inMemoryStorage) Get(key string) ([]byte, error) {
	if data, ok := s.data[key]; !ok {
		return nil, kv.NewNotFoundError("key not found")
	} else {
		return data, nil
	}
}

func (s *inMemoryStorage) Set(key string, data []byte) error {
	s.data[key] = data
	return nil
}

func TestIntegrationHSM(t *testing.T) {
	storage := inMemoryStorage{map[string][]byte{}}

	modulePath := "/usr/lib/softhsm/libsofthsm2.so"
	if runtime.GOOS == "darwin" {
		modulePath = "/usr/local/lib/softhsm/libsofthsm2.so"
	}

	hsmService, err := New(Config{
		ModulePath: modulePath,
		Pin:        "banzai",
		TokenLabel: "bank-vaults",
		KeyLabel:   "bank-vaults",
	}, &storage)

	if err != nil {
		t.Fatal("new failed", err)
	}

	err = hsmService.Set("my-secret-data", []byte("hello world"))
	if err != nil {
		t.Fatal("set failed", err)
	}

	data, err := hsmService.Get("my-secret-data")
	if err != nil {
		t.Fatal("get failed", err)
	}

	assert.Equal(t, []byte("hello world"), data)
}
