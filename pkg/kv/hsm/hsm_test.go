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

package hsm

import "fmt"

type TestService struct {
	db map[string][]byte
}

func (h *TestService) Set(key string, value []byte) error {
	h.db[key] = value
	return nil
}

func (h *TestService) Get(key string) ([]byte, error) {
	return h.db[key], nil
}

func main() {

	store := &TestService{db: map[string][]byte{}}

	service, err := NewHSM(HSMConfig{}, store)
	if err != nil {
		panic(err)
	}

	err = service.Set("path1", []byte("test data"))
	if err != nil {
		panic(err)
	}

	fmt.Printf("store: %+v\n", store.db)

	data, err := service.Get("path1")
	if err != nil {
		panic(err)
	}

	println("data:", string(data))
}
