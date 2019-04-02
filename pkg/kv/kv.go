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

package kv

import "fmt"

// NotFoundError represents an error when a key is not found
type NotFoundError struct {
	msg string // description of error
}

func (e *NotFoundError) Error() string { return e.msg }

// NewNotFoundError creates a new NotFoundError
func NewNotFoundError(msg string, args ...interface{}) *NotFoundError {
	return &NotFoundError{
		msg: fmt.Sprintf(msg, args...),
	}
}

// Service defines a basic key-value store. Implementations of this interface
// may or may not guarantee consistency or security properties.
type Service interface {
	Set(key string, value []byte) error
	Get(key string) ([]byte, error)
}

type Tester struct {
	Service Service
}

func (t Tester) Test(key string) error {
	_, err := t.Service.Get(key)

	if err != nil {
		if _, ok := err.(*NotFoundError); !ok {
			return err
		}
	}

	return t.Service.Set(key, []byte{})
}
