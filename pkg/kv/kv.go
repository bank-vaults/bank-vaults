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

import (
	"fmt"

	"emperror.dev/errors"
)

// notFoundError represents an error when a key is not found
type notFoundError struct {
	msg string // description of error
}

func (notFoundError) NotFound() bool {
	return true
}

func (e notFoundError) Error() string { return e.msg }

// NewNotFoundError creates a new NotFoundError
func NewNotFoundError(msg string, args ...interface{}) error {
	return notFoundError{
		msg: fmt.Sprintf(msg, args...),
	}
}

func IsNotFoundError(err error) bool {
	var notFoundErr notFoundError
	if errors.As(err, &notFoundErr) && notFoundErr.NotFound() {
		return true
	}

	return false
}

// Service defines a basic key-value store. Implementations of this interface
// may or may not guarantee consistency or security properties.
type Service interface {
	Set(key string, value []byte) error
	Get(key string) ([]byte, error)
}
