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

package main

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	internal "github.com/banzaicloud/bank-vaults/internal/configuration"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

type element interface {
	Set(v interface{})
	Get() interface{}
}

type iterator <-chan element

type mapElement struct {
	m map[string]interface{}
	k string
}

func (e *mapElement) Set(v interface{}) {
	e.m[e.k] = v
}

func (e *mapElement) Get() interface{} {
	return e.m[e.k]
}

type sliceElement struct {
	s []interface{}
	i int
}

func (e *sliceElement) Set(v interface{}) {
	e.s[e.i] = v
}

func (e *sliceElement) Get() interface{} {
	return e.s[e.i]
}

func mapIterator(m map[string]interface{}) iterator {
	c := make(chan element, len(m))
	for k := range m {
		c <- &mapElement{k: k, m: m}
	}
	close(c)
	return c
}

func sliceIterator(s []interface{}) iterator {
	c := make(chan element, len(s))
	for i := range s {
		c <- &sliceElement{i: i, s: s}
	}
	close(c)
	return c
}

func traverseObject(o interface{}, vaultClient *vault.Client) error {
	var iterator iterator

	switch value := o.(type) {
	case map[string]interface{}:
		iterator = mapIterator(value)
	case []interface{}:
		iterator = sliceIterator(value)
	default:
		return nil
	}

	for e := range iterator {
		switch s := e.Get().(type) {
		case string:
			if hasVaultPrefix(s) {
				dataFromVault, err := getDataFromVault(map[string]string{"data": s}, vaultClient)
				if err != nil {
					return err
				}

				e.Set(dataFromVault["data"])
			}
		case map[string]interface{}, []interface{}:
			err := traverseObject(e.Get(), vaultClient)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func mutateObject(object *unstructured.Unstructured, vaultConfig internal.VaultConfig) error {
	logger.Infof("mutating object: %s.%s", object.GetNamespace(), object.GetName())
	logger.Infof("object: %+v", object.Object)

	vaultClient, err := newVaultClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %v", err)
	}

	defer vaultClient.Close()

	return traverseObject(object.Object, vaultClient)
}
