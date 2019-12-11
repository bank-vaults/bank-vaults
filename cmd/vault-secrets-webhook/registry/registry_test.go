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

package registry

import (
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestIsAllowedToCache(t *testing.T) {
	tests := []struct {
		container    *corev1.Container
		allowToCache bool
	}{
		{
			container: &corev1.Container{
				Name:  "app",
				Image: "foo:bar",
			},
			allowToCache: true,
		},
		{
			container: &corev1.Container{
				Name:  "app",
				Image: "foo",
			},
			allowToCache: false,
		},
		{
			container: &corev1.Container{
				Name:  "app",
				Image: "foo:latest",
			},
			allowToCache: false,
		},
		{
			container: &corev1.Container{
				Name:            "app",
				Image:           "foo:bar",
				ImagePullPolicy: corev1.PullAlways,
			},
			allowToCache: false,
		},
	}
	for _, test := range tests {
		allowToCache := IsAllowedToCache(test.container)
		if test.allowToCache != allowToCache {
			t.Errorf("IsAllowedToCache() != %v", test.allowToCache)
		}
	}
}

func TestParsingRegistryAddress(t *testing.T) {
	tests := []struct {
		container       *corev1.Container
		podSpec         *corev1.PodSpec
		registryAddress string
	}{
		{
			container: &corev1.Container{
				Image: "foo:bar",
			},
			podSpec:         &corev1.PodSpec{},
			registryAddress: "https://index.docker.io",
		},
		{
			container: &corev1.Container{
				Image: "foo",
			},
			podSpec:         &corev1.PodSpec{},
			registryAddress: "https://index.docker.io",
		},
		{
			container: &corev1.Container{
				Image: "library/foo:latest",
			},
			podSpec:         &corev1.PodSpec{},
			registryAddress: "https://index.docker.io",
		},
		{
			container: &corev1.Container{
				Image: "index.docker.io/foo:latest",
			},
			podSpec:         &corev1.PodSpec{},
			registryAddress: "https://index.docker.io",
		},
		{
			container: &corev1.Container{
				Image: "foo:bar",
			},
			podSpec:         &corev1.PodSpec{},
			registryAddress: "https://index.docker.io",
		},
		{
			container: &corev1.Container{
				Image: "docker.io/foo:bar",
			},
			podSpec:         &corev1.PodSpec{},
			registryAddress: "https://index.docker.io",
		},
		{
			container: &corev1.Container{
				Image: "docker.pkg.github.com/banzaicloud/bank-vaults/vault-env:0.6.0",
			},
			podSpec:         &corev1.PodSpec{},
			registryAddress: "https://docker.pkg.github.com",
		},
	}

	for _, test := range tests {
		containerInfo := ContainerInfo{}
		mockCache := cache.New(time.Minute, time.Minute)

		err := containerInfo.Collect(test.container, test.podSpec, mockCache)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, test.registryAddress, containerInfo.RegistryAddress)
	}
}
