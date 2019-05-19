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

package main

import (
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
)

// GetEntrypointCmd returns entrypoint and command of container
func GetEntrypointCmd(vaultClient *vault.Client) ([]string, []string) {
	podInfo := K8s{}
	podInfo.Load()

	if podInfo.RegistryName != "" {
		logger.Info("Trimmed registry name from image name",
			zap.String("registry", podInfo.RegistryName),
			zap.String("image", podInfo.Image),
		)
		podInfo.Image = strings.TrimLeft(podInfo.Image, fmt.Sprintf("%s/", podInfo.RegistryName))
	}

	registryAddress := podInfo.RegistryAddress
	if registryAddress == "" {
		registryAddress = "https://registry-1.docker.io/"
	}
	logger.Warn("I'm using registry", zap.String("registry", registryAddress))

	return GetImageBlob(registryAddress, podInfo.RegistryUsername, podInfo.RegistryPassword, podInfo.Image, podInfo.RegistryName)
}
