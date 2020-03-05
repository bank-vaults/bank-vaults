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
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	internal "github.com/banzaicloud/bank-vaults/internal/configuration"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

func configMapNeedsMutation(configMap *corev1.ConfigMap) bool {
	for _, value := range configMap.Data {
		if hasVaultPrefix(value) {
			return true
		}
	}
	for _, value := range configMap.BinaryData {
		if hasVaultPrefix(string(value)) {
			return true
		}
	}
	return false
}

func mutateConfigMap(configMap *corev1.ConfigMap, vaultConfig internal.VaultConfig) error {
	// do an early exit and don't construct the Vault client if not needed
	if !configMapNeedsMutation(configMap) {
		return nil
	}

	vaultClient, err := newVaultClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %v", err)
	}

	defer vaultClient.Close()

	for key, value := range configMap.Data {
		if hasVaultPrefix(value) {
			data := map[string]string{
				key: value,
			}
			err := mutateConfigMapData(configMap, data, vaultClient)
			if err != nil {
				return err
			}
		}
	}

	for key, value := range configMap.BinaryData {
		if hasVaultPrefix(string(value)) {
			binaryData := map[string]string{
				key: string(value),
			}
			err := mutateConfigMapBinaryData(configMap, binaryData, vaultClient)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func mutateConfigMapData(configMap *corev1.ConfigMap, data map[string]string, vaultClient *vault.Client) error {
	mapData, err := getDataFromVault(data, vaultClient)
	if err != nil {
		return err
	}
	for key, value := range mapData {
		configMap.Data[key] = value
	}
	return nil
}

func mutateConfigMapBinaryData(configMap *corev1.ConfigMap, data map[string]string, vaultClient *vault.Client) error {
	mapData, err := getDataFromVault(data, vaultClient)
	if err != nil {
		return err
	}
	for key, value := range mapData {
		// binary data are stored in base64 inside vault
		// we need to decode base64 since k8s will encode this data too
		valueBytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return err
		}
		configMap.BinaryData[key] = valueBytes
	}
	return nil
}
