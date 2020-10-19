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
	"encoding/base64"
	"strings"

	"emperror.dev/errors"
	corev1 "k8s.io/api/core/v1"

	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

func configMapNeedsMutation(configMap *corev1.ConfigMap, vaultConfig VaultConfig) bool {
	for _, value := range configMap.Data {
		if hasVaultPrefix(value) {
			return true
		}
		if vaultConfig.InlineMutation && hasInlineVaultDelimiters(value) {
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

func (mw *mutatingWebhook) mutateConfigMap(configMap *corev1.ConfigMap, vaultConfig VaultConfig) error {
	// do an early exit and don't construct the Vault client if not needed
	if !configMapNeedsMutation(configMap, vaultConfig) {
		return nil
	}

	vaultClient, err := mw.newVaultClient(vaultConfig)
	if err != nil {
		return errors.Wrap(err, "failed to create vault client")
	}

	defer vaultClient.Close()

	for key, value := range configMap.Data {
		if hasInlineVaultDelimiters(value) {
			data := map[string]string{
				key: value,
			}
			err := mw.mutateInlineConfigMapData(configMap, data, vaultClient, vaultConfig)
			if err != nil {
				return err
			}
		} else if hasVaultPrefix(value) {
			data := map[string]string{
				key: value,
			}
			err := mw.mutateConfigMapData(configMap, data, vaultClient, vaultConfig)
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
			err := mw.mutateConfigMapBinaryData(configMap, binaryData, vaultClient, vaultConfig)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (mw *mutatingWebhook) mutateConfigMapData(configMap *corev1.ConfigMap, data map[string]string, vaultClient *vault.Client, vaultConfig VaultConfig) error {
	mapData, err := getDataFromVault(data, vaultClient, vaultConfig, mw.logger)
	if err != nil {
		return err
	}
	for key, value := range mapData {
		configMap.Data[key] = value
	}
	return nil
}

func (mw *mutatingWebhook) mutateInlineConfigMapData(configMap *corev1.ConfigMap, data map[string]string, vaultClient *vault.Client, vaultConfig VaultConfig) error {
	for key, value := range data {
		for _, vaultSecretReference := range findInlineVaultDelimiters(value) {
			mapData, err := getDataFromVault(map[string]string{key: vaultSecretReference[1]}, vaultClient, vaultConfig, mw.logger)
			if err != nil {
				return err
			}
			for key, value := range mapData {
				configMap.Data[key] = strings.Replace(configMap.Data[key], vaultSecretReference[0], value, -1)
			}
		}
	}
	return nil
}

func (mw *mutatingWebhook) mutateConfigMapBinaryData(configMap *corev1.ConfigMap, data map[string]string, vaultClient *vault.Client, vaultConfig VaultConfig) error {
	mapData, err := getDataFromVault(data, vaultClient, vaultConfig, mw.logger)
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
