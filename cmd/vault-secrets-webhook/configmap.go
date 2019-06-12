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
	"strconv"
	"strings"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cast"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mutateConfigMap(obj metav1.Object, configMap *corev1.ConfigMap, vaultConfig vaultConfig, ns string) error {

	clientConfig := vaultapi.DefaultConfig()
	clientConfig.Address = vaultConfig.addr

	vaultInsecure, err := strconv.ParseBool(vaultConfig.skipVerify)
	if err != nil {
		return fmt.Errorf("could not parse VAULT_SKIP_VERIFY")
	}

	tlsConfig := vaultapi.TLSConfig{Insecure: vaultInsecure}

	clientConfig.ConfigureTLS(&tlsConfig)

	vaultClient, err := vault.NewClientFromConfig(
		clientConfig,
		vault.ClientRole(vaultConfig.role),
		vault.ClientAuthPath(vaultConfig.path),
	)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %v", err)
	}

	for key, value := range configMap.Data {
		data := map[string]string{
			key: string(value),
		}
		err := mutateData(configMap, data, vaultClient)
		if err != nil {
			return err
		}
	}

	return nil
}

func mutateData(configMap *corev1.ConfigMap, data map[string]string, vaultClient *vault.Client) error {

	mapData, err := getDataFromVault(data, vaultClient)

	if err != nil {
		return err
	}
	for key, value := range mapData {
		configMap.Data[key] = string([]byte(value))
	}
	return nil
}

func getDataFromVault(data map[string]string, vaultClient *vault.Client) (map[string]string, error) {
	var vaultData = make(map[string]string)

	for key, value := range data {
		for _, val := range strings.Fields(value) {
			if strings.HasPrefix(val, "vault:") {
				path := strings.TrimPrefix(val, "vault:")
				split := strings.SplitN(path, "#", 3)
				path = split[0]
				var vaultKey string
				if len(split) > 1 {
					vaultKey = split[1]
				}
				version := "-1"
				if len(split) == 3 {
					version = split[2]
				}

				var vaultSecret map[string]interface{}

				secret, err := vaultClient.Vault().Logical().ReadWithData(path, map[string][]string{"version": {version}})
				if err != nil {
					logger.Errorf("Failed to read secret path: %s error: %s", path, err.Error())
				}
				if secret == nil {
					logger.Errorf("Path not found path: %s", path)
				} else {
					v2Data, ok := secret.Data["data"]
					if ok {
						vaultSecret = cast.ToStringMap(v2Data)
					} else {
						vaultSecret = cast.ToStringMap(secret.Data)
					}
				}
				value = strings.ReplaceAll(value, val, cast.ToString(vaultSecret[vaultKey]))
			}
		}
		vaultData[key] = value
	}
	return vaultData, nil
}
