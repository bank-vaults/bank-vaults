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

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
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
