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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/banzaicloud/bank-vaults/cmd/vault-secrets-webhook/registry"
	"github.com/banzaicloud/bank-vaults/pkg/vault"
	dockerTypes "github.com/docker/docker/api/types"
	"github.com/spf13/cast"
	corev1 "k8s.io/api/core/v1"
)

func secretNeedsMutation(secret *corev1.Secret) bool {
	for key, value := range secret.Data {
		if key == corev1.DockerConfigJsonKey || strings.HasPrefix(string(value), "vault:") {
			return true
		}
	}
	return false
}

func mutateSecret(secret *corev1.Secret, vaultConfig vaultConfig, ns string) error {

	// do an early exit and don't construct the Vault client if not needed
	if !secretNeedsMutation(secret) {
		return nil
	}

	vaultClient, err := newVaultClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %v", err)
	}

	defer vaultClient.Close()

	for key, value := range secret.Data {
		if key == corev1.DockerConfigJsonKey {
			var dc registry.DockerCreds
			err := json.Unmarshal(value, &dc)
			if err != nil {
				return fmt.Errorf("unmarshal dockerconfig json failed: %v", err)
			}
			err = mutateDockerCreds(secret, &dc, vaultClient)
			if err != nil {
				return fmt.Errorf("mutate dockerconfig json failed: %v", err)
			}
		} else if strings.HasPrefix(string(value), "vault:") {
			sc := map[string]string{
				key: string(value),
			}
			err := mutateSecretData(secret, sc, vaultClient)
			if err != nil {
				return fmt.Errorf("mutate generic secret failed: %v", err)
			}
		}
	}

	return nil
}

func mutateDockerCreds(secret *corev1.Secret, dc *registry.DockerCreds, vaultClient *vault.Client) error {

	assembled := registry.DockerCreds{Auths: map[string]dockerTypes.AuthConfig{}}

	for key, creds := range dc.Auths {
		authBytes, err := base64.StdEncoding.DecodeString(creds.Auth)
		if err != nil {
			return fmt.Errorf("auth base64 decoding failed: %v", err)
		}
		auth := string(authBytes)
		if strings.HasPrefix(auth, "vault:") {
			split := strings.Split(auth, ":")
			if len(split) != 4 {
				return errors.New("splitting auth credentials failed")
			}
			username := fmt.Sprintf("%s:%s", split[0], split[1])
			password := fmt.Sprintf("%s:%s", split[2], split[3])

			credPath := map[string]string{
				"username": username,
				"password": password,
			}

			dcCreds, err := getDataFromVault(credPath, vaultClient)
			if err != nil {
				return err
			}
			auth = fmt.Sprintf("%s:%s", dcCreds["username"], dcCreds["password"])
			dockerAuth := dockerTypes.AuthConfig{
				Auth: base64.StdEncoding.EncodeToString([]byte(auth)),
			}
			if creds.Username != "" && creds.Password != "" {
				dockerAuth.Username = dcCreds["username"]
				dockerAuth.Password = dcCreds["password"]
			}
			assembled.Auths[key] = dockerAuth
		}
	}

	marshalled, err := json.Marshal(assembled)
	if err != nil {
		return fmt.Errorf("marshaling dockerconfig failed: %v", err)
	}
	logger.Debugf("assembled %s", marshalled)

	secret.Data[corev1.DockerConfigJsonKey] = marshalled

	return nil
}

func mutateSecretData(secret *corev1.Secret, sc map[string]string, vaultClient *vault.Client) error {
	secCreds, err := getDataFromVault(sc, vaultClient)
	if err != nil {
		return err
	}
	for key, value := range secCreds {
		secret.Data[key] = []byte(value)
	}
	return nil
}

func getDataFromVault(data map[string]string, vaultClient *vault.Client) (map[string]string, error) {
	var vaultData = make(map[string]string)

	removePunctuation := func(r rune) rune {
		if strings.ContainsRune(";<>=\"'", r) {
			return -1
		}
		return r
	}

	for key, value := range data {
		for _, val := range strings.Fields(value) {
			val = strings.Map(removePunctuation, val)
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

				secret, err := vaultClient.RawClient().Logical().ReadWithData(path, map[string][]string{"version": {version}})
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
