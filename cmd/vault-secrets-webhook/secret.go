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
	"encoding/json"
	"fmt"
	"strings"

	"emperror.dev/errors"
	dockerTypes "github.com/docker/docker/api/types"
	corev1 "k8s.io/api/core/v1"

	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

type dockerCreds struct {
	Auths map[string]dockerTypes.AuthConfig `json:"auths"`
}

func secretNeedsMutation(secret *corev1.Secret, vaultConfig VaultConfig) (bool, error) {
	for key, value := range secret.Data {
		if key == corev1.DockerConfigJsonKey {
			var dc dockerCreds
			err := json.Unmarshal(value, &dc)
			if err != nil {
				return false, errors.Wrap(err, "unmarshal dockerconfig json failed")
			}

			for _, creds := range dc.Auths {
				authBytes, err := base64.StdEncoding.DecodeString(creds.Auth)
				if err != nil {
					return false, errors.Wrap(err, "auth base64 decoding failed")
				}

				auth := string(authBytes)
				if hasVaultPrefix(auth) {
					return true, nil
				}
			}
		} else if hasVaultPrefix(string(value)) {
			return true, nil
		} else if vaultConfig.InlineMutation && hasInlineVaultDelimiters(string(value)) {
			return true, nil
		}
	}
	return false, nil
}

func (mw *mutatingWebhook) mutateSecret(secret *corev1.Secret, vaultConfig VaultConfig) error {
	// do an early exit and don't construct the Vault client if not needed
	requiredToMutate, err := secretNeedsMutation(secret, vaultConfig)
	if err != nil {
		return errors.Wrap(err, "failed to check if secret needs to be mutated")
	}

	if !requiredToMutate {
		return nil
	}

	vaultClient, err := mw.newVaultClient(vaultConfig)
	if err != nil {
		return errors.Wrap(err, "failed to create vault client")
	}

	defer vaultClient.Close()

	for key, value := range secret.Data {
		if key == corev1.DockerConfigJsonKey {
			var dc dockerCreds
			err := json.Unmarshal(value, &dc)
			if err != nil {
				return errors.Wrap(err, "unmarshal dockerconfig json failed")
			}
			err = mw.mutateDockerCreds(secret, &dc, vaultClient, vaultConfig)
			if err != nil {
				return errors.Wrap(err, "mutate dockerconfig json failed")
			}
		} else if hasInlineVaultDelimiters(string(value)) {
			data := map[string]string{
				key: string(value),
			}
			err := mw.mutateInlineSecretData(secret, data, vaultClient, vaultConfig)
			if err != nil {
				return err
			}
		} else if hasVaultPrefix(string(value)) {
			sc := map[string]string{
				key: string(value),
			}
			err := mw.mutateSecretData(secret, sc, vaultClient, vaultConfig)
			if err != nil {
				return errors.Wrap(err, "mutate generic secret failed")
			}
		}
	}

	return nil
}

func (mw *mutatingWebhook) mutateDockerCreds(secret *corev1.Secret, dc *dockerCreds, vaultClient *vault.Client, vaultConfig VaultConfig) error {
	assembled := dockerCreds{Auths: map[string]dockerTypes.AuthConfig{}}

	for key, creds := range dc.Auths {
		authBytes, err := base64.StdEncoding.DecodeString(creds.Auth)
		if err != nil {
			return errors.Wrap(err, "auth base64 decoding failed")
		}

		auth := string(authBytes)
		if hasVaultPrefix(auth) {
			split := strings.Split(auth, ":")
			if len(split) != 4 {
				return errors.New("splitting auth credentials failed") // nolint:goerr113
			}
			username := fmt.Sprintf("%s:%s", split[0], split[1])
			password := fmt.Sprintf("%s:%s", split[2], split[3])

			credPath := map[string]string{
				"username": username,
				"password": password,
			}

			dcCreds, err := getDataFromVault(credPath, vaultClient, vaultConfig, mw.logger)
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
		return errors.Wrap(err, "marshaling dockerconfig failed")
	}

	secret.Data[corev1.DockerConfigJsonKey] = marshalled

	return nil
}

func (mw *mutatingWebhook) mutateInlineSecretData(secret *corev1.Secret, sc map[string]string, vaultClient *vault.Client, vaultConfig VaultConfig) error {
	for key, value := range sc {
		for _, vaultSecretReference := range findInlineVaultDelimiters(value) {
			mapData, err := getDataFromVault(map[string]string{key: vaultSecretReference[1]}, vaultClient, vaultConfig, mw.logger)
			if err != nil {
				return err
			}
			for key, value := range mapData {
				secret.Data[key] = []byte(strings.Replace(string(secret.Data[key]), vaultSecretReference[0], value, -1))
			}
		}
	}
	return nil
}

func (mw *mutatingWebhook) mutateSecretData(secret *corev1.Secret, sc map[string]string, vaultClient *vault.Client, vaultConfig VaultConfig) error {
	secCreds, err := getDataFromVault(sc, vaultClient, vaultConfig, mw.logger)
	if err != nil {
		return err
	}
	for key, value := range secCreds {
		secret.Data[key] = []byte(value)
	}
	return nil
}
