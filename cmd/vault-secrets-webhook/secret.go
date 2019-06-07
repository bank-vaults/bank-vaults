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
	"strconv"
	"strings"

	"github.com/banzaicloud/bank-vaults/cmd/vault-secrets-webhook/registry"
	"github.com/banzaicloud/bank-vaults/pkg/vault"
	dockerTypes "github.com/docker/docker/api/types"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cast"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mutateSecret(obj metav1.Object, secret *corev1.Secret, vaultConfig vaultConfig, ns string) error {

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
		} else {
			sc := map[string]string{
				key: string(value),
			}
			err := mutateSecretCreds(secret, sc, vaultClient)
			if err != nil {
				return err
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

			dcCreds, err := getCredsFromVault(credPath, vaultClient)
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

func mutateSecretCreds(secret *corev1.Secret, sc map[string]string, vaultClient *vault.Client) error {
	secCreds, err := getCredsFromVault(sc, vaultClient)
	if err != nil {
		return err
	}
	for key, value := range secCreds {
		secret.Data[key] = []byte(value)
	}
	return nil
}

func getCredsFromVault(creds map[string]string, vaultClient *vault.Client) (map[string]string, error) {
	var secCreds = make(map[string]string)

	for key, value := range creds {
		if strings.HasPrefix(value, "vault:") {
			path := strings.TrimPrefix(value, "vault:")
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

			var data map[string]interface{}

			secret, err := vaultClient.Vault().Logical().ReadWithData(path, map[string][]string{"version": {version}})
			if err != nil {
				logger.Errorf("Failed to read secret path: %s error: %s", path, err.Error())
			}
			if secret == nil {
				logger.Errorf("Path not found path: %s", path)
			} else {
				v2Data, ok := secret.Data["data"]
				if ok {
					data = cast.ToStringMap(v2Data)
				} else {
					data = cast.ToStringMap(secret.Data)
				}
			}
			secCreds[key] = cast.ToString(data[vaultKey])
		}
	}
	return secCreds, nil
}
