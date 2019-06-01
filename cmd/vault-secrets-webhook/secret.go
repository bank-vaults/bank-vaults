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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/slok/kubewebhook/pkg/log"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type dockerCreds struct {
	Auths map[string]dockerCred `json:"auths"`
}

type dockerCred struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Auth     []byte `json:"auth"`
}

func mutateSecret(obj metav1.Object, secret *corev1.Secret, vaultConfig vaultConfig, ns string) error {
	logger := &log.Std{Debug: viper.GetBool("debug")}
	logger.Debugf("SecretData: %s", secret.Data)

	os.Setenv("VAULT_ADDR", vaultConfig.addr)
	os.Setenv("VAULT_SKIP_VERIFY", vaultConfig.skipVerify)

	for key, value := range secret.Data {
		if key == ".dockerconfigjson" {
			var dc dockerCreds
			_ = json.Unmarshal(value, &dc)
			_ = mutateDockerCreds(secret, &dc, vaultConfig)
		} else {
			sc := map[string]string{
				key: string(value),
			}
			_ = mutateSecretCreds(secret, sc, vaultConfig)
		}
	}

	os.Unsetenv("VAULT_ADDR")
	os.Unsetenv("VAULT_SKIP_VERIFY")

	return nil
}

func mutateDockerCreds(secret *corev1.Secret, dc *dockerCreds, vaultConfig vaultConfig) error {
	logger := &log.Std{Debug: viper.GetBool("debug")}

	var assembled dockerCreds
	assembled.Auths = make(map[string]dockerCred)
	for key, creds := range dc.Auths {
		if strings.HasPrefix(string(creds.Auth), "vault:") {
			logger.Debugf("auth %s %s", key, creds.Auth)
			split := strings.Split(string(creds.Auth), ":")
			username := fmt.Sprintf("%s:%s", split[0], split[1])
			password := fmt.Sprintf("%s:%s", split[2], split[3])

			credPath := map[string]string{
				"username": username,
				"password": password,
			}

			dcCreds := getCredsFromVault(credPath, vaultConfig)
			dockerAuths := dockerCred{
				Auth: []byte(fmt.Sprintf("%s:%s", dcCreds["username"], dcCreds["password"])),
			}
			if creds.Username != "" && creds.Password != "" {
				dockerAuths.Username = dcCreds["username"]
				dockerAuths.Password = dcCreds["password"]
			}
			assembled.Auths[key] = dockerAuths
		}
	}
	marhalled, _ := json.Marshal(assembled)
	logger.Debugf("assembled %s", marhalled)

	secret.Data[".dockerconfigjson"] = marhalled

	return nil
}

func mutateSecretCreds(secret *corev1.Secret, sc map[string]string, vaultConfig vaultConfig) error {
	logger := &log.Std{Debug: viper.GetBool("debug")}
	logger.Debugf("simple secret %s", sc)

	secCreds := getCredsFromVault(sc, vaultConfig)
	for key, value := range secCreds {
		secret.Data[key] = []byte(value)
	}
	return nil
}

func getCredsFromVault(creds map[string]string, vaultConfig vaultConfig) map[string]string {
	logger := &log.Std{Debug: viper.GetBool("debug")}

	logger.Debugf("Vaultconfig %s", vaultConfig)

	client, err := vault.NewClientWithOptions(
		vault.ClientRole(vaultConfig.role),
		vault.ClientAuthPath(vaultConfig.path),
	)

	if err != nil {
		logger.Errorf("Failed to create vault client")
	}

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

			var secret *vaultapi.Secret
			var err error
			var data map[string]interface{}

			secret, err = client.Vault().Logical().ReadWithData(path, map[string][]string{"version": {version}})
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
	return secCreds
}
