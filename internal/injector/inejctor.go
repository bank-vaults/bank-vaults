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

package injector

import (
	"strings"

	"emperror.dev/errors"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"

	"github.com/banzaicloud/bank-vaults/internal/configuration"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

type SecretInjectorFunc func(key, value string)

type SecretRenewer interface {
	Renew(path string, secret *vaultapi.Secret) error
}

type Config struct {
	TransitKeyID         string
	TransitPath          string
	IgnoreMissingSecrets bool
	DaemonMode           bool
}

type SecretInjector struct {
	config  Config
	client  *vault.Client
	renewer SecretRenewer
	logger  *logrus.Entry
}

func NewSecretInjector(config Config, client *vault.Client, renewer SecretRenewer, logger *logrus.Entry) SecretInjector {
	return SecretInjector{config: config, client: client, renewer: renewer, logger: logger}
}

func (i SecretInjector) InjectSecretsFromVault(references map[string]string, inject SecretInjectorFunc) error {
	transitCache := map[string][]byte{}
	secretCache := map[string]*vaultapi.Secret{}

	templater := configuration.NewTemplater(configuration.DefaultLeftDelimiter, configuration.DefaultRightDelimiter)

	for name, value := range references {
		var update bool
		if strings.HasPrefix(value, ">>vault:") {
			value = strings.TrimPrefix(value, ">>")
			update = true
		} else {
			update = false
		}

		if !strings.HasPrefix(value, "vault:") {
			inject(name, value)
			continue
		}

		valuePath := strings.TrimPrefix(value, "vault:")

		// handle special case for vault:login env value
		// namely pass through the the VAULT_TOKEN received from the Vault login procedure
		if name == "VAULT_TOKEN" && valuePath == "login" {
			value = i.client.RawClient().Token()
			inject(name, value)
			continue
		}

		// decrypts value with Vault Transit Secret Engine
		if i.client.Transit.IsEncrypted(value) {
			if len(i.config.TransitKeyID) == 0 {
				return errors.NewWithDetails("found encrypted variable, but transit key ID is empty:", name)
			}

			if v, ok := transitCache[value]; ok {
				inject(name, string(v))
				continue
			}

			out, err := i.client.Transit.Decrypt(i.config.TransitPath, i.config.TransitKeyID, []byte(value))
			if err != nil {
				if !i.config.IgnoreMissingSecrets {
					return errors.WrapWithDetails(err, "failed to decrypt variable:", name)
				}
				i.logger.Errorln("failed to decrypt variable:", name, err)
				continue
			}

			transitCache[value] = out
			inject(name, string(out))
			continue
		}

		split := strings.SplitN(valuePath, "#", 3)
		valuePath = split[0]

		var key string
		if len(split) > 1 {
			key = split[1]
		}

		version := "-1"
		if len(split) == 3 {
			version = split[2]
		}

		secretCacheKey := valuePath + "#" + version

		var secret *vaultapi.Secret
		var err error

		if secret = secretCache[secretCacheKey]; secret == nil {
			if update {
				secret, err = i.client.RawClient().Logical().Write(valuePath, map[string]interface{}{})
				if err != nil {
					return errors.WrapWithDetails(err, "failed to write secret to path:", valuePath)
				}
				secretCache[secretCacheKey] = secret
			} else {
				secret, err = i.client.RawClient().Logical().ReadWithData(valuePath, map[string][]string{"version": {version}})
				if err != nil {
					if !i.config.IgnoreMissingSecrets {
						return errors.WrapWithDetails(err, "failed to read secret from path:", valuePath)
					}
					i.logger.Errorln("failed to read secret from path:", valuePath, err.Error())
				} else {
					secretCache[secretCacheKey] = secret
				}
			}

			if i.config.DaemonMode && secret != nil && secret.Renewable && secret.LeaseDuration > 0 {
				i.logger.Infof("secret %s has a lease duration of %ds, starting renewal", valuePath, secret.LeaseDuration)

				err = i.renewer.Renew(valuePath, secret)
				if err != nil {
					return errors.Wrap(err, "secret renewal can't be established")
				}
			}
		}

		if secret == nil {
			if !i.config.IgnoreMissingSecrets {
				return errors.NewWithDetails("path not found:", valuePath)
			}

			i.logger.Errorln("path not found:", valuePath)
			continue
		}

		var data map[string]interface{}
		v2Data, ok := secret.Data["data"]
		if ok {
			data = cast.ToStringMap(v2Data)

			// Check if a given version of a path is destroyed
			metadata := secret.Data["metadata"].(map[string]interface{})
			if metadata["destroyed"].(bool) {
				i.logger.Warnln("version of secret has been permanently destroyed version:", version, "path:", valuePath)
			}

			// Check if a given version of a path still exists
			if deletionTime, ok := metadata["deletion_time"].(string); ok && deletionTime != "" {
				i.logger.Warnln("cannot find data for path, given version has been deleted",
					"path:", valuePath, "version:", version,
					"deletion_time", deletionTime)
			}
		} else {
			data = cast.ToStringMap(secret.Data)
		}

		if templater.IsGoTemplate(key) {
			value, err := templater.Template(key, data)
			if err != nil {
				return errors.WrapWithDetails(err, "failed to interpolate template key with vault data:", key)
			}
			inject(name, value.String())
		} else {
			if value, ok := data[key]; ok {
				value, err := cast.ToStringE(value)
				if err != nil {
					return errors.Wrap(err, "value can't be cast to a string")
				}
				inject(name, value)
			} else {
				return errors.NewWithDetails("key not found:", key)
			}
		}
	}

	return nil
}
