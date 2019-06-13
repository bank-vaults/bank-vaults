// Copyright © 2018 Banzai Cloud
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
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cast"
	"go.uber.org/zap"
)

type sanitizedEnviron []string

var logger *zap.Logger

var sanitizeEnvmap = map[string]bool{
	"VAULT_TOKEN":                  true,
	"VAULT_ADDR":                   true,
	"VAULT_CACERT":                 true,
	"VAULT_CAPATH":                 true,
	"VAULT_CLIENT_CERT":            true,
	"VAULT_CLIENT_KEY":             true,
	"VAULT_CLIENT_TIMEOUT":         true,
	"VAULT_CLUSTER_ADDR":           true,
	"VAULT_MAX_RETRIES":            true,
	"VAULT_REDIRECT_ADDR":          true,
	"VAULT_SKIP_VERIFY":            true,
	"VAULT_TLS_SERVER_NAME":        true,
	"VAULT_CLI_NO_COLOR":           true,
	"VAULT_RATE_LIMIT":             true,
	"VAULT_NAMESPACE":              true,
	"VAULT_MFA":                    true,
	"VAULT_ROLE":                   true,
	"VAULT_PATH":                   true,
	"VAULT_IGNORE_MISSING_SECRETS": true,
	"VAULT_ENV_PASSTHROUGH":        true,
}

// Appends variable an entry (name=value) into the environ list.
// VAULT_* variables are not populated into this list.
func (environ *sanitizedEnviron) append(iname interface{}, ivalue interface{}) {
	name, value := iname.(string), ivalue.(string)
	if _, ok := sanitizeEnvmap[name]; !ok {
		*environ = append(*environ, fmt.Sprintf("%s=%s", name, value))
	}
}

func main() {
	flag.Parse()

	logger, _ = zap.NewProduction()
	defer logger.Sync()

	client, err := vault.NewClientWithOptions(
		vault.ClientRole(os.Getenv("VAULT_ROLE")),
		vault.ClientAuthPath(os.Getenv("VAULT_PATH")),
	)
	if err != nil {
		logger.Fatal("Failed to create vault client", zap.Error(err))
	}

	ignoreMissingSecrets := os.Getenv("VAULT_IGNORE_MISSING_SECRETS") == "true"

	// do not sanitize env vars specified in VAULT_ENV_PASSTHROUGH
	for _, envVar := range strings.Split(os.Getenv("VAULT_ENV_PASSTHROUGH"), ",") {
		if trimmed := strings.TrimSpace(envVar); trimmed != "" {
			delete(sanitizeEnvmap, trimmed)
		}
	}

	// initial and sanitized environs
	environ := syscall.Environ()
	sanitized := make(sanitizedEnviron, 0, len(environ))

	for _, env := range environ {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]
		var update bool
		if strings.HasPrefix(value, ">>") {
			value = strings.TrimPrefix(value, ">>")
			update = true
		} else {
			update = false
		}
		if strings.HasPrefix(value, "vault:") {
			path := strings.TrimPrefix(value, "vault:")
			split := strings.SplitN(path, "#", 3)
			path = split[0]

			var key string
			if len(split) > 1 {
				key = split[1]
			}

			version := "-1"
			if len(split) == 3 {
				version = split[2]
			}

			var secret *vaultapi.Secret
			var err error

			if update {
				var empty map[string]interface{}
				secret, err = client.Vault().Logical().Write(path, empty)
				if err != nil {
					logger.Fatal("Failed to write secret", zap.String("path", path), zap.Error(err))
				}
			} else {
				secret, err = client.Vault().Logical().ReadWithData(path, map[string][]string{"version": {version}})
				if err != nil {
					if ignoreMissingSecrets {
						logger.Warn("Failed to read secret", zap.String("path", path), zap.Error(err))
					} else {
						logger.Fatal("Failed to read secret", zap.String("path", path), zap.Error(err))
					}
				}
			}

			if secret == nil {
				if ignoreMissingSecrets {
					logger.Warn("Path not found", zap.String("path", path))
				} else {
					logger.Fatal("Path not found", zap.String("path", path))
				}
			} else {
				var data map[string]interface{}
				v2Data, ok := secret.Data["data"]
				if ok {
					data = cast.ToStringMap(v2Data)

					// Check if a given version of a path is destroyed
					metadata := secret.Data["metadata"].(map[string]interface{})
					if metadata["destroyed"].(bool) {
						logger.Warn("Version of secret has been permanently destroyed", zap.String("version", version), zap.String("path", path))
					}

					// Check if a given version of a path still exists
					if metadata["deletion_time"].(string) != "" {
						logger.Warn("Cannot find data for path, given version has been deleted",
							zap.String("path", path), zap.String("version", version),
							zap.String("deletion_time", metadata["deletion_time"].(string)),
						)
					}
				} else {
					data = cast.ToStringMap(secret.Data)
				}
				if value, ok := data[key]; ok {
					sanitized.append(name, value)
				} else {
					logger.Fatal("Key not found", zap.String("key", key))
				}
			}
		} else {
			sanitized.append(name, value)
		}
	}

	var entrypointCmd []string
	if len(os.Args) == 1 {
		logger.Fatal("no command is given, vault-env can't determine the entrypoint (command), please specify it explicitly or let the webhook query it (see documentation)")
		os.Exit(1)
	} else {
		entrypointCmd = os.Args[1:]
	}
	binary, err := exec.LookPath(entrypointCmd[0])
	if err != nil {
		logger.Fatal("Binary not found", zap.String("binary", entrypointCmd[0]))
	}
	err = syscall.Exec(binary, entrypointCmd, sanitized)
	if err != nil {
		logger.Fatal("Failed to exec process", zap.String("binary", binary), zap.Error(err))
	}
}
