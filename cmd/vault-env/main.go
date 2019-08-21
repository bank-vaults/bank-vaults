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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

// The special value for VAULT_ENV which marks that the login token needs to be passed through to the application
// which was acquired during the new Vault client creation
const vaultLogin = "vault:login"

type sanitizedEnviron []string

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
	ignoreMissingSecrets := os.Getenv("VAULT_IGNORE_MISSING_SECRETS") == "true"

	// The login procedure takes the token from a file (if using Vault Agent)
	// or requests one for itself (Kubernetes Auth), so if we got a VAULT_TOKEN
	// for the special value with "vault:login"
	originalVaultTokenEnvVar := os.Getenv("VAULT_TOKEN")
	if originalVaultTokenEnvVar == vaultLogin {
		os.Unsetenv("VAULT_TOKEN")
	}

	client, err := vault.NewClientWithOptions(
		vault.ClientRole(os.Getenv("VAULT_ROLE")),
		vault.ClientAuthPath(os.Getenv("VAULT_PATH")),
	)
	if err != nil {
		log.Fatal("failed to create vault client", err.Error())
	}

	passthroughEnvVars := strings.Split(os.Getenv("VAULT_ENV_PASSTHROUGH"), ",")

	if originalVaultTokenEnvVar == vaultLogin {
		os.Setenv("VAULT_TOKEN", vaultLogin)
		passthroughEnvVars = append(passthroughEnvVars, "VAULT_TOKEN")
	}

	// do not sanitize env vars specified in VAULT_ENV_PASSTHROUGH
	for _, envVar := range passthroughEnvVars {
		if trimmed := strings.TrimSpace(envVar); trimmed != "" {
			delete(sanitizeEnvmap, trimmed)
		}
	}

	secretCache := map[string]*vaultapi.Secret{}

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

			// handle special case for vault:login env value
			// namely pass through the the VAULT_TOKEN received from the Vault login procedure
			if name == "VAULT_TOKEN" && path == "login" {
				value = client.RawClient().Token()
				sanitized.append(name, value)
				continue
			}

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

			if secret = secretCache[path]; secret == nil {
				if update {
					secret, err = client.RawClient().Logical().Write(path, map[string]interface{}{})
					if err != nil {
						log.Fatalln("failed to write secret to path:", path, err.Error())
					} else {
						secretCache[path] = secret
					}
				} else {
					secret, err = client.RawClient().Logical().ReadWithData(path, map[string][]string{"version": {version}})
					if err != nil {
						if ignoreMissingSecrets {
							log.Errorln("failed to read secret from path:", path, err.Error())
						} else {
							log.Fatalln("failed to read secret from path:", path, err.Error())
						}
					} else {
						secretCache[path] = secret
					}
				}
			}

			if secret == nil {
				if ignoreMissingSecrets {
					log.Warnln("path not found:", path)
				} else {
					log.Fatalln("path not found:", path)
				}
			} else {
				var data map[string]interface{}
				v2Data, ok := secret.Data["data"]
				if ok {
					data = cast.ToStringMap(v2Data)

					// Check if a given version of a path is destroyed
					metadata := secret.Data["metadata"].(map[string]interface{})
					if metadata["destroyed"].(bool) {
						log.Warnln("version of secret has been permanently destroyed version:", version, "path:", path)
					}

					// Check if a given version of a path still exists
					if deletionTime, ok := metadata["deletion_time"].(string); ok && deletionTime != "" {
						log.Warnln("cannot find data for path, given version has been deleted",
							"path:", path, "version:", version,
							"deletion_time", deletionTime)
					}
				} else {
					data = cast.ToStringMap(secret.Data)
				}
				if value, ok := data[key]; ok {
					sanitized.append(name, value)
				} else {
					log.Fatalln("key not found:", key)
				}
			}
		} else {
			sanitized.append(name, value)
		}
	}

	var entrypointCmd []string
	if len(os.Args) == 1 {
		log.Fatalln("no command is given, vault-env can't determine the entrypoint (command), please specify it explicitly or let the webhook query it (see documentation)")
	} else {
		entrypointCmd = os.Args[1:]
	}
	binary, err := exec.LookPath(entrypointCmd[0])
	if err != nil {
		log.Fatalln("binary not found", entrypointCmd[0])
	}
	err = syscall.Exec(binary, entrypointCmd, sanitized)
	if err != nil {
		log.Fatalln("failed to exec process", binary, entrypointCmd, err.Error())
	}
}
