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
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"syscall"

	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
	vaultapi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

// The special value for VAULT_ENV which marks that the login token needs to be passed through to the application
// which was acquired during the new Vault client creation
const vaultLogin = "vault:login"

type sanitizedEnviron []string

var (
	sanitizeEnvmap = map[string]bool{
		"VAULT_TOKEN":                        true,
		"VAULT_ADDR":                         true,
		"VAULT_CACERT":                       true,
		"VAULT_CAPATH":                       true,
		"VAULT_CLIENT_CERT":                  true,
		"VAULT_CLIENT_KEY":                   true,
		"VAULT_CLIENT_TIMEOUT":               true,
		"VAULT_CLUSTER_ADDR":                 true,
		"VAULT_MAX_RETRIES":                  true,
		"VAULT_REDIRECT_ADDR":                true,
		"VAULT_SKIP_VERIFY":                  true,
		"VAULT_TLS_SERVER_NAME":              true,
		"VAULT_CLI_NO_COLOR":                 true,
		"VAULT_RATE_LIMIT":                   true,
		"VAULT_NAMESPACE":                    true,
		"VAULT_MFA":                          true,
		"VAULT_ROLE":                         true,
		"VAULT_PATH":                         true,
		"VAULT_TRANSIT_KEY_ID":               true,
		"VAULT_IGNORE_TRANSIT_DECRYPT_ERROR": true,
		"VAULT_IGNORE_MISSING_SECRETS":       true,
		"VAULT_ENV_PASSTHROUGH":              true,
		"VAULT_JSON_LOG":                     true,
		"VAULT_REVOKE_TOKEN":                 true,
	}

	// Example: vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==
	// ref: https://www.vaultproject.io/docs/secrets/transit/index.html#usage
	transitEncodedVariable = regexp.MustCompile(`vault:v\d+:.*`)

	logger *log.Logger
)

// GlobalHook struct used for adding additional fields to the log
type GlobalHook struct {
}

// Levels returning all log levels
func (h *GlobalHook) Levels() []log.Level {
	return log.AllLevels
}

// Fire adding the additional fields to all log entries
func (h *GlobalHook) Fire(e *log.Entry) error {
	e.Data["app"] = "vault-env"
	return nil
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
	enableJSONLog := os.Getenv("VAULT_JSON_LOG")

	logger = log.New()
	// Add additonal fields to all log messages
	logger.AddHook(&GlobalHook{})
	if enableJSONLog == "true" {
		logger.SetFormatter(&log.JSONFormatter{})
	}

	var entrypointCmd []string
	if len(os.Args) == 1 {
		logger.Fatalln("no command is given, vault-env can't determine the entrypoint (command), please specify it explicitly or let the webhook query it (see documentation)")
	} else {
		entrypointCmd = os.Args[1:]
	}

	binary, err := exec.LookPath(entrypointCmd[0])
	if err != nil {
		logger.Fatalln("binary not found", entrypointCmd[0])
	}

	ignoreMissingSecrets := os.Getenv("VAULT_IGNORE_MISSING_SECRETS") == "true"
	ignoreTransitDecryptError := os.Getenv("VAULT_IGNORE_TRANSIT_DECRYPT_ERROR") == "true"

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
		logger.Fatal("failed to create vault client", err.Error())
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

	encodedCache := map[string][]byte{}
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

		if !strings.HasPrefix(value, "vault:") {
			sanitized.append(name, value)
			continue
		}
		secretPath := strings.TrimPrefix(value, "vault:")

		// handle special case for vault:login env value
		// namely pass through the the VAULT_TOKEN received from the Vault login procedure
		if name == "VAULT_TOKEN" && secretPath == "login" {
			value = client.RawClient().Token()
			sanitized.append(name, value)
			continue
		}

		// decrypt value with Vault Transit Secret Engine
		// ref: https://www.vaultproject.io/docs/secrets/transit/index.html
		if transitEncodedVariable.MatchString(value) {
			transitKeyID := os.Getenv("VAULT_TRANSIT_KEY_ID")
			if len(transitKeyID) == 0 {
				logger.Fatal("Found encrypted data, but transit key ID is empty")
			}
			if v, ok := encodedCache[value]; ok {
				sanitized.append(name, v)
				continue
			}
			out, err := client.RawClient().Logical().Write(
				path.Join("transit/decrypt", transitKeyID),
				map[string]interface{}{
					"ciphertext": value,
				},
			)
			if err != nil {
				if !ignoreTransitDecryptError {
					logger.Fatalln("failed to decrypt:", value, err)
				}
				logger.Errorln("failed to decrypt:", value, err)
				continue
			}
			// decrypted data returns in base64-format
			decodedData, err := base64.StdEncoding.DecodeString(out.Data["plaintext"].(string))
			if err != nil {
				logger.Fatalln("failed to decode:", value, err)
			}
			encodedCache[value] = decodedData
			sanitized.append(name, string(decodedData))
			continue
		}

		split = strings.SplitN(secretPath, "#", 3)
		secretPath = split[0]

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

		if secret = secretCache[secretPath]; secret == nil {
			if update {
				secret, err = client.RawClient().Logical().Write(secretPath, map[string]interface{}{})
				if err != nil {
					logger.Fatalln("failed to write secret to path:", secretPath, err.Error())
				}
				secretCache[secretPath] = secret
			} else {
				secret, err = client.RawClient().Logical().ReadWithData(secretPath, map[string][]string{"version": {version}})
				if err != nil {
					if !ignoreMissingSecrets {
						logger.Fatalln("failed to read secret from path:", secretPath, err.Error())
					}
					logger.Errorln("failed to read secret from path:", secretPath, err.Error())
				} else {
					secretCache[secretPath] = secret
				}
			}
		}

		if secret == nil {
			if !ignoreMissingSecrets {
				logger.Fatalln("path not found:", secretPath)
			}
			logger.Fatalln("path not found:", secretPath)
			continue
		}

		var data map[string]interface{}
		v2Data, ok := secret.Data["data"]
		if ok {
			data = cast.ToStringMap(v2Data)

			// Check if a given version of a path is destroyed
			metadata := secret.Data["metadata"].(map[string]interface{})
			if metadata["destroyed"].(bool) {
				logger.Warnln("version of secret has been permanently destroyed version:", version, "path:", secretPath)
			}

			// Check if a given version of a path still exists
			if deletionTime, ok := metadata["deletion_time"].(string); ok && deletionTime != "" {
				logger.Warnln("cannot find data for path, given version has been deleted",
					"path:", secretPath, "version:", version,
					"deletion_time", deletionTime)
			}
		} else {
			data = cast.ToStringMap(secret.Data)
		}

		if value, ok := data[key]; ok {
			sanitized.append(name, value)
		} else {
			logger.Fatalln("key not found:", key)
		}
	}

	if os.Getenv("VAULT_REVOKE_TOKEN") == "true" {
		// ref: https://www.vaultproject.io/api/auth/token/index.html#revoke-a-token-self-
		err = client.RawClient().Auth().Token().RevokeSelf(client.RawClient().Token())
		if err != nil {
			// Do not exit on error, token revoking can be denied by policy
			logger.Warnln("failed to revoke token")
		}
	}

	err = syscall.Exec(binary, entrypointCmd, sanitized)
	if err != nil {
		logger.Fatalln("failed to exec process", binary, entrypointCmd, err.Error())
	}
}
