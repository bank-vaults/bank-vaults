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

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cast"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
)

type sanitizedEnviron []string

var sanitizeEnvmap = map[string]bool{
	"VAULT_TOKEN":           true,
	"VAULT_ADDR":            true,
	"VAULT_CACERT":          true,
	"VAULT_CAPATH":          true,
	"VAULT_CLIENT_CERT":     true,
	"VAULT_CLIENT_KEY":      true,
	"VAULT_CLIENT_TIMEOUT":  true,
	"VAULT_CLUSTER_ADDR":    true,
	"VAULT_MAX_RETRIES":     true,
	"VAULT_REDIRECT_ADDR":   true,
	"VAULT_SKIP_VERIFY":     true,
	"VAULT_TLS_SERVER_NAME": true,
	"VAULT_CLI_NO_COLOR":    true,
	"VAULT_RATE_LIMIT":      true,
	"VAULT_NAMESPACE":       true,
	"VAULT_MFA":             true,
	"VAULT_ROLE":            true,
	"VAULT_PATH":            true,
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
	client, err := vault.NewClientWithOptions(
		vault.ClientRole(os.Getenv("VAULT_ROLE")),
		vault.ClientAuthPath(os.Getenv("VAULT_PATH")),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create vault client: %s\n", err.Error())
		os.Exit(1)
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
					fmt.Fprintf(os.Stderr, "failed to write secret '%s': %s\n", path, err.Error())
					os.Exit(1)
				}
			} else {
				secret, err = client.Vault().Logical().ReadWithData(path, map[string][]string{"version": {version}})
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to read secret '%s': %s\n", path, err.Error())
					os.Exit(1)
				}
			}

			if secret == nil {
				fmt.Fprintf(os.Stderr, "path not found: %s\n", path)
				os.Exit(1)
			} else {
				var data map[string]interface{}
				v2Data, ok := secret.Data["data"]

				if ok {
					data = cast.ToStringMap(v2Data)

					// Check if a given version of a path is destroyed
					metadata := secret.Data["metadata"].(map[string]interface{})
					if metadata["destroyed"].(bool) {
						fmt.Fprintf(os.Stderr, "Version %s of %s secret has been permanently destroyed\n", version, path)
					}

					// Check if a given version of a path still exists
					if metadata["deletion_time"].(string) != "" {
						fmt.Fprintf(os.Stderr, "Cannot find data for path: %s, given version (%s) has been deleted at %s\n", path, version, metadata["deletion_time"])
					}
				} else {
					data = cast.ToStringMap(secret.Data)
				}
				if value, ok := data[key]; ok {
					sanitized.append(name, value)
				} else {
					fmt.Fprintf(os.Stderr, "key not found: %s\n", key)
					os.Exit(1)
				}
			}
		} else {
			sanitized.append(name, value)
		}
	}

	if len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "no command is given, currently vault-env can't determine the entrypoint (command), please specify it explicitly")
		os.Exit(1)
	} else {
		binary, err := exec.LookPath(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "binary not found: %s\n", os.Args[1])
			os.Exit(1)
		}
		err = syscall.Exec(binary, os.Args[1:], sanitized)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to exec process '%s': %s\n", binary, err.Error())
			os.Exit(1)
		}
	}
}
