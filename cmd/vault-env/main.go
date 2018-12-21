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
	"github.com/spf13/cast"
)

func main() {

	role := os.Getenv("VAULT_ROLE")
	if role == "" {
		role = "default"
	}
	path := os.Getenv("VAULT_PATH")
	if path == "" {
		path = "kubernetes"
	}

	client, err := vault.NewClientWithConfig(vaultapi.DefaultConfig(), role, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create vault client: %s\n", err.Error())
		os.Exit(1)
	}

	environ := syscall.Environ()

	for i, env := range environ {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]
		if strings.HasPrefix(value, "vault:") {

			path := strings.TrimPrefix(value, "vault:")
			split := strings.SplitN(path, "#", 2)
			path = split[0]

			var key string
			if len(split) > 0 {
				key = split[1]
			}

			secret, err := client.Vault().Logical().Read(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read secret '%s': %s\n", path, err.Error())
				os.Exit(1)
			}

			if secret == nil {
				fmt.Fprintf(os.Stderr, "path not found: %s\n", path)
				os.Exit(1)
			} else {
				data := cast.ToStringMap(secret.Data)
				if value, ok := data[key]; ok {
					environ[i] = fmt.Sprintf("%s=%s", name, value)
				} else {
					fmt.Fprintf(os.Stderr, "key not found: %s\n", key)
					os.Exit(1)
				}
			}
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
		err = syscall.Exec(binary, os.Args[1:], environ)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to exec process '%s': %s\n", binary, err.Error())
			os.Exit(1)
		}
	}
}
