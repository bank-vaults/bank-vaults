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
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"emperror.dev/errors"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	logrusadapter "logur.dev/adapter/logrus"

	"github.com/banzaicloud/bank-vaults/internal/injector"
	"github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

// The special value for VAULT_ENV which marks that the login token needs to be passed through to the application
// which was acquired during the new Vault client creation
const vaultLogin = "vault:login"

type sanitizedEnviron struct {
	env   []string
	login bool
}

type envType struct {
	login bool
}

var sanitizeEnvmap = map[string]envType{
	"VAULT_TOKEN":                  {login: true},
	"VAULT_ADDR":                   {login: true},
	"VAULT_AGENT_ADDR":             {login: true},
	"VAULT_CACERT":                 {login: true},
	"VAULT_CAPATH":                 {login: true},
	"VAULT_CLIENT_CERT":            {login: true},
	"VAULT_CLIENT_KEY":             {login: true},
	"VAULT_CLIENT_TIMEOUT":         {login: true},
	"VAULT_SRV_LOOKUP":             {login: true},
	"VAULT_SKIP_VERIFY":            {login: true},
	"VAULT_NAMESPACE":              {login: true},
	"VAULT_TLS_SERVER_NAME":        {login: true},
	"VAULT_WRAP_TTL":               {login: true},
	"VAULT_MFA":                    {login: true},
	"VAULT_MAX_RETRIES":            {login: true},
	"VAULT_CLUSTER_ADDR":           {login: false},
	"VAULT_REDIRECT_ADDR":          {login: false},
	"VAULT_CLI_NO_COLOR":           {login: false},
	"VAULT_RATE_LIMIT":             {login: false},
	"VAULT_ROLE":                   {login: false},
	"VAULT_PATH":                   {login: false},
	"VAULT_AUTH_METHOD":            {login: false},
	"VAULT_TRANSIT_KEY_ID":         {login: false},
	"VAULT_TRANSIT_PATH":           {login: false},
	"VAULT_IGNORE_MISSING_SECRETS": {login: false},
	"VAULT_ENV_PASSTHROUGH":        {login: false},
	"VAULT_JSON_LOG":               {login: false},
	"VAULT_LOG_LEVEL":              {login: false},
	"VAULT_REVOKE_TOKEN":           {login: false},
	"VAULT_ENV_DAEMON":             {login: false},
	"VAULT_ENV_FROM_PATH":          {login: false},
}

// Appends variable an entry (name=value) into the environ list.
// VAULT_* variables are not populated into this list if this is not a login scenario.
func (e *sanitizedEnviron) append(name string, value string) {
	if envType, ok := sanitizeEnvmap[name]; !ok || (e.login && envType.login) {
		e.env = append(e.env, fmt.Sprintf("%s=%s", name, value))
	}
}

type daemonSecretRenewer struct {
	client *vault.Client
	sigs   chan os.Signal
	logger logrus.FieldLogger
}

func (r daemonSecretRenewer) Renew(path string, secret *vaultapi.Secret) error {
	renewerInput := vaultapi.RenewerInput{Secret: secret}
	renewer, err := r.client.RawClient().NewRenewer(&renewerInput)
	if err != nil {
		return errors.Wrap(err, "failed to create secret renewer")
	}

	go renewer.Renew()

	go func() {
		for {
			select {
			case renewOutput := <-renewer.RenewCh():
				r.logger.Infof("secret %s renewed for %ds", path, renewOutput.Secret.LeaseDuration)
			case doneError := <-renewer.DoneCh():
				if !secret.Renewable {
					time.Sleep(time.Duration(secret.LeaseDuration) * time.Second)
					r.logger.Infof("secret lease for %s has expired", path)
				}
				r.logger.WithField("error", doneError).Infof("secret renewal for %s has stopped, sending SIGTERM to process", path)

				r.sigs <- syscall.SIGTERM

				timeout := <-time.After(10 * time.Second)
				r.logger.Infoln("killing process due to SIGTERM timeout =", timeout)
				r.sigs <- syscall.SIGKILL

				return
			}
		}
	}()

	return nil
}

func main() {
	enableJSONLog := cast.ToBool(os.Getenv("VAULT_JSON_LOG"))
	lvl, err := logrus.ParseLevel(os.Getenv("VAULT_LOG_LEVEL"))
	if err != nil {
		lvl = logrus.InfoLevel
	}

	var logger *logrus.Entry
	{
		log := logrus.New()
		log.SetLevel(lvl)
		if enableJSONLog {
			log.SetFormatter(&logrus.JSONFormatter{})
		}
		logger = log.WithField("app", "vault-env")
	}

	daemonMode := cast.ToBool(os.Getenv("VAULT_ENV_DAEMON"))

	sigs := make(chan os.Signal, 1)

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

	// Used both for reading secrets and transit encryption
	ignoreMissingSecrets := cast.ToBool(os.Getenv("VAULT_IGNORE_MISSING_SECRETS"))

	clientOptions := []vault.ClientOption{vault.ClientLogger(logrusadapter.NewFromEntry(logger))}
	// The login procedure takes the token from a file (if using Vault Agent)
	// or requests one for itself (Kubernetes Auth, or GCP, etc...),
	// so if we got a VAULT_TOKEN for the special value with "vault:login"
	originalVaultTokenEnvVar := os.Getenv("VAULT_TOKEN")
	isLogin := originalVaultTokenEnvVar == vaultLogin
	if tokenFile := os.Getenv("VAULT_TOKEN_FILE"); tokenFile != "" {
		// load token from vault-agent .vault-token or injected webhook
		if b, err := ioutil.ReadFile(tokenFile); err == nil {
			originalVaultTokenEnvVar = string(b)
		} else {
			logger.Fatalf("could not read vault token file: %s", tokenFile)
		}
		clientOptions = append(clientOptions, vault.ClientToken(originalVaultTokenEnvVar))
	} else {
		if isLogin {
			os.Unsetenv("VAULT_TOKEN")
		}
		// use role/path based authentication
		clientOptions = append(clientOptions,
			vault.ClientRole(os.Getenv("VAULT_ROLE")),
			vault.ClientAuthPath(os.Getenv("VAULT_PATH")),
			vault.ClientAuthMethod(os.Getenv("VAULT_AUTH_METHOD")),
		)
	}

	client, err := vault.NewClientWithOptions(clientOptions...)
	if err != nil {
		logger.Fatal("failed to create vault client", err.Error())
	}

	passthroughEnvVars := strings.Split(os.Getenv("VAULT_ENV_PASSTHROUGH"), ",")

	if isLogin {
		os.Setenv("VAULT_TOKEN", vaultLogin)
		passthroughEnvVars = append(passthroughEnvVars, "VAULT_TOKEN")
	}

	// do not sanitize env vars specified in VAULT_ENV_PASSTHROUGH
	for _, envVar := range passthroughEnvVars {
		if trimmed := strings.TrimSpace(envVar); trimmed != "" {
			delete(sanitizeEnvmap, trimmed)
		}
	}

	// initial and sanitized environs
	environ := make(map[string]string, len(os.Environ()))
	sanitized := sanitizedEnviron{login: isLogin}

	config := injector.Config{
		TransitKeyID:         os.Getenv("VAULT_TRANSIT_KEY_ID"),
		TransitPath:          os.Getenv("VAULT_TRANSIT_PATH"),
		DaemonMode:           daemonMode,
		IgnoreMissingSecrets: ignoreMissingSecrets,
	}

	var secretRenewer injector.SecretRenewer

	if daemonMode {
		secretRenewer = daemonSecretRenewer{client: client, sigs: sigs, logger: logger}
	}

	secretInjector := injector.NewSecretInjector(config, client, secretRenewer, logger)

	for _, env := range os.Environ() {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]
		environ[name] = value
	}

	inject := func(key, value string) {
		sanitized.append(key, value)
	}

	err = secretInjector.InjectSecretsFromVault(environ, inject)
	if err != nil {
		logger.Fatalln("failed to inject secrets from vault:", err)
	}

	if paths := os.Getenv("VAULT_ENV_FROM_PATH"); paths != "" {
		err = secretInjector.InjectSecretsFromVaultPath(paths, inject)
	}
	if err != nil {
		logger.Fatalln("failed to inject secrets from vault path:", err)
	}

	if cast.ToBool(os.Getenv("VAULT_REVOKE_TOKEN")) {
		// ref: https://www.vaultproject.io/api/auth/token/index.html#revoke-a-token-self-
		err = client.RawClient().Auth().Token().RevokeSelf(client.RawClient().Token())
		if err != nil {
			// Do not exit on error, token revoking can be denied by policy
			logger.Warn("failed to revoke token")
		}

		client.Close()
	}

	logger.Infoln("spawning process:", entrypointCmd)

	if daemonMode {
		logger.Infoln("in daemon mode...")
		cmd := exec.Command(binary, entrypointCmd[1:]...)
		cmd.Env = append(os.Environ(), sanitized.env...)
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout

		signal.Notify(sigs)

		err = cmd.Start()
		if err != nil {
			logger.Fatalln("failed to start process", entrypointCmd, err.Error())
		}

		go func() {
			for sig := range sigs {
				// We don't want to signal a non-running process.
				if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
					break
				}

				err := cmd.Process.Signal(sig)
				if err != nil {
					logger.Warnf("failed to signal process with %s: %v", sig, err)
				} else {
					logger.Infof("received signal: %s", sig)
				}
			}
		}()

		err = cmd.Wait()

		close(sigs)

		var eerr exec.ExitError
		if errors.As(err, &eerr) {
			os.Exit(cmd.ProcessState.ExitCode())
		} else if err != nil {
			logger.Fatalln("failed to exec process", entrypointCmd, err.Error())
			os.Exit(-1)
		} else {
			os.Exit(cmd.ProcessState.ExitCode())
		}
	} else {
		err = syscall.Exec(binary, entrypointCmd, sanitized.env)
		if err != nil {
			logger.Fatalln("failed to exec process", entrypointCmd, err.Error())
		}
	}
}
