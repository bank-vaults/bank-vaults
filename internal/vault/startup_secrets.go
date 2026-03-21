// Copyright © 2022 Banzai Cloud
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

package vault

import (
	"context"
	"os"
	"strings"

	"fmt"
	"log/slog"

	"emperror.dev/errors"
	"github.com/spf13/cast"
	corev1 "k8s.io/api/core/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	crconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

type startupSecret struct {
	Type        string `mapstructure:"type"`
	Path        string `mapstructure:"path"`
	MaxVersions *int   `mapstructure:"max_versions"`
	Data        struct {
		Data         map[string]interface{}   `mapstructure:"data"`
		Options      map[string]interface{}   `mapstructure:"options,omitempty"`
		SecretKeyRef []map[string]interface{} `mapstructure:"secretKeyRef"`
	} `mapstructure:"data"`
}

func getOrDefaultSecretData(ctx context.Context, m interface{}) (map[string]interface{}, error) {
	values, err := cast.ToSliceE(m)
	if err != nil {
		return map[string]interface{}{}, err
	}

	c, err := crclient.New(crconfig.GetConfigOrDie(), crclient.Options{})
	if err != nil {
		return map[string]interface{}{}, err
	}

	secData := map[string]string{}
	for _, value := range values {
		keyRef, err := cast.ToStringMapStringE(value)
		if err != nil {
			return map[string]interface{}{}, err
		}

		secret := &corev1.Secret{}
		err = c.Get(ctx, crclient.ObjectKey{
			Namespace: os.Getenv("NAMESPACE"),
			Name:      keyRef["name"],
		}, secret)
		if err != nil {
			return map[string]interface{}{}, err
		}
		secData[keyRef["key"]] = cast.ToString(secret.Data[keyRef["key"]])
	}
	data := map[string]interface{}{}
	data["data"] = secData

	return data, nil
}

func vaultKVVersion(secretPath string, secretEngines []secretEngine) string {
	for _, v := range secretEngines {
		if strings.HasPrefix(secretPath, v.Path) && v.Type == "kv" {
			return v.Options["version"]
		}
	}
	return ""
}

// vaultKVMaxVersions returns the max_versions configured on the secret engine for the given path.
func vaultKVMaxVersions(secretPath string, secretEngines []secretEngine) *int {
	for _, v := range secretEngines {
		if strings.HasPrefix(secretPath, v.Path) && v.Type == "kv" {
			return v.MaxVersions
		}
	}
	return nil
}

func readStartupSecret(ctx context.Context, startupSecret startupSecret, secretEngines []secretEngine) (string, map[string]interface{}, error) {
	if len(startupSecret.Data.Data) > 0 && len(startupSecret.Data.SecretKeyRef) > 0 {
		return "", nil, errors.New("the startup secret data source should be either 'data' or 'secretKeyRef'." +
			"They are mutually exclusive and cannot be used together")
	}

	data := map[string]interface{}{
		"data": startupSecret.Data.Data,
	}
	if vaultKVVersion(startupSecret.Path, secretEngines) == "1" {
		data = startupSecret.Data.Data
	}

	if len(startupSecret.Data.SecretKeyRef) > 0 {
		secretData, err := getOrDefaultSecretData(ctx, startupSecret.Data.SecretKeyRef)
		if err != nil {
			return "", nil, errors.Wrap(err, "error getting secret data from k8s secret")
		}
		data = secretData
	}

	return startupSecret.Path, data, nil
}

func generateCertPayload(data interface{}) (map[string]interface{}, error) {
	pkiData, err := cast.ToStringMapStringE(data)
	if err != nil {
		return map[string]interface{}{}, errors.Wrapf(err, "cast to map[string]... failed: %v", data)
	}

	pkiSlice := []string{}
	for _, v := range pkiData {
		pkiSlice = append(pkiSlice, v)
	}

	if len(pkiSlice) < 2 {
		return map[string]interface{}{}, errors.Errorf("missing key or certificate in pki data: %v", pkiData)
	}

	return map[string]interface{}{"pem_bundle": strings.Join(pkiSlice, "\n")}, nil
}

func (v *vault) configureStartupSecrets(ctx context.Context) error {
	managedStartupSecrets := v.externalConfig.StartupSecrets
	for _, startupSecret := range managedStartupSecrets {
		var err error
		switch startupSecret.Type {
		case "kv":
			err = v.handleKVSecret(ctx, startupSecret)

		case "pki":
			err = v.handlePKISecret(ctx, startupSecret)

		default:
			return errors.Errorf("'%s' startup secret type is not supported, only 'kv' or 'pki'", startupSecret.Type)
		}
		if err != nil {
			return errors.Wrap(err, "error handling startup secret")
		}
	}

	return nil
}

func (v *vault) handleKVSecret(ctx context.Context, startupSecret startupSecret) error {
	path, data, err := readStartupSecret(ctx, startupSecret, v.externalConfig.Secrets)
	if err != nil {
		return errors.Wrap(err, "unable to read 'kv' startup secret")
	}

	if len(startupSecret.Data.Options) > 0 {
		data["options"] = startupSecret.Data.Options
	}

	_, err = v.writeWithWarningCheck(path, data)
	if err != nil {
		return errors.Wrapf(err, "error writing data for startup 'kv' secret '%s'", path)
	}

	// Resolve max_versions: startup secret overrides secret engine default
	maxVersions := vaultKVMaxVersions(startupSecret.Path, v.externalConfig.Secrets)
	if startupSecret.MaxVersions != nil {
		maxVersions = startupSecret.MaxVersions
	}

	// Set max_versions per secret via the metadata endpoint if resolved
	if maxVersions != nil {
		metadataPath := strings.Replace(path, "/data/", "/metadata/", 1)
		metadataData := map[string]interface{}{
			"max_versions": *maxVersions,
		}
		slog.Info(fmt.Sprintf("setting max_versions=%d for secret %s", *maxVersions, path))
		if _, err := v.writeWithWarningCheck(metadataPath, metadataData); err != nil {
			return errors.Wrapf(err, "error setting max_versions for secret '%s'", path)
		}
	}

	return nil
}

func (v *vault) handlePKISecret(ctx context.Context, startupSecret startupSecret) error {
	path, data, err := readStartupSecret(ctx, startupSecret, v.externalConfig.Secrets)
	if err != nil {
		return errors.Wrap(err, "unable to read 'pki' startup secret")
	}

	certData, err := generateCertPayload(data["data"])
	if err != nil {
		return errors.Wrap(err, "error generating 'pki' startup secret")
	}

	_, err = v.writeWithWarningCheck(path, certData)
	if err != nil {
		return errors.Wrapf(err, "error writing data for startup 'pki' secret '%s'", path)
	}

	return nil
}
