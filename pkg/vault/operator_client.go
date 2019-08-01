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

package vault

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
	hclPrinter "github.com/hashicorp/hcl/hcl/printer"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
	json "github.com/json-iterator/go"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

// DefaultConfigFile is the name of the default config file
const DefaultConfigFile = "vault-config.yml"

// secretEngineConfigNoNeedName holds the secret engine types where
// the name shouldn't be part of the config path
var secretEngineConfigNoNeedName = map[string]bool{
	"ad":       true,
	"alicloud": true,
	"azure":    true,
	"gcp":      true,
	"gcpkms":   true,
	"kv":       true,
}

// Config holds the configuration of the Vault initialization
type Config struct {
	// how many key parts exist
	SecretShares int
	// how many of these parts are needed to unseal Vault (secretThreshold <= secretShares)
	SecretThreshold int

	// if this root token is set, the dynamic generated will be invalidated and this created instead
	InitRootToken string
	// should the root token be stored in the keyStore
	StoreRootToken bool

	// should the KV backend be tested first to validate access rights
	PreFlightChecks bool
}

// vault is an implementation of the Vault interface that will perform actions
// against a Vault server, using a provided KMS to retrieve
type vault struct {
	keyStore    kv.Service
	cl          *api.Client
	config      *Config
	rotateCache map[string]bool
}

// Interface check
var _ Vault = &vault{}

// Vault is an interface that can be used to attempt to perform actions against
// a Vault server.
type Vault interface {
	Init() error
	Sealed() (bool, error)
	Active() (bool, error)
	Unseal() error
	Leader() (bool, error)
	Configure(config *viper.Viper) error
	StepDownActive(string) error
}

// New returns a new vault Vault, or an error.
func New(k kv.Service, cl *api.Client, config Config) (Vault, error) {

	if config.SecretShares < config.SecretThreshold {
		return nil, errors.New("the secret threshold can't be bigger than the shares")
	}

	return &vault{
		keyStore:    k,
		cl:          cl,
		config:      &config,
		rotateCache: map[string]bool{},
	}, nil
}

func (v *vault) Sealed() (bool, error) {
	resp, err := v.cl.Sys().SealStatus()
	if err != nil {
		return false, fmt.Errorf("error checking status: %s", err.Error())
	}
	return resp.Sealed, nil
}

func (v *vault) Active() (bool, error) {
	req := v.cl.NewRequest("GET", "/v1/sys/health")
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	resp, err := v.cl.RawRequestWithContext(ctx, req)
	if err != nil {
		return false, fmt.Errorf("error checking status: %s", err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, fmt.Errorf("error unexpected status code: %d", resp.StatusCode)
}

func (v *vault) Leader() (bool, error) {
	resp, err := v.cl.Sys().Leader()
	if err != nil {
		return false, fmt.Errorf("error checking leader: %s", err.Error())
	}
	return resp.IsSelf, nil
}

// Unseal will attempt to unseal vault by retrieving keys from the kms service
// and sending unseal requests to vault. It will return an error if retrieving
// a key fails, or if the unseal progress is reset to 0 (indicating that a key)
// was invalid.
func (v *vault) Unseal() error {
	defer runtime.GC()
	for i := 0; ; i++ {
		keyID := v.unsealKeyForID(i)

		logrus.Debugf("retrieving key from kms service...")
		k, err := v.keyStore.Get(keyID)

		if err != nil {
			return fmt.Errorf("unable to get key '%s': %s", keyID, err.Error())
		}

		logrus.Debugf("sending unseal request to vault...")
		resp, err := v.cl.Sys().Unseal(string(k))

		if err != nil {
			return fmt.Errorf("fail to send unseal request to vault: %s", err.Error())
		}

		logrus.Debugf("got unseal response: %+v", *resp)

		if !resp.Sealed {
			return nil
		}

		// if progress is 0, we failed to unseal vault.
		if resp.Progress == 0 {
			return fmt.Errorf("failed to unseal vault. progress reset to 0")
		}
	}
}

func (v *vault) keyStoreNotFound(key string) (bool, error) {
	_, err := v.keyStore.Get(key)
	if _, ok := err.(*kv.NotFoundError); ok {
		return true, nil
	}
	return false, err
}

func (v *vault) keyStoreSet(key string, val []byte) error {
	notFound, err := v.keyStoreNotFound(key)
	if notFound {
		return v.keyStore.Set(key, val)
	} else if err == nil {
		return fmt.Errorf("error setting key '%s': it already exists", key)
	} else {
		return fmt.Errorf("error setting key '%s': %s", key, err.Error())
	}
}

// Init initializes Vault if is not initialized already
func (v *vault) Init() error {
	initialized, err := v.cl.Sys().InitStatus()
	if err != nil {
		return fmt.Errorf("error testing if vault is initialized: %s", err.Error())
	}
	if initialized {
		logrus.Info("vault is already initialized")
		return nil
	}

	logrus.Info("initializing vault")

	// test backend first
	if v.config.PreFlightChecks {
		tester := kv.Tester{Service: v.keyStore}
		err = tester.Test(v.testKey())
		if err != nil {
			return fmt.Errorf("error testing keystore before init: %s", err.Error())
		}
	}

	// test for an existing keys
	keys := []string{
		v.rootTokenKey(),
	}

	// add unseal keys
	for i := 0; i <= v.config.SecretShares; i++ {
		keys = append(keys, v.unsealKeyForID(i))
	}

	// test every key
	for _, key := range keys {
		notFound, err := v.keyStoreNotFound(key)
		if notFound && err != nil {
			return fmt.Errorf("error before init: checking key '%s' failed: %s", key, err.Error())
		} else if !notFound && err == nil {
			return fmt.Errorf("error before init: value for key '%s' already exists", key)
		}
	}

	resp, err := v.cl.Sys().Init(&api.InitRequest{
		SecretShares:      v.config.SecretShares,
		SecretThreshold:   v.config.SecretThreshold,
		RecoveryShares:    v.config.SecretShares,
		RecoveryThreshold: v.config.SecretThreshold,
	})

	if err != nil {
		return fmt.Errorf("error initializing vault: %s", err.Error())
	}

	for i, k := range resp.Keys {
		keyID := v.unsealKeyForID(i)
		err := v.keyStoreSet(keyID, []byte(k))

		if err != nil {
			return fmt.Errorf("error storing unseal key '%s': %s", keyID, err.Error())
		}

		logrus.WithField("key", keyID).Info("unseal key stored in key store")
	}

	for i, k := range resp.RecoveryKeys {
		keyID := v.recoveryKeyForID(i)
		err := v.keyStoreSet(keyID, []byte(k))

		if err != nil {
			return fmt.Errorf("error storing recovery key '%s': %s", keyID, err.Error())
		}

		logrus.WithField("key", keyID).Info("recovery key stored in key store")
	}

	rootToken := resp.RootToken

	// this sets up a predefined root token
	if v.config.InitRootToken != "" {
		logrus.Info("setting up init root token, waiting for vault to be unsealed")

		count := 0
		wait := time.Second * 2
		for {
			sealed, err := v.Sealed()
			if !sealed {
				break
			}
			if err == nil {
				logrus.Info("vault still sealed, wait for unsealing")
			} else {
				logrus.Infof("vault not reachable: %s", err.Error())
			}

			count++
			time.Sleep(wait)
		}

		// use temporary token
		v.cl.SetToken(resp.RootToken)

		// setup root token with provided key
		_, err := v.cl.Auth().Token().CreateOrphan(&api.TokenCreateRequest{
			ID:          v.config.InitRootToken,
			Policies:    []string{"root"},
			DisplayName: "root-token",
			NoParent:    true,
		})
		if err != nil {
			return fmt.Errorf("unable to setup requested root token, (temporary root token: '%s'): %s", resp.RootToken, err)
		}

		// revoke the temporary token
		err = v.cl.Auth().Token().RevokeSelf(resp.RootToken)
		if err != nil {
			return fmt.Errorf("unable to revoke temporary root token: %s", err.Error())
		}

		rootToken = v.config.InitRootToken
	}

	if v.config.StoreRootToken {
		rootTokenKey := v.rootTokenKey()
		if err = v.keyStoreSet(rootTokenKey, []byte(resp.RootToken)); err != nil {
			return fmt.Errorf("error storing root token '%s' in key'%s'", rootToken, rootTokenKey)
		}
		logrus.WithField("key", rootTokenKey).Info("root token stored in key store")
	} else if v.config.InitRootToken == "" {
		logrus.WithField("root-token", resp.RootToken).Warnf("won't store root token in key store, this token grants full privileges to vault, so keep this secret")
	}

	return nil
}

func (v *vault) StepDownActive(address string) error {
	logrus.Debugf("retrieving key from kms service...")

	rootToken, err := v.keyStore.Get(v.rootTokenKey())
	if err != nil {
		return fmt.Errorf("unable to get key '%s': %s", v.rootTokenKey(), err.Error())
	}
	// Clear the token and GC it
	defer runtime.GC()
	defer v.cl.SetToken("")
	defer func() { rootToken = nil }()

	tmpClient, err := api.NewClient(nil)
	if err != nil {
		return fmt.Errorf("unable to create temporary client: %s", err.Error())
	}

	tmpClient.SetAddress(address)
	tmpClient.SetToken(string(rootToken))

	return tmpClient.Sys().StepDown()
}

func (v *vault) Configure(config *viper.Viper) error {
	logrus.Debugf("retrieving key from kms service...")

	rootToken, err := v.keyStore.Get(v.rootTokenKey())
	if err != nil {
		return fmt.Errorf("unable to get key '%s': %s", v.rootTokenKey(), err.Error())
	}

	v.cl.SetToken(string(rootToken))

	// Clear the token and GC it
	defer runtime.GC()
	defer v.cl.SetToken("")
	defer func() { rootToken = nil }()

	err = v.configureAuthMethods(config)
	if err != nil {
		return fmt.Errorf("error configuring auth methods for vault: %s", err.Error())
	}

	err = v.configurePolicies(config)
	if err != nil {
		return fmt.Errorf("error configuring policies for vault: %s", err.Error())
	}

	err = v.configurePlugins(config)
	if err != nil {
		return fmt.Errorf("error configuring plugins for vault: %s", err.Error())
	}

	err = v.configureSecretEngines(config)
	if err != nil {
		return fmt.Errorf("error configuring secret engines for vault: %s", err.Error())
	}

	err = v.configureAuditDevices(config)
	if err != nil {
		return fmt.Errorf("error configuring audit devices for vault: %s", err.Error())
	}

	err = v.configureStartupSecrets(config)
	if err != nil {
		return fmt.Errorf("error writing startup secrets tor vault: %s", err.Error())
	}

	err = v.configureIdentityGroups(config)
	if err != nil {
		return fmt.Errorf("error writing groups configurations for vault: %s", err.Error())
	}

	return err
}

func (*vault) unsealKeyForID(i int) string {
	return fmt.Sprint("vault-unseal-", i)
}

func (*vault) recoveryKeyForID(i int) string {
	return fmt.Sprint("vault-recovery-", i)
}

func (*vault) rootTokenKey() string {
	return fmt.Sprint("vault-root")
}

func (*vault) testKey() string {
	return fmt.Sprint("vault-test")
}

func (v *vault) kubernetesAuthConfigDefault() (map[string]interface{}, error) {
	kubernetesCACert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, err
	}
	tokenReviewerJWT, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, err
	}
	config := map[string]interface{}{
		"kubernetes_host":    fmt.Sprint("https://", os.Getenv("KUBERNETES_SERVICE_HOST")),
		"kubernetes_ca_cert": string(kubernetesCACert),
		"token_reviewer_jwt": string(tokenReviewerJWT),
	}
	return config, err
}

func (v *vault) configureAuthMethods(config *viper.Viper) error {
	authMethods := []map[string]interface{}{}
	err := config.UnmarshalKey("auth", &authMethods)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault auth methods config: %s", err.Error())
	}

	existingAuths, err := v.cl.Sys().ListAuth()

	if err != nil {
		return fmt.Errorf("error listing auth backends vault: %s", err.Error())
	}

	for _, authMethod := range authMethods {
		authMethodType, err := cast.ToStringE(authMethod["type"])
		if err != nil {
			return fmt.Errorf("error finding auth method type: %s", err.Error())
		}

		path := authMethodType
		if pathOverwrite, ok := authMethod["path"]; ok {
			path, err = cast.ToStringE(pathOverwrite)
			if err != nil {
				return fmt.Errorf("error converting path for auth method: %s", err.Error())
			}
			path = strings.Trim(path, "/")
		}

		description := fmt.Sprintf("%s backend", authMethodType)
		if descriptionOverwrite, ok := authMethod["description"]; ok {
			description, err = cast.ToStringE(descriptionOverwrite)
			if err != nil {
				return fmt.Errorf("error converting description for auth method: %s", err.Error())
			}
		}

		// Check and skip existing auth mounts
		exists := false
		if authMount, ok := existingAuths[path+"/"]; ok {
			if authMount.Type == authMethodType {
				logrus.Debugf("%s auth backend is already mounted in vault", authMethodType)
				exists = true
			}
		}

		if !exists {
			logrus.Debugf("enabling %s auth backend in vault...", authMethodType)

			// https://www.vaultproject.io/api/system/auth.html
			options := api.EnableAuthOptions{
				Type:        authMethodType,
				Description: description,
			}

			err := v.cl.Sys().EnableAuthWithOptions(path, &options)

			if err != nil {
				return fmt.Errorf("error enabling %s auth method for vault: %s", authMethodType, err.Error())
			}
		}

		switch authMethodType {
		case "kubernetes":
			config, err := getOrDefaultStringMap(authMethod, "config")
			if err != nil {
				return fmt.Errorf("error finding config block for kubernetes: %s", err.Error())
			}
			// If kubernetes_host is defined we are probably out of cluster, so don't read the default config
			if _, ok := config["kubernetes_host"]; !ok {
				defaultConfig, err := v.kubernetesAuthConfigDefault()
				if err != nil {
					return fmt.Errorf("error getting default kubernetes auth config for vault: %s", err.Error())
				}
				// merge the config blocks
				for k, v := range config {
					defaultConfig[k] = v
				}
				config = defaultConfig
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return fmt.Errorf("error configuring kubernetes auth for vault: %s", err.Error())
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return fmt.Errorf("error finding roles block for kubernetes: %s", err.Error())
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
			if err != nil {
				return fmt.Errorf("error configuring kubernetes auth roles for vault: %s", err.Error())
			}
		case "github":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return fmt.Errorf("error finding config block for github: %s", err.Error())
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return fmt.Errorf("error configuring github auth for vault: %s", err.Error())
			}
			mappings, err := cast.ToStringMapE(authMethod["map"])
			if err != nil {
				return fmt.Errorf("error finding map block for github: %s", err.Error())
			}
			err = v.configureGithubMappings(path, mappings)
			if err != nil {
				return fmt.Errorf("error configuring github mappings for vault: %s", err.Error())
			}
		case "aws":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return fmt.Errorf("error finding config block for aws: %s", err.Error())
			}
			err = v.configureAwsConfig(path, config)
			if err != nil {
				return fmt.Errorf("error configuring aws auth for vault: %s", err.Error())
			}
			if crossaccountroleRaw, ok := authMethod["crossaccountrole"]; ok {
				crossaccountrole, err := cast.ToSliceE(crossaccountroleRaw)
				if err != nil {
					return fmt.Errorf("error finding crossaccountrole block for aws: %s", err.Error())
				}
				err = v.configureAWSCrossAccountRoles(path, crossaccountrole)
				if err != nil {
					return fmt.Errorf("error configuring aws auth cross account roles for vault: %s", err.Error())
				}
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return fmt.Errorf("error finding roles block for aws: %s", err.Error())
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
			if err != nil {
				return fmt.Errorf("error configuring aws auth roles for vault: %s", err.Error())
			}
		case "gcp":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return fmt.Errorf("error finding config block for gcp: %s", err.Error())
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return fmt.Errorf("error configuring gcp auth for vault: %s", err.Error())
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return fmt.Errorf("error finding roles block for gcp: %s", err.Error())
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
			if err != nil {
				return fmt.Errorf("error configuring gcp auth roles for vault: %s", err.Error())
			}
		case "approle":
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return fmt.Errorf("error finding role block for approle: %s", err.Error())
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
			if err != nil {
				return fmt.Errorf("error configuring approle auth for vault: %s", err.Error())
			}
		case "jwt", "oidc":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return fmt.Errorf("error finding config block for %s: %s", authMethodType, err.Error())
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return fmt.Errorf("error configuring %s auth on path %s for vault: %s", authMethodType, path, err.Error())
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return fmt.Errorf("error finding roles block for %s: %s", authMethodType, err.Error())
			}
			err = v.configureJwtRoles(path, roles)
			if err != nil {
				return fmt.Errorf("error configuring %s roles on path %s for vault: %s", authMethodType, path, err.Error())
			}
		case "token":
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return fmt.Errorf("error finding roles block for token: %s", err.Error())
			}
			err = v.configureGenericAuthRoles(authMethodType, "token", "roles", roles)
			if err != nil {
				return fmt.Errorf("error configuring token roles for vault: %s", err.Error())
			}
		case "cert":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return fmt.Errorf("error finding config block for cert: %s", err.Error())
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return fmt.Errorf("error configuring cert auth for vault: %s", err.Error())
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return fmt.Errorf("error finding roles block for certs: %s", err.Error())
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "certs", roles)
			if err != nil {
				return fmt.Errorf("error configuring certs auth roles for vault: %s", err.Error())
			}
		case "ldap", "okta":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return fmt.Errorf("error finding config block for %s: %s", authMethodType, err.Error())
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return fmt.Errorf("error configuring %s auth on path %s for vault: %s", authMethodType, path, err.Error())
			}
			for _, usersOrGroupsKey := range []string{"groups", "users"} {
				if userOrGroupRaw, ok := authMethod[usersOrGroupsKey]; ok {
					userOrGroup, err := cast.ToStringMapE(userOrGroupRaw)
					if err != nil {
						return fmt.Errorf("error finding %s block for %s: %s", usersOrGroupsKey, authMethodType, err.Error())
					}
					err = v.configureGenericUserAndGroupMappings(authMethodType, path, usersOrGroupsKey, userOrGroup)
					if err != nil {
						return fmt.Errorf("error configuring %s %s for vault: %s", authMethodType, usersOrGroupsKey, err.Error())
					}
				}
			}
		}
	}

	return nil
}

func (v *vault) configurePolicies(config *viper.Viper) error {
	policies := []map[string]string{}

	err := config.UnmarshalKey("policies", &policies)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault policy config: %s", err.Error())
	}

	for _, policy := range policies {

		policyName := policy["name"]
		policyRules, err := hclPrinter.Format([]byte(policy["rules"]))
		if err != nil {
			return fmt.Errorf("error formatting %s policy rules: %s", policyName, err.Error())
		}

		err = v.cl.Sys().PutPolicy(policyName, string(policyRules))
		if err != nil {
			return fmt.Errorf("error putting %s policy into vault: %s", policyName, err.Error())
		}
	}

	return nil
}

func (v *vault) configureGithubMappings(path string, mappings map[string]interface{}) error {
	for mappingType, mapping := range mappings {
		mapping, err := cast.ToStringMapStringE(mapping)
		if err != nil {
			return fmt.Errorf("error converting mapping for github: %s", err.Error())
		}
		for userOrTeam, policy := range mapping {
			_, err := v.cl.Logical().Write(fmt.Sprintf("auth/%s/map/%s/%s", path, mappingType, userOrTeam), map[string]interface{}{"value": policy})
			if err != nil {
				return fmt.Errorf("error putting %s github mapping into vault: %s", mappingType, err.Error())
			}
		}
	}
	return nil
}

func (v *vault) configureAwsConfig(path string, config map[string]interface{}) error {
	// https://www.vaultproject.io/api/auth/aws/index.html
	_, err := v.cl.Logical().Write(fmt.Sprintf("auth/%s/config/client", path), config)

	if err != nil {
		return fmt.Errorf("error putting aws config into vault: %s", err.Error())
	}
	return nil
}

// configureGenericAuthRoles supports a very generic configuration format for auth roles, which is followed by:
// https://www.vaultproject.io/api/auth/jwt/index.html partially
// https://www.vaultproject.io/api/auth/kubernetes/index.html
// https://www.vaultproject.io/api/auth/gcp/index.html
// https://www.vaultproject.io/api/auth/aws/index.html
// https://www.vaultproject.io/api/auth/approle/index.html
// https://www.vaultproject.io/api/auth/token/index.html
func (v *vault) configureGenericAuthRoles(method, path, roleSubPath string, roles []interface{}) error {
	for _, roleInterface := range roles {
		role, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return fmt.Errorf("error converting roles for %s: %s", method, err.Error())
		}

		_, err = v.cl.Logical().Write(fmt.Sprintf("auth/%s/%s/%s", path, roleSubPath, role["name"]), role)
		if err != nil {
			return fmt.Errorf("error putting %s %s role into vault: %s", role["name"], method, err.Error())
		}
	}
	return nil
}

func (v *vault) configureAWSCrossAccountRoles(path string, crossAccountRoles []interface{}) error {
	for _, roleInterface := range crossAccountRoles {
		crossAccountRole, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return fmt.Errorf("error converting cross account aws roles for aws: %s", err.Error())
		}

		stsAccount := fmt.Sprint(crossAccountRole["sts_account"])

		_, err = v.cl.Logical().Write(fmt.Sprintf("auth/%s/config/sts/%s", path, stsAccount), crossAccountRole)
		if err != nil {
			return fmt.Errorf("error putting %s cross account aws role into vault: %s", stsAccount, err.Error())
		}
	}
	return nil
}

// configureGenericAuthConfig supports a very generic configuration format, which is followed by:
// https://www.vaultproject.io/api/auth/jwt/index.html
// https://www.vaultproject.io/api/auth/kubernetes/index.html
// https://www.vaultproject.io/api/auth/okta/index.html
// https://www.vaultproject.io/api/auth/ldap/index.html
// https://www.vaultproject.io/api/auth/gcp/index.html
// https://www.vaultproject.io/api/auth/github/index.html
func (v *vault) configureGenericAuthConfig(method, path string, config map[string]interface{}) error {
	_, err := v.cl.Logical().Write(fmt.Sprintf("auth/%s/config", path), config)

	if err != nil {
		return fmt.Errorf("error putting %s auth config into vault: %s", method, err.Error())
	}
	return nil
}

// TODO try to generalize this with configureGenericAuthRoles() fix the type flaw
func (v *vault) configureJwtRoles(path string, roles []interface{}) error {
	for _, roleInterface := range roles {
		role, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return fmt.Errorf("error converting roles for jwt: %s", err.Error())
		}
		// role can have have a bound_claims or claim_mappings child dict. But it will cause:
		// `json: unsupported type: map[interface {}]interface {}`
		// So check and replace by `map[string]interface{}` before using it.
		if val, ok := role["bound_claims"]; ok {
			role["bound_claims"] = cast.ToStringMap(val)
		}
		if val, ok := role["claim_mappings"]; ok {
			role["claim_mappings"] = cast.ToStringMap(val)
		}

		_, err = v.cl.Logical().Write(fmt.Sprintf("auth/%s/role/%s", path, role["name"]), role)

		if err != nil {
			return fmt.Errorf("error putting %s jwt role into vault: %s", role["name"], err.Error())
		}
	}
	return nil
}

func (v *vault) configureGenericUserAndGroupMappings(method, path string, mappingType string, mappings map[string]interface{}) error {
	for userOrGroup, policy := range mappings {
		mapping, err := cast.ToStringMapE(policy)
		if err != nil {
			return fmt.Errorf("error converting mapping for %s: %s", method, err.Error())
		}
		_, err = v.cl.Logical().Write(fmt.Sprintf("auth/%s/%s/%s", path, mappingType, userOrGroup), mapping)
		if err != nil {
			return fmt.Errorf("error putting %s %s mapping into vault: %s", method, mappingType, err.Error())
		}
	}
	return nil
}

func (v *vault) configurePlugins(config *viper.Viper) error {
	plugins := []map[string]interface{}{}
	err := config.UnmarshalKey("plugins", &plugins)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault plugins config: %s", err.Error())
	}

	listPlugins, err := v.cl.Sys().ListPlugins(&api.ListPluginsInput{})
	if err != nil {
		return fmt.Errorf("failed to retrieve list of plugins: %s", err.Error())
	}

	logrus.Debugf("already registered plugins: %#v", listPlugins.Names)

	for _, plugin := range plugins {
		command, err := getOrError(plugin, "command")
		if err != nil {
			return fmt.Errorf("error getting command for plugin: %s", err.Error())
		}
		pluginName, err := getOrError(plugin, "plugin_name")
		if err != nil {
			return fmt.Errorf("error getting plugin_name for plugin: %s", err.Error())
		}
		sha256, err := getOrError(plugin, "sha256")
		if err != nil {
			return fmt.Errorf("error getting sha256 for plugin: %s", err.Error())
		}
		typeRaw, err := getOrError(plugin, "type")
		if err != nil {
			return fmt.Errorf("error getting type for plugin: %s", err.Error())
		}
		pluginType, err := consts.ParsePluginType(typeRaw)
		if err != nil {
			return fmt.Errorf("error parsing type for plugin: %s", err.Error())
		}

		input := api.RegisterPluginInput{
			Name:    pluginName,
			Command: command,
			SHA256:  sha256,
			Type:    pluginType,
		}
		logrus.Infof("registering plugin with input: %#v", input)

		err = v.cl.Sys().RegisterPlugin(&input)
		if err != nil {
			return fmt.Errorf("error registering plugin %s in vault", err.Error())
		}

		logrus.Infoln("registered plugin", plugin)
	}

	return nil
}

func (v *vault) mountExists(path string) (bool, error) {
	mounts, err := v.cl.Sys().ListMounts()
	if err != nil {
		return false, fmt.Errorf("error reading mounts from vault: %s", err.Error())
	}
	logrus.Infof("already existing mounts: %+v", mounts)
	return mounts[path+"/"] != nil, nil
}

func (v *vault) configureSecretEngines(config *viper.Viper) error {
	secretsEngines := []map[string]interface{}{}
	err := config.UnmarshalKey("secrets", &secretsEngines)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault secrets config: %s", err.Error())
	}

	for _, secretEngine := range secretsEngines {
		secretEngineType, err := cast.ToStringE(secretEngine["type"])
		if err != nil {
			return fmt.Errorf("error finding type for secret engine: %s", err.Error())
		}

		path := secretEngineType
		if pathOverwrite, ok := secretEngine["path"]; ok {
			path, err = cast.ToStringE(pathOverwrite)
			if err != nil {
				return fmt.Errorf("error converting path for secret engine: %s", err.Error())
			}
			path = strings.Trim(path, "/")
		}

		mountExists, err := v.mountExists(path)
		if err != nil {
			return err
		}

		if !mountExists {
			description, err := getOrDefaultString(secretEngine, "description")
			if err != nil {
				return fmt.Errorf("error getting description for secret engine: %s", err.Error())
			}
			pluginName, err := getOrDefaultString(secretEngine, "plugin_name")
			if err != nil {
				return fmt.Errorf("error getting plugin_name for secret engine: %s", err.Error())
			}
			local, err := getOrDefaultBool(secretEngine, "local")
			if err != nil {
				return fmt.Errorf("error getting local for secret engine: %s", err.Error())
			}
			sealWrap, err := getOrDefaultBool(secretEngine, "seal_wrap")
			if err != nil {
				return fmt.Errorf("error getting seal_wrap for secret engine: %s", err.Error())
			}
			config, err := getMountConfigInput(secretEngine)
			if err != nil {
				return err
			}
			input := api.MountInput{
				Type:        secretEngineType,
				Description: description,
				PluginName:  pluginName,
				Config:      config,
				Options:     config.Options, // options needs to be sent here first time
				Local:       local,
				SealWrap:    sealWrap,
			}
			logrus.Infof("mounting secret engine with input: %#v", input)
			err = v.cl.Sys().Mount(path, &input)
			if err != nil {
				return fmt.Errorf("error mounting %s into vault: %s", path, err.Error())
			}

			logrus.Infoln("mounted", secretEngineType, "to", path)

		} else {
			logrus.Infof("tuning already existing mount: %s/", path)
			config, err := getMountConfigInput(secretEngine)
			if err != nil {
				return err
			}
			err = v.cl.Sys().TuneMount(path, config)
			if err != nil {
				return fmt.Errorf("error tuning %s in vault: %s", path, err.Error())
			}
		}

		// Configuration of the Secret Engine in a very generic manner, YAML config file should have the proper format
		configuration, err := getOrDefaultStringMap(secretEngine, "configuration")
		if err != nil {
			return fmt.Errorf("error getting configuration for secret engine: %s", err.Error())
		}

		for configOption, configData := range configuration {
			configData, err := cast.ToSliceE(configData)
			if err != nil {
				return fmt.Errorf("error converting config data for secret engine: %s", err.Error())
			}
			for _, subConfigData := range configData {
				subConfigData, err := cast.ToStringMapE(subConfigData)
				if err != nil {
					return fmt.Errorf("error converting sub config data for secret engine: %s", err.Error())
				}

				name, ok := subConfigData["name"]
				if !ok && !isConfigNoNeedName(secretEngineType, configOption) {
					return fmt.Errorf("error finding sub config data name for secret engine: %s/%s", path, configOption)
				}

				// config data can have a child dict. But it will cause:
				// `json: unsupported type: map[interface {}]interface {}`
				// So check and replace by `map[string]interface{}` before using it.
				for k, v := range subConfigData {
					switch val := v.(type) {
					case map[interface{}]interface{}:
						subConfigData[k] = cast.ToStringMap(val)
					}
				}

				var configPath string
				if name != nil {
					configPath = fmt.Sprintf("%s/%s/%s", path, configOption, name)
				} else {
					configPath = fmt.Sprintf("%s/%s", path, configOption)
				}

				rotate := cast.ToBool(subConfigData["rotate"])

				// For secret engines where the root credentials are rotatable we don't wan't to reconfigure again
				// with the old credentials, because that would cause access denied issues. Currently these are:
				// - AWS
				// - Database
				if rotate && mountExists &&
					((secretEngineType == "database" && configOption == "config") ||
						(secretEngineType == "aws" && configOption == "config/root")) {

					// TODO we need to find out if it was rotated or not
					err = v.rotateSecretEngineCredentials(secretEngineType, path, name.(string), configPath)
					if err != nil {
						return fmt.Errorf("error rotating credentials for '%s' config in vault: %s", configPath, err.Error())
					}

					logrus.Infof("skipping reconfiguration of %s because of credential rotation", configPath)
					continue
				}

				// Control if the configs should be updated or just Created once and skipped later on
				// This is a workaround to secrets backend like GCP that will destroy and recreate secrets at every iteration
				createOnly := cast.ToBool(subConfigData["create_only"])
				// Delete the create_only key from the map, so we don't push it to vault
				delete(subConfigData, "create_only")

				if createOnly && mountExists {
					sec, err := v.cl.Logical().Read(configPath)
					if err != nil {
						return fmt.Errorf("error reading configPath %s: %s", configPath, err.Error())
					}

					if sec != nil {
						logrus.Infoln("Secret at configpath ", configPath, "already exists, create_only was set so this will skipped and not updated")
						continue
					}
				}

				_, err = v.cl.Logical().Write(configPath, subConfigData)
				if err != nil {
					if isOverwriteProhibitedError(err) {
						logrus.Infoln("can't reconfigure", configPath, "please delete it manually")
						continue
					}
					return fmt.Errorf("error configuring %s config in vault: %s", configPath, err.Error())
				}

				if rotate {
					err = v.rotateSecretEngineCredentials(secretEngineType, path, name.(string), configPath)
					if err != nil {
						return fmt.Errorf("error rotating credentials for '%s' config in vault: %s", configPath, err.Error())
					}
				}
			}
		}
	}

	return nil
}

func (v *vault) rotateSecretEngineCredentials(secretEngineType, path, name, configPath string) error {
	var rotatePath string
	switch secretEngineType {
	case "aws":
		rotatePath = fmt.Sprintf("%s/config/rotate-root", path)
	case "database":
		rotatePath = fmt.Sprintf("%s/rotate-root/%s", path, name)
	case "gcp":
		rotatePath = fmt.Sprintf("%s/%s/rotate", path, name)
	default:
		return fmt.Errorf("secret engine type '%s' doesn't support credential rotation", secretEngineType)
	}

	if _, ok := v.rotateCache[rotatePath]; !ok {

		logrus.Infoln("doing credential rotation at", rotatePath)

		_, err := v.cl.Logical().Write(rotatePath, nil)
		if err != nil {
			return fmt.Errorf("error rotating credentials for '%s' config in vault: %s", configPath, err.Error())
		}

		logrus.Infoln("credential got rotated at", rotatePath)

		v.rotateCache[rotatePath] = true
	} else {
		logrus.Infoln("credentials were rotated previously for", rotatePath)
	}

	return nil
}

func (v *vault) configureAuditDevices(config *viper.Viper) error {
	auditDevices := []map[string]interface{}{}
	err := config.UnmarshalKey("audit", &auditDevices)
	if err != nil {
		return fmt.Errorf("error unmarshalling audit devices config: %s", err.Error())
	}

	for _, auditDevice := range auditDevices {
		auditDeviceType, err := cast.ToStringE(auditDevice["type"])
		if err != nil {
			return fmt.Errorf("error finding type for audit device: %s", err.Error())
		}

		path := auditDeviceType
		if pathOverwrite, ok := auditDevice["path"]; ok {
			path, err = cast.ToStringE(pathOverwrite)
			if err != nil {
				return fmt.Errorf("error converting path for audit device: %s", err.Error())
			}
			path = strings.Trim(path, "/")
		}

		mounts, err := v.cl.Sys().ListAudit()
		if err != nil {
			return fmt.Errorf("error reading audit mounts from vault: %s", err.Error())
		}

		logrus.Infof("already existing audit devices: %#v", mounts)

		if mounts[path+"/"] == nil {
			var options api.EnableAuditOptions
			err = mapstructure.Decode(auditDevice, &options)
			if err != nil {
				return fmt.Errorf("error parsing audit options: %s", err.Error())
			}
			logrus.Infof("enabling audit device with options: %#v", options)
			err = v.cl.Sys().EnableAuditWithOptions(path, &options)
			if err != nil {
				return fmt.Errorf("error enabling audit device %s in vault: %s", path, err.Error())
			}

			logrus.Infoln("mounted audit device", auditDeviceType, "to", path)

		} else {
			logrus.Infof("audit device is already mounted: %s/", path)
		}
	}

	return nil
}

func (v *vault) configureStartupSecrets(config *viper.Viper) error {
	raw := config.Get("startupSecrets")
	startupSecrets, err := toSliceStringMapE(raw)
	if err != nil {
		return fmt.Errorf("error decoding data for startup secrets: %s", err.Error())
	}
	for _, startupSecret := range startupSecrets {
		startupSecretType, err := cast.ToStringE(startupSecret["type"])
		if err != nil {
			return fmt.Errorf("error finding type for startup secret: %s", err.Error())
		}

		switch startupSecretType {
		case "kv":
			path, err := cast.ToStringE(startupSecret["path"])
			if err != nil {
				return fmt.Errorf("error findind path for startup secret: %s", err.Error())
			}

			data, err := getOrDefaultStringMap(startupSecret, "data")
			if err != nil {
				return fmt.Errorf("error getting data for startup secret '%s': %s", path, err.Error())
			}

			_, err = v.cl.Logical().Write(path, data)
			if err != nil {
				return fmt.Errorf("error writing data for startup secret '%s': %s", path, err.Error())
			}

		default:
			return errors.New("other startup secret type than 'kv' is not supported yet")
		}
	}
	return nil
}

func readVaultGroup(group string, client *api.Client) (secret *api.Secret, err error) {
	secret, err = client.Logical().Read(fmt.Sprintf("identity/group/name/%s", group))
	if err != nil {
		return nil, fmt.Errorf("failed to read group %s by name: %v", group, err)
	}
	if secret == nil {
		// No Data returned, Group does not exist
		return nil, nil
	}
	return secret, nil
}

func readVaultGroupAlias(id string, client *api.Client) (secret *api.Secret, err error) {
	secret, err = client.Logical().Read(fmt.Sprintf("identity/group-alias/id/%s", id))
	if err != nil {
		return nil, fmt.Errorf("failed to read group alias %s by id: %v", id, err)
	}
	if secret == nil {
		// No Data returned, Group does not exist
		return nil, nil
	}
	return secret, nil
}

func getVaultAuthMountAccessor(path string, client *api.Client) (accessor string, err error) {
	path = strings.TrimRight(path, "/") + "/"
	mounts, err := client.Sys().ListAuth()

	if err != nil {
		return "", fmt.Errorf("failed to read auth mounts from vault: %s", err)
	}
	if mounts[path] == nil {
		return "", fmt.Errorf("auth mount path %s does not exist on vaut", path)
	}
	return mounts[path].Accessor, nil
}

func getVaultGroupId(group string, client *api.Client) (id string, err error) {
	g, err := readVaultGroup(group, client)
	if err != nil {
		return "", fmt.Errorf("error reading group %s: %s", group, err)
	}
	if g == nil {
		return "", fmt.Errorf("group %s does not exist", group)
	}
	return g.Data["id"].(string), nil
}

func getVaultGroupAliasName(aliasId string, client *api.Client) (id string, err error) {
	alias, err := readVaultGroupAlias(aliasId, client)
	if err != nil {
		return "", fmt.Errorf("error reading group alias %s: %s", aliasId, err)
	}
	if alias == nil {
		return "", fmt.Errorf("group alias %s does not exist", aliasId)
	}
	return alias.Data["name"].(string), nil
}

func findVaultGroupAliasIDFromName(name string, client *api.Client) (id string, err error) {
	aliases, err := client.Logical().List("identity/group-alias/id")

	if err != nil {
		return "", fmt.Errorf("error listing group aliases: %s", err)
	}
	if aliases == nil {
		return "", nil
	}

	for _, alias := range aliases.Data["keys"].([]interface{}) {
		aliasName, err := getVaultGroupAliasName(cast.ToString(alias), client)
		if err != nil {
			return "", fmt.Errorf("error fetching name for alias id: %s", alias)
		}
		if aliasName == name {
			return cast.ToString(alias), nil
		}
	}

	// Did not find any alias matching ID to Name
	return "", nil
}

func (v *vault) configureIdentityGroups(config *viper.Viper) error {
	groups := []map[string]interface{}{}
	groupAliases := []map[string]interface{}{}

	err := config.UnmarshalKey("groups", &groups)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault groups config: %s", err.Error())
	}

	err = config.UnmarshalKey("group-aliases", &groupAliases)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault group aliases config: %s", err.Error())
	}

	for _, group := range groups {
		g, err := readVaultGroup(cast.ToString(group["name"]), v.cl)
		if err != nil {
			return fmt.Errorf("error reading group: %s", err)
		}

		// Currently does not support specifing members directly in the group config
		// Use group aliases for that
		if cast.ToString(group["type"]) != "external" {
			return fmt.Errorf("only external groups are supported for now")
		}

		config := map[string]interface{}{
			"name":     cast.ToString(group["name"]),
			"type":     cast.ToString(group["type"]),
			"policies": cast.ToStringSlice(group["policies"]),
			"metadata": cast.ToStringMap(group["metadata"]),
		}

		if g == nil {
			logrus.Infof("creating group: %s", group["name"])
			_, err = v.cl.Logical().Write("identity/group", config)
			if err != nil {
				return fmt.Errorf("failed to create group %s : %v", group["name"], err)
			}
		} else {
			logrus.Infof("tuning already existing group: %s", group["name"])
			_, err = v.cl.Logical().Write(fmt.Sprintf("identity/group/name/%s", group["name"]), config)
			if err != nil {
				return fmt.Errorf("failed to tune group %s : %v", group["name"], err)
			}
		}
	}

	for _, groupAlias := range groupAliases {
		ga, err := findVaultGroupAliasIDFromName(cast.ToString(groupAlias["name"]), v.cl)
		if err != nil {
			return fmt.Errorf("error finding group-alias: %s", err)
		}

		accessor, err := getVaultAuthMountAccessor(cast.ToString(groupAlias["mountpath"]), v.cl)
		if err != nil {
			return fmt.Errorf("error getting mount accessor for %s: %s", groupAlias["mountpath"], err)
		}

		id, err := getVaultGroupId(cast.ToString(groupAlias["group"]), v.cl)
		if err != nil {
			return fmt.Errorf("error getting canonical_id for group %s: %s", groupAlias["group"], err)
		}

		config := map[string]interface{}{
			"name":           cast.ToString(groupAlias["name"]),
			"mount_accessor": accessor,
			"canonical_id":   id,
		}

		if ga == "" {
			logrus.Infof("creating group-alias: %s", groupAlias["name"])
			_, err = v.cl.Logical().Write("identity/group-alias", config)
			if err != nil {
				return fmt.Errorf("failed to create group-alias %s : %v", groupAlias["name"], err)
			}
		} else {
			logrus.Infof("tuning already existing group-alias: %s - ID: %s", groupAlias["name"], ga)
			_, err = v.cl.Logical().Write(fmt.Sprintf("identity/group-alias/id/%s", ga), config)
			if err != nil {
				return fmt.Errorf("failed to tune group-alias %s : %v", ga, err)
			}
		}
	}

	return nil
}

// toSliceStringMapE casts []map[string]interface{} preserving nested types
func toSliceStringMapE(o interface{}) ([]map[string]interface{}, error) {
	data, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	var sm []map[string]interface{}
	return sm, json.Unmarshal(data, &sm)
}

func getOrDefaultBool(m map[string]interface{}, key string) (bool, error) {
	value := m[key]
	if value != nil {
		return cast.ToBoolE(value)
	}
	return false, nil
}

func getOrDefaultString(m map[string]interface{}, key string) (string, error) {
	value := m[key]
	if value != nil {
		return cast.ToStringE(value)
	}
	return "", nil
}

func getOrDefaultStringMapString(m map[string]interface{}, key string) (map[string]string, error) {
	value := m[key]
	if value != nil {
		return cast.ToStringMapStringE(value)
	}
	return map[string]string{}, nil
}

func getOrDefaultStringMap(m map[string]interface{}, key string) (map[string]interface{}, error) {
	value := m[key]
	if value != nil {
		return cast.ToStringMapE(value)
	}
	return map[string]interface{}{}, nil
}

func getOrError(m map[string]interface{}, key string) (string, error) {
	value := m[key]
	if value != nil {
		return cast.ToStringE(value)
	}
	return "", fmt.Errorf("value for %s is not set", key)
}

func isOverwriteProhibitedError(err error) bool {
	return strings.Contains(err.Error(), "delete them before reconfiguring")
}

func getMountConfigInput(secretEngine map[string]interface{}) (api.MountConfigInput, error) {
	var mountConfigInput api.MountConfigInput
	config, ok := secretEngine["config"]
	if ok {
		if err := mapstructure.Decode(config, &mountConfigInput); err != nil {
			return mountConfigInput, fmt.Errorf("error parsing config for secret engine: %s", err.Error())
		}
	}

	// Bank-Vaults supported options outside config to be used options in the mount request
	// so for now, to preserve backward compatibility we overwrite the options inside config
	// with the options outside.
	options, err := getOrDefaultStringMapString(secretEngine, "options")
	if err != nil {
		return mountConfigInput, fmt.Errorf("error getting options for secret engine: %s", err.Error())
	}
	mountConfigInput.Options = options

	return mountConfigInput, nil
}

func isConfigNoNeedName(secretEngineType string, configOption string) bool {
	if configOption == "config" {
		_, ok := secretEngineConfigNoNeedName[secretEngineType]
		return ok
	}

	if secretEngineType == "aws" && configOption == "config/root" {
		return true
	}

	return false
}
