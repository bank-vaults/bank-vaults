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
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/hashicorp/hcl"
	hclPrinter "github.com/hashicorp/hcl/hcl/printer"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/consts"
	json "github.com/json-iterator/go"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	crconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	vaultpkg "github.com/banzaicloud/bank-vaults/pkg/sdk/vault"
)

// DefaultConfigFile is the name of the default config file
const DefaultConfigFile = "vault-config.yml"

// secretEnginesWihtoutNameConfig holds the secret engine types where
// the name shouldn't be part of the config path
var secretEnginesWihtoutNameConfig = map[string]bool{
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
	keyStore    KVService
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
	RaftInitialized() (bool, error)
	RaftJoin(string) error
	Sealed() (bool, error)
	Active() (bool, error)
	Unseal() error
	Leader() (bool, error)
	Configure(config *viper.Viper) error
}

//
type KVService interface {
	Set(key string, value []byte) error
	Get(key string) ([]byte, error)
}

type kvTester struct {
	Service KVService
}

func (t kvTester) Test(key string) error {
	_, err := t.Service.Get(key)

	if err != nil {
		if !isNotFoundError(err) {
			return err
		}
	}

	return t.Service.Set(key, []byte(key))
}

// New returns a new vault Vault, or an error.
func New(k KVService, cl *api.Client, config Config) (Vault, error) {
	if config.SecretShares < config.SecretThreshold {
		return nil, errors.Errorf("the secret threshold can't be bigger than the shares [%d < %d]", config.SecretShares, config.SecretThreshold)
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
		return false, errors.Wrap(err, "error checking status")
	}
	return resp.Sealed, nil
}

func (v *vault) Active() (bool, error) {
	req := v.cl.NewRequest("GET", "/v1/sys/health")
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	resp, err := v.cl.RawRequestWithContext(ctx, req)
	if err != nil {
		return false, errors.Wrap(err, "error checking status")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, errors.Errorf("error unexpected status code: %d", resp.StatusCode)
}

func (v *vault) Leader() (bool, error) {
	resp, err := v.cl.Sys().Leader()
	if err != nil {
		return false, errors.Wrap(err, "error checking leader")
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
			return errors.Wrapf(err, "unable to get key '%s'", keyID)
		}

		logrus.Debugf("sending unseal request to vault...")
		resp, err := v.cl.Sys().Unseal(string(k))

		if err != nil {
			return errors.Wrap(err, "fail to send unseal request to vault")
		}

		logrus.Debugf("got unseal response: %+v", *resp)

		if !resp.Sealed {
			return nil
		}

		// if progress is 0, we failed to unseal vault.
		if resp.Progress == 0 {
			return errors.New("failed to unseal vault, are you using the right unseal keys?") // nolint:goerr113
		}
	}
}

type notFoundError interface {
	NotFound() bool
}

func isNotFoundError(err error) bool {
	cause := errors.Cause(err)
	if notFoundError, ok := cause.(notFoundError); ok && notFoundError.NotFound() {
		return true
	}
	return false
}

func (v *vault) keyStoreNotFound(key string) (bool, error) {
	_, err := v.keyStore.Get(key)
	if isNotFoundError(err) {
		return true, nil
	}
	return false, err
}

func (v *vault) keyStoreSet(key string, val []byte) error {
	notFound, err := v.keyStoreNotFound(key)
	if notFound {
		return v.keyStore.Set(key, val)
	} else if err == nil {
		return errors.Errorf("error setting key '%s': it already exists", key)
	} else {
		return errors.Wrapf(err, "error setting key '%s'", key)
	}
}

// Init initializes Vault if is not initialized already
func (v *vault) Init() error {
	initialized, err := v.cl.Sys().InitStatus()
	if err != nil {
		return errors.Wrap(err, "error testing if vault is initialized")
	}
	if initialized {
		logrus.Info("vault is already initialized")
		return nil
	}

	logrus.Info("initializing vault")

	// test backend first
	if v.config.PreFlightChecks {
		tester := kvTester{Service: v.keyStore}
		err = tester.Test(v.testKey())
		if err != nil {
			return errors.Wrap(err, "error testing keystore before init")
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
			return errors.Wrapf(err, "error before init: checking key '%s' failed", key)
		} else if !notFound && err == nil {
			return errors.Errorf("error before init: value for key '%s' already exists", key)
		}
	}

	resp, err := v.cl.Sys().Init(&api.InitRequest{
		SecretShares:      v.config.SecretShares,
		SecretThreshold:   v.config.SecretThreshold,
		RecoveryShares:    v.config.SecretShares,
		RecoveryThreshold: v.config.SecretThreshold,
	})

	if err != nil {
		return errors.Wrap(err, "error initializing vault")
	}

	for i, k := range resp.Keys {
		keyID := v.unsealKeyForID(i)
		err := v.keyStoreSet(keyID, []byte(k))

		if err != nil {
			return errors.Wrapf(err, "error storing unseal key '%s'", keyID)
		}

		logrus.WithField("key", keyID).Info("unseal key stored in key store")
	}

	for i, k := range resp.RecoveryKeys {
		keyID := v.recoveryKeyForID(i)
		err := v.keyStoreSet(keyID, []byte(k))

		if err != nil {
			return errors.Wrapf(err, "error storing recovery key '%s'", keyID)
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
			return errors.Wrapf(err, "unable to setup requested root token, (temporary root token: '%s')", resp.RootToken)
		}

		// revoke the temporary token
		err = v.cl.Auth().Token().RevokeSelf(resp.RootToken)
		if err != nil {
			return errors.Wrap(err, "unable to revoke temporary root token")
		}

		rootToken = v.config.InitRootToken
	}

	if v.config.StoreRootToken {
		rootTokenKey := v.rootTokenKey()
		if err = v.keyStoreSet(rootTokenKey, []byte(resp.RootToken)); err != nil {
			return errors.Wrapf(err, "error storing root token '%s' in key'%s'", rootToken, rootTokenKey)
		}
		logrus.WithField("key", rootTokenKey).Info("root token stored in key store")
	} else if v.config.InitRootToken == "" {
		logrus.WithField("root-token", resp.RootToken).Warnf("won't store root token in key store, this token grants full privileges to vault, so keep this secret")
	}

	return nil
}

// in our case Vault is initialized when root key is stored in the Cloud KMS
func (v *vault) RaftInitialized() (bool, error) {
	rootToken, err := v.keyStore.Get(v.rootTokenKey())
	if err != nil {
		if isNotFoundError(err) {
			return false, nil
		}

		return false, errors.Wrapf(err, "unable to get key '%s'", v.rootTokenKey())
	}

	if len(rootToken) > 0 {
		return true, nil
	}

	return false, nil
}

// RaftJoin joins Vault raft cluster if is not initialized already
func (v *vault) RaftJoin(leaderAPIAddr string) error {
	// raft storage mode
	if leaderAPIAddr != "" {
		initialized, err := v.cl.Sys().InitStatus()
		if err != nil {
			return errors.Wrap(err, "error testing if vault is initialized")
		}

		if initialized {
			logrus.Info("vault is already initialized, skipping raft join")
			return nil
		}
	} else if strings.HasSuffix(os.Getenv("POD_NAME"), "-0") {
		// raft ha_storage mode
		// TODO this currently doesn't allow multi-DC setups with Raft HA storage only mode
		return nil
	}

	request := api.RaftJoinRequest{
		LeaderAPIAddr: leaderAPIAddr,
	}

	raftCacertFile := os.Getenv("VAULT_RAFT_CACERT")
	if raftCacertFile == "" {
		raftCacertFile = os.Getenv(api.EnvVaultCACert)
	}

	if raftCacertFile != "" {
		leaderCACert, err := ioutil.ReadFile(raftCacertFile)
		if err != nil {
			return errors.Wrap(err, "error reading vault raft CA certificate")
		}

		request.LeaderCACert = string(leaderCACert)
	}

	response, err := v.cl.Sys().RaftJoin(&request)
	if err != nil {
		return errors.Wrap(err, "error joining raft cluster")
	}

	if response.Joined {
		logrus.Info("vault joined raft cluster")
		return nil
	}

	return errors.New("vault hasn't joined raft cluster") // nolint:goerr113
}

func (v *vault) Configure(config *viper.Viper) error {
	logrus.Debugf("retrieving key from kms service...")

	rootToken, err := v.keyStore.Get(v.rootTokenKey())
	if err != nil {
		return errors.Wrapf(err, "unable to get key '%s'", v.rootTokenKey())
	}

	v.cl.SetToken(string(rootToken))

	// Clear the token and GC it
	defer runtime.GC()
	defer v.cl.SetToken("")
	defer func() { rootToken = nil }()

	err = v.configureAuthMethods(config)
	if err != nil {
		return errors.Wrap(err, "error configuring auth methods for vault")
	}

	err = v.configurePolicies(config)
	if err != nil {
		return errors.Wrap(err, "error configuring policies for vault")
	}

	err = v.configurePlugins(config)
	if err != nil {
		return errors.Wrap(err, "error configuring plugins for vault")
	}

	err = v.configureSecretEngines(config)
	if err != nil {
		return errors.Wrap(err, "error configuring secret engines for vault")
	}

	err = v.configureAuditDevices(config)
	if err != nil {
		return errors.Wrap(err, "error configuring audit devices for vault")
	}

	err = v.configureStartupSecrets(config)
	if err != nil {
		return errors.Wrap(err, "error writing startup secrets to vault")
	}

	err = v.configureIdentityGroups(config)
	if err != nil {
		return errors.Wrap(err, "error writing groups configurations for vault")
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
	return "vault-root"
}

func (*vault) testKey() string {
	return "vault-test"
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
		return errors.Wrap(err, "error unmarshalling vault auth methods config")
	}

	if len(authMethods) == 0 {
		return nil
	}

	existingAuths, err := v.cl.Sys().ListAuth()
	if err != nil {
		return errors.Wrap(err, "error listing auth backends vault")
	}

	for _, authMethod := range authMethods {
		authMethodType, err := cast.ToStringE(authMethod["type"])
		if err != nil {
			return errors.Wrap(err, "error finding auth method type")
		}

		path := authMethodType
		if pathOverwrite, ok := authMethod["path"]; ok {
			path, err = cast.ToStringE(pathOverwrite)
			if err != nil {
				return errors.Wrap(err, "error converting path for auth method")
			}
			path = strings.Trim(path, "/")
		}

		description := fmt.Sprintf("%s backend", authMethodType)
		if descriptionOverwrite, ok := authMethod["description"]; ok {
			description, err = cast.ToStringE(descriptionOverwrite)
			if err != nil {
				return errors.Wrap(err, "error converting description for auth method")
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

		// get auth mount options
		// https://www.vaultproject.io/api/system/auth.html#config
		var authConfigInput api.AuthConfigInput
		var hasMountOptions bool
		if _, hasMountOptions = authMethod["options"]; hasMountOptions {
			err = mapstructure.Decode(authMethod["options"], &authConfigInput)
			if err != nil {
				return errors.Wrap(err, "error parsing auth method options")
			}
		}

		if !exists {
			logrus.Debugf("enabling %s auth backend in vault...", authMethodType)

			// https://www.vaultproject.io/api/system/auth.html
			var options api.EnableAuthOptions
			if hasMountOptions {
				options = api.EnableAuthOptions{
					Type:        authMethodType,
					Description: description,
					Config:      authConfigInput,
				}
			} else {
				options = api.EnableAuthOptions{
					Type:        authMethodType,
					Description: description,
				}
			}

			err := v.cl.Sys().EnableAuthWithOptions(path, &options)
			if err != nil {
				return errors.Wrapf(err, "error enabling %s auth method in vault", authMethodType)
			}
		} else if hasMountOptions {
			logrus.Debugf("tuning existing %s auth backend in vault...", path)
			// all auth methods are mounted below auth/
			tunePath := fmt.Sprintf("auth/%s", path)
			err = v.cl.Sys().TuneMount(tunePath, authConfigInput)
			if err != nil {
				return errors.Wrapf(err, "error tuning %s auth method in vault", path)
			}
		}

		// config data can have a child dict. But it will cause:
		// `json: unsupported type: map[interface {}]interface {}`
		// So check and replace by `map[string]interface{}` before using it.
		if config, ok := authMethod["config"]; ok {
			config, err := cast.ToStringMapE(config)
			if err != nil {
				return errors.Wrapf(err, "error type fixing config block for %s", authMethodType)
			}
			for k, v := range config {
				switch val := v.(type) {
				case map[interface{}]interface{}:
					config[k] = cast.ToStringMap(val)
				}
			}
			authMethod["config"] = config
		}

		switch authMethodType {
		case "kubernetes":
			config, err := getOrDefaultStringMap(authMethod, "config")
			if err != nil {
				return errors.Wrap(err, "error finding config block for kubernetes")
			}
			// If kubernetes_host is defined we are probably out of cluster, so don't read the default config
			if _, ok := config["kubernetes_host"]; !ok {
				defaultConfig, err := v.kubernetesAuthConfigDefault()
				if err != nil {
					return errors.Wrap(err, "error getting default kubernetes auth config for vault")
				}
				// merge the config blocks
				for k, v := range config {
					defaultConfig[k] = v
				}
				config = defaultConfig
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return errors.Wrap(err, "error configuring kubernetes auth for vault")
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return errors.Wrap(err, "error finding roles block for kubernetes")
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
			if err != nil {
				return errors.Wrap(err, "error configuring kubernetes auth roles for vault")
			}
		case "github":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return errors.Wrap(err, "error finding config block for github")
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return errors.Wrap(err, "error configuring github auth for vault")
			}
			mappings, err := cast.ToStringMapE(authMethod["map"])
			if err != nil {
				return errors.Wrap(err, "error finding map block for github")
			}
			err = v.configureGithubMappings(path, mappings)
			if err != nil {
				return errors.Wrap(err, "error configuring github mappings for vault")
			}
		case "aws":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return errors.Wrapf(err, "error finding config block for aws")
			}
			err = v.configureAwsConfig(path, config)
			if err != nil {
				return errors.Wrap(err, "error configuring aws auth for vault")
			}
			if crossaccountroleRaw, ok := authMethod["crossaccountrole"]; ok {
				crossaccountrole, err := cast.ToSliceE(crossaccountroleRaw)
				if err != nil {
					return errors.Wrap(err, "error finding crossaccountrole block for aws")
				}
				err = v.configureAWSCrossAccountRoles(path, crossaccountrole)
				if err != nil {
					return errors.Wrap(err, "error configuring aws auth cross account roles for vault")
				}
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return errors.Wrap(err, "error finding roles block for aws")
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
			if err != nil {
				return errors.Wrap(err, "error configuring aws auth roles for vault")
			}
		case "gcp", "oci":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return errors.Wrapf(err, "error finding config block for %s", authMethodType)
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return errors.Wrapf(err, "error configuring %s auth for vault", authMethodType)
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return errors.Wrapf(err, "error finding roles block for %s", authMethodType)
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
			if err != nil {
				return errors.Wrapf(err, "error configuring %s auth roles for vault", authMethodType)
			}
		case "approle":
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return errors.Wrap(err, "error finding role block for approle")
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
			if err != nil {
				return errors.Wrap(err, "error configuring approle auth for vault")
			}
		case "jwt", "oidc":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return errors.Wrapf(err, "error finding config block for %s", authMethodType)
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return errors.Wrapf(err, "error configuring %s auth on path %s for vault", authMethodType, path)
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return errors.Wrapf(err, "error finding roles block for %s", authMethodType)
			}
			err = v.configureJwtRoles(path, roles)
			if err != nil {
				return errors.Wrapf(err, "error configuring %s roles on path %s for vault", authMethodType, path)
			}
		case "token":
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return errors.Wrap(err, "error finding roles block for token")
			}
			err = v.configureGenericAuthRoles(authMethodType, "token", "roles", roles)
			if err != nil {
				return errors.Wrap(err, "error configuring token roles for vault")
			}
		case "cert":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return errors.Wrap(err, "error finding config block for cert")
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return errors.Wrap(err, "error configuring cert auth for vault")
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return errors.Wrap(err, "error finding roles block for certs")
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "certs", roles)
			if err != nil {
				return errors.Wrap(err, "error configuring certs auth roles for vault")
			}
		case "ldap", "okta":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return errors.Wrapf(err, "error finding config block for %s", authMethodType)
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return errors.Wrapf(err, "error configuring %s auth on path %s for vault", authMethodType, path)
			}
			for _, usersOrGroupsKey := range []string{"groups", "users"} {
				if userOrGroupRaw, ok := authMethod[usersOrGroupsKey]; ok {
					userOrGroup, err := cast.ToStringMapE(userOrGroupRaw)
					if err != nil {
						return errors.Wrapf(err, "error finding %s block for %s", usersOrGroupsKey, authMethodType)
					}
					err = v.configureGenericUserAndGroupMappings(authMethodType, path, usersOrGroupsKey, userOrGroup)
					if err != nil {
						return errors.Wrapf(err, "error configuring %s %s for vault", authMethodType, usersOrGroupsKey)
					}
				}
			}
		case "userpass":
			users, err := cast.ToSliceE(authMethod["users"])
			if err != nil {
				return errors.Wrapf(err, "error finding users block for %s", authMethodType)
			}
			err = v.configureUserpassUsers(path, users)
			if err != nil {
				return errors.Wrapf(err, "error configuring users for userpass in vault")
			}
		case "azure":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return errors.Wrap(err, "error finding config block for azure")
			}
			err = v.configureGenericAuthConfig(authMethodType, path, config)
			if err != nil {
				return errors.Wrap(err, "error configuring azure auth for vault")
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return errors.Wrap(err, "error finding roles block for azure")
			}
			err = v.configureGenericAuthRoles(authMethodType, path, "role", roles)
			if err != nil {
				return errors.Wrap(err, "error configuring azure auth roles for vault")
			}
		}
	}

	return nil
}

func (v *vault) configurePolicies(config *viper.Viper) error {
	policies := []map[string]string{}

	err := config.UnmarshalKey("policies", &policies)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling vault policy config")
	}

	for _, policy := range policies {
		policyName := policy["name"]

		// Try to format rules (HCL only)
		policyRules, err := hclPrinter.Format([]byte(policy["rules"]))
		if err != nil {
			// Check if rules parse (HCL or JSON)
			_, parseErr := hcl.Parse(policy["rules"])
			if parseErr != nil {
				return errors.Wrapf(err, "error parsing %s policy rules", policyName)
			}

			// Policies are parsable but couldn't be HCL formatted (most likely JSON)
			policyRules = []byte(policy["rules"])
			logrus.Debugf("error HCL-formatting %s policy rules (ignore if rules are JSON-formatted): %s", policyName, err.Error())
		}

		err = v.cl.Sys().PutPolicy(policyName, string(policyRules))
		if err != nil {
			return errors.Wrapf(err, "error putting %s policy into vault", policyName)
		}
	}

	return nil
}

func (v *vault) configureGithubMappings(path string, mappings map[string]interface{}) error {
	for mappingType, mapping := range mappings {
		mapping, err := cast.ToStringMapStringE(mapping)
		if err != nil {
			return errors.Wrap(err, "error converting mapping for github")
		}
		for userOrTeam, policy := range mapping {
			_, err := v.writeWithWarningCheck(fmt.Sprintf("auth/%s/map/%s/%s", path, mappingType, userOrTeam), map[string]interface{}{"value": policy})
			if err != nil {
				return errors.Wrapf(err, "error putting %s github mapping into vault", mappingType)
			}
		}
	}
	return nil
}

func (v *vault) configureAwsConfig(path string, config map[string]interface{}) error {
	// https://www.vaultproject.io/api/auth/aws/index.html
	_, err := v.writeWithWarningCheck(fmt.Sprintf("auth/%s/config/client", path), config)
	if err != nil {
		return errors.Wrap(err, "error putting aws config into vault")
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
			return errors.Wrapf(err, "error converting roles for %s", method)
		}

		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/%s/%s", path, roleSubPath, role["name"]), role)
		if err != nil {
			return errors.Wrapf(err, "error putting %s %s role into vault", role["name"], method)
		}
	}
	return nil
}

func (v *vault) configureUserpassUsers(path string, users []interface{}) error {
	for _, userRaw := range users {
		user, err := cast.ToStringMapE(userRaw)
		if err != nil {
			return errors.Wrapf(err, "error converting user for userpass")
		}

		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/%s/%s", path, "users", user["username"]), user)
		if err != nil {
			return errors.Wrapf(err, "error putting userpass %s user into vault", user["username"])
		}
	}
	return nil
}

func (v *vault) configureAWSCrossAccountRoles(path string, crossAccountRoles []interface{}) error {
	for _, roleInterface := range crossAccountRoles {
		crossAccountRole, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return errors.Wrap(err, "error converting cross account aws roles for aws")
		}

		stsAccount := fmt.Sprint(crossAccountRole["sts_account"])

		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/config/sts/%s", path, stsAccount), crossAccountRole)
		if err != nil {
			return errors.Wrapf(err, "error putting %s cross account aws role into vault", stsAccount)
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
	_, err := v.writeWithWarningCheck(fmt.Sprintf("auth/%s/config", path), config)
	if err != nil {
		return errors.Wrapf(err, "error putting %s auth config into vault", method)
	}
	return nil
}

// TODO try to generalize this with configureGenericAuthRoles() fix the type flaw
func (v *vault) configureJwtRoles(path string, roles []interface{}) error {
	for _, roleInterface := range roles {
		role, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return errors.Wrap(err, "error converting roles for jwt")
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

		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/role/%s", path, role["name"]), role)
		if err != nil {
			return errors.Wrapf(err, "error putting %s jwt role into vault", role["name"])
		}
	}
	return nil
}

func (v *vault) configureGenericUserAndGroupMappings(method, path string, mappingType string, mappings map[string]interface{}) error {
	for userOrGroup, policy := range mappings {
		mapping, err := cast.ToStringMapE(policy)
		if err != nil {
			return errors.Wrapf(err, "error converting mapping for %s", method)
		}
		_, err = v.writeWithWarningCheck(fmt.Sprintf("auth/%s/%s/%s", path, mappingType, userOrGroup), mapping)
		if err != nil {
			return errors.Wrapf(err, "error putting %s %s mapping into vault", method, mappingType)
		}
	}
	return nil
}

func (v *vault) configurePlugins(config *viper.Viper) error {
	plugins := []map[string]interface{}{}
	err := config.UnmarshalKey("plugins", &plugins)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling vault plugins config")
	}

	if len(plugins) == 0 {
		return nil
	}

	listPlugins, err := v.cl.Sys().ListPlugins(&api.ListPluginsInput{})
	if err != nil {
		return errors.Wrap(err, "failed to retrieve list of plugins")
	}

	logrus.Debugf("already registered plugins: %#v", listPlugins.PluginsByType)

	for _, plugin := range plugins {
		command, err := getOrError(plugin, "command")
		if err != nil {
			return errors.Wrap(err, "error getting command for plugin")
		}
		pluginName, err := getOrError(plugin, "plugin_name")
		if err != nil {
			return errors.Wrap(err, "error getting plugin_name for plugin")
		}
		sha256, err := getOrError(plugin, "sha256")
		if err != nil {
			return errors.Wrap(err, "error getting sha256 for plugin")
		}
		typeRaw, err := getOrError(plugin, "type")
		if err != nil {
			return errors.Wrap(err, "error getting type for plugin")
		}
		pluginType, err := consts.ParsePluginType(typeRaw)
		if err != nil {
			return errors.Wrap(err, "error parsing type for plugin")
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
			return errors.Wrapf(err, "error registering plugin %s in vault", pluginName)
		}

		logrus.Infoln("registered plugin", pluginName)
	}

	return nil
}

func (v *vault) mountExists(path string) (bool, error) {
	mounts, err := v.cl.Sys().ListMounts()
	if err != nil {
		return false, errors.Wrap(err, "error reading mounts from vault")
	}
	logrus.Infof("already existing mounts: %+v", mounts)
	return mounts[path+"/"] != nil, nil
}

func (v *vault) configureSecretEngines(config *viper.Viper) error {
	secretsEngines := []map[string]interface{}{}
	err := config.UnmarshalKey("secrets", &secretsEngines)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling vault secrets config")
	}

	for _, secretEngine := range secretsEngines {
		secretEngineType, err := cast.ToStringE(secretEngine["type"])
		if err != nil {
			return errors.Wrap(err, "error finding type for secret engine")
		}

		path := secretEngineType
		if pathOverwrite, ok := secretEngine["path"]; ok {
			path, err = cast.ToStringE(pathOverwrite)
			if err != nil {
				return errors.Wrap(err, "error converting path for secret engine")
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
				return errors.Wrap(err, "error getting description for secret engine")
			}
			pluginName, err := getOrDefaultString(secretEngine, "plugin_name")
			if err != nil {
				return errors.Wrap(err, "error getting plugin_name for secret engine")
			}
			local, err := getOrDefaultBool(secretEngine, "local")
			if err != nil {
				return errors.Wrap(err, "error getting local for secret engine")
			}
			sealWrap, err := getOrDefaultBool(secretEngine, "seal_wrap")
			if err != nil {
				return errors.Wrap(err, "error getting seal_wrap for secret engine")
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
				return errors.Wrapf(err, "error mounting %s into vault", path)
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
				return errors.Wrapf(err, "error tuning %s in vault", path)
			}
		}

		// Configuration of the Secret Engine in a very generic manner, YAML config file should have the proper format
		configuration, err := getOrDefaultStringMap(secretEngine, "configuration")
		if err != nil {
			return errors.Wrap(err, "error getting configuration for secret engine")
		}

		for configOption, configData := range configuration {
			configData, err := cast.ToSliceE(configData)
			if err != nil {
				return errors.Wrap(err, "error converting config data for secret engine")
			}
			for _, subConfigData := range configData {
				subConfigData, err := cast.ToStringMapE(subConfigData)
				if err != nil {
					return errors.Wrap(err, "error converting sub config data for secret engine")
				}

				name, ok := subConfigData["name"]
				if !ok && !configNeedsNoName(secretEngineType, configOption) {
					return errors.Errorf("error finding sub config data name for secret engine: %s/%s", path, configOption)
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

				// Control if the configs should be updated or just Created once and skipped later on
				// This is a workaround to secrets backend like GCP that will destroy and recreate secrets at every iteration
				createOnly := cast.ToBool(subConfigData["create_only"])
				// Delete the create_only key from the map, so we don't push it to vault
				delete(subConfigData, "create_only")

				rotate := cast.ToBool(subConfigData["rotate"])
				// Delete the rotate key from the map, so we don't push it to vault
				delete(subConfigData, "rotate")

				saveTo := cast.ToString(subConfigData["save_to"])
				// Delete the rotate key from the map, so we don't push it to vault
				delete(subConfigData, "save_to")

				var shouldUpdate = true
				if (createOnly || rotate) && mountExists {
					var sec interface{}
					if configOption == "root/generate" { // the pki generate call is a different beast
						req := v.cl.NewRequest("GET", fmt.Sprintf("/v1/%s/ca", path))
						resp, err := v.cl.RawRequestWithContext(context.Background(), req)
						if resp != nil {
							defer resp.Body.Close()
						}
						if err != nil {
							return errors.Wrapf(err, "failed to check pki CA")
						}
						if resp.StatusCode == http.StatusOK {
							sec = true
						}
					} else {
						sec, err = v.cl.Logical().Read(configPath)
						if err != nil {
							return errors.Wrapf(err, "error reading configPath %s", configPath)
						}
					}

					if sec != nil {
						reason := "rotate"
						if createOnly {
							reason = "create_only"
						}
						logrus.Infof("Secret at configpath %s already exists, %s was set so this will not be updated", configPath, reason)
						shouldUpdate = false
					}
				}

				if shouldUpdate {
					sec, err := v.writeWithWarningCheck(configPath, subConfigData)
					if err != nil {
						if isOverwriteProhibitedError(err) {
							logrus.Infoln("can't reconfigure", configPath, "please delete it manually")
							continue
						}
						return errors.Wrapf(err, "error configuring %s config in vault", configPath)
					}

					if saveTo != "" {
						_, err = v.writeWithWarningCheck(saveTo, vaultpkg.NewData(0, sec.Data))
						if err != nil {
							return errors.Wrapf(err, "error saving secret in vault to %s", saveTo)
						}
					}
				}

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
						return errors.Wrapf(err, "error rotating credentials for '%s' config in vault", configPath)
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
		return errors.Errorf("secret engine type '%s' doesn't support credential rotation", secretEngineType)
	}

	if _, ok := v.rotateCache[rotatePath]; !ok {
		logrus.Infoln("doing credential rotation at", rotatePath)

		_, err := v.writeWithWarningCheck(rotatePath, nil)
		if err != nil {
			return errors.Wrapf(err, "error rotating credentials for '%s' config in vault", configPath)
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
		return errors.Wrap(err, "error unmarshalling audit devices config")
	}

	for _, auditDevice := range auditDevices {
		auditDeviceType, err := cast.ToStringE(auditDevice["type"])
		if err != nil {
			return errors.Wrap(err, "error finding type for audit device")
		}

		path := auditDeviceType
		if pathOverwrite, ok := auditDevice["path"]; ok {
			path, err = cast.ToStringE(pathOverwrite)
			if err != nil {
				return errors.Wrap(err, "error converting path for audit device")
			}
			path = strings.Trim(path, "/")
		}

		mounts, err := v.cl.Sys().ListAudit()
		if err != nil {
			return errors.Wrap(err, "error reading audit mounts from vault")
		}

		logrus.Infof("already existing audit devices: %#v", mounts)

		if mounts[path+"/"] == nil {
			var options api.EnableAuditOptions
			err = mapstructure.Decode(auditDevice, &options)
			if err != nil {
				return errors.Wrap(err, "error parsing audit options")
			}
			logrus.Infof("enabling audit device with options: %#v", options)
			err = v.cl.Sys().EnableAuditWithOptions(path, &options)
			if err != nil {
				return errors.Wrapf(err, "error enabling audit device %s in vault", path)
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
		return errors.Wrapf(err, "error decoding data for startup secrets")
	}
	for _, startupSecret := range startupSecrets {
		startupSecretType, err := cast.ToStringE(startupSecret["type"])
		if err != nil {
			return errors.Wrap(err, "error finding type for startup secret")
		}

		switch startupSecretType {
		case "kv":
			path, data, err := readStartupSecret(startupSecret)
			if err != nil {
				return errors.Wrap(err, "unable to read 'kv' startup secret")
			}

			_, err = v.writeWithWarningCheck(path, data)
			if err != nil {
				return errors.Wrapf(err, "error writing data for startup 'kv' secret '%s'", path)
			}

		case "pki":
			path, data, err := readStartupSecret(startupSecret)
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

		default:
			return errors.Errorf("'%s' startup secret type is not supported, only 'kv' or 'pki'", startupSecretType)
		}
	}

	return nil
}

func (v *vault) writeWithWarningCheck(path string, data map[string]interface{}) (*api.Secret, error) {
	sec, err := v.cl.Logical().Write(path, data)
	if err != nil {
		return nil, err
	}
	if sec != nil {
		for _, warning := range sec.Warnings {
			logrus.Warn(warning)
		}
	}
	return sec, nil
}

func readStartupSecret(startupSecret map[string]interface{}) (string, map[string]interface{}, error) {
	path, err := cast.ToStringE(startupSecret["path"])
	if err != nil {
		return "", nil, errors.Wrap(err, "error findind path for startup secret")
	}

	data, err := getOrDefaultStringMap(startupSecret, "data")
	if err != nil {
		return "", nil, errors.Wrapf(err, "error getting data for startup secret '%s'", path)
	}

	if _, ok := data["secretKeyRef"]; ok {
		secData, err := getOrDefaultSecretData(data["secretKeyRef"])
		if err != nil {
			return "", nil, errors.Wrap(err, "error getting data from k8s secret")
		}
		data = secData
	}

	return path, data, nil
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

func readVaultGroup(group string, client *api.Client) (secret *api.Secret, err error) {
	secret, err = client.Logical().Read(fmt.Sprintf("identity/group/name/%s", group))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read group %s by name", group)
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
		return nil, errors.Wrapf(err, "failed to read group alias by id %s", id)
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
		return "", errors.Wrapf(err, "failed to read auth mounts from vault")
	}
	if mounts[path] == nil {
		return "", errors.Errorf("auth mount path %s does not exist in vault", path)
	}
	return mounts[path].Accessor, nil
}

func getVaultGroupID(group string, client *api.Client) (id string, err error) {
	g, err := readVaultGroup(group, client)
	if err != nil {
		return "", errors.Wrapf(err, "error reading group %s", group)
	}
	if g == nil {
		return "", errors.Errorf("group %s does not exist", group)
	}
	return g.Data["id"].(string), nil
}

func getVaultGroupAliasName(aliasID string, client *api.Client) (id string, err error) {
	alias, err := readVaultGroupAlias(aliasID, client)
	if err != nil {
		return "", errors.Wrapf(err, "error reading group alias %s", aliasID)
	}
	if alias == nil {
		return "", errors.Errorf("group alias %s does not exist", aliasID)
	}
	return alias.Data["name"].(string), nil
}

func getVaultGroupAliasMount(aliasID string, client *api.Client) (id string, err error) {
	alias, err := readVaultGroupAlias(aliasID, client)
	if err != nil {
		return "", errors.Wrapf(err, "error reading group alias %s", aliasID)
	}
	if alias == nil {
		return "", errors.Errorf("group alias %s does not exist", aliasID)
	}
	return alias.Data["mount_accessor"].(string), nil
}

func findVaultGroupAliasIDFromNameAndMount(name string, accessor string, client *api.Client) (id string, err error) {
	aliases, err := client.Logical().List("identity/group-alias/id")
	if err != nil {
		return "", errors.Wrap(err, "error listing group aliases")
	}
	if aliases == nil {
		return "", nil
	}

	for _, alias := range aliases.Data["keys"].([]interface{}) {
		aliasName, err := getVaultGroupAliasName(cast.ToString(alias), client)
		if err != nil {
			return "", errors.Wrapf(err, "error fetching name for alias id: %s err", alias)
		}

		aliasMount, err := getVaultGroupAliasMount(cast.ToString(alias), client)
		if err != nil {
			return "", errors.Wrapf(err, "error fetching mount for alias id: %s err", alias)
		}

		if aliasName == name && aliasMount == accessor {
			return cast.ToString(alias), nil
		}
	}

	// Did not find any alias matching Name and MountPath
	return "", nil
}

func (v *vault) configureIdentityGroups(config *viper.Viper) error {
	groups := []map[string]interface{}{}
	groupAliases := []map[string]interface{}{}

	err := config.UnmarshalKey("groups", &groups)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling vault groups config")
	}

	err = config.UnmarshalKey("group-aliases", &groupAliases)
	if err != nil {
		return errors.Wrap(err, "error unmarshalling vault group aliases config")
	}

	for _, group := range groups {
		g, err := readVaultGroup(cast.ToString(group["name"]), v.cl)
		if err != nil {
			return errors.Wrap(err, "error reading group")
		}

		// Currently does not support specifying members directly in the group config
		// Use group aliases for that
		if cast.ToString(group["type"]) != "external" {
			return errors.Errorf("only external groups are supported for now")
		}

		config := map[string]interface{}{
			"name":     cast.ToString(group["name"]),
			"type":     cast.ToString(group["type"]),
			"policies": cast.ToStringSlice(group["policies"]),
			"metadata": cast.ToStringMap(group["metadata"]),
		}

		if g == nil {
			logrus.Infof("creating group: %s", group["name"])
			_, err = v.writeWithWarningCheck("identity/group", config)
			if err != nil {
				return errors.Wrapf(err, "failed to create group %s", group["name"])
			}
		} else {
			logrus.Infof("tuning already existing group: %s", group["name"])
			_, err = v.writeWithWarningCheck(fmt.Sprintf("identity/group/name/%s", group["name"]), config)
			if err != nil {
				return errors.Wrapf(err, "failed to tune group %s", group["name"])
			}
		}
	}

	// Group Aliases for External Groups might require to have the same Name when on different Mount/Path combinations
	// external groups can only have ONE alias so we need to make sure not to overwrite any
	for _, groupAlias := range groupAliases {
		accessor, err := getVaultAuthMountAccessor(cast.ToString(groupAlias["mountpath"]), v.cl)
		if err != nil {
			return errors.Wrapf(err, "error getting mount accessor for %s", groupAlias["mountpath"])
		}

		id, err := getVaultGroupID(cast.ToString(groupAlias["group"]), v.cl)
		if err != nil {
			return errors.Wrapf(err, "error getting canonical_id for group %s", groupAlias["group"])
		}

		config := map[string]interface{}{
			"name":           cast.ToString(groupAlias["name"]),
			"mount_accessor": accessor,
			"canonical_id":   id,
		}

		// Find a matching alias for NAME and MOUNT
		ga, err := findVaultGroupAliasIDFromNameAndMount(cast.ToString(groupAlias["name"]), accessor, v.cl)
		if err != nil {
			return errors.Wrapf(err, "error finding group-alias %s", groupAlias["name"])
		}

		if ga == "" {
			logrus.Infof("creating group-alias: %s@%s", groupAlias["name"], accessor)
			_, err = v.writeWithWarningCheck("identity/group-alias", config)
			if err != nil {
				return errors.Wrapf(err, "failed to create group-alias %s", groupAlias["name"])
			}
		} else {
			logrus.Infof("tuning already existing group-alias: %s@%s - ID: %s", groupAlias["name"], accessor, ga)
			_, err = v.writeWithWarningCheck(fmt.Sprintf("identity/group-alias/id/%s", ga), config)
			if err != nil {
				return errors.Wrapf(err, "failed to tune group-alias %s", ga)
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
	return "", errors.Errorf("value for %s is not set", key)
}

func isOverwriteProhibitedError(err error) bool {
	return strings.Contains(err.Error(), "delete them before reconfiguring")
}

func getMountConfigInput(secretEngine map[string]interface{}) (api.MountConfigInput, error) {
	var mountConfigInput api.MountConfigInput
	config, ok := secretEngine["config"]
	if ok {
		if err := mapstructure.Decode(config, &mountConfigInput); err != nil {
			return mountConfigInput, errors.Wrap(err, "error parsing config for secret engine")
		}
	}

	// Bank-Vaults supported options outside config to be used options in the mount request
	// so for now, to preserve backward compatibility we overwrite the options inside config
	// with the options outside.
	options, err := getOrDefaultStringMapString(secretEngine, "options")
	if err != nil {
		return mountConfigInput, errors.Wrap(err, "error getting options for secret engine")
	}
	mountConfigInput.Options = options

	return mountConfigInput, nil
}

func configNeedsNoName(secretEngineType string, configOption string) bool {
	if configOption == "config" {
		_, ok := secretEnginesWihtoutNameConfig[secretEngineType]
		return ok
	}

	if secretEngineType == "aws" && configOption == "config/root" {
		return true
	}

	return false
}

func getOrDefaultSecretData(m interface{}) (map[string]interface{}, error) {
	values, err := cast.ToSliceE(m)
	if err != nil {
		return map[string]interface{}{}, err
	}

	k8sCfg := crconfig.GetConfigOrDie()
	c, err := crclient.New(k8sCfg, crclient.Options{})
	if err != nil {
		return map[string]interface{}{}, err
	}

	vaultNamespace := os.Getenv("NAMESPACE")

	secData := map[string]string{}
	for _, value := range values {
		keyRef, err := cast.ToStringMapStringE(value)
		if err != nil {
			return map[string]interface{}{}, err
		}

		secret := &corev1.Secret{}
		err = c.Get(context.Background(), crclient.ObjectKey{
			Namespace: vaultNamespace,
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
