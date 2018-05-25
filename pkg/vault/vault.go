package vault

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

const DefaultConfigFile = "vault-config.yml"

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
}

// vault is an implementation of the Vault interface that will perform actions
// against a Vault server, using a provided KMS to retrieve
type vault struct {
	keyStore kv.Service
	cl       *api.Client
	config   *Config
}

// Interface check
var _ Vault = &vault{}

// Vault is an interface that can be used to attempt to perform actions against
// a Vault server.
type Vault interface {
	Sealed() (bool, error)
	Unseal() error
	Init() error
	Configure() error
}

// New returns a new vault Vault, or an error.
func New(k kv.Service, cl *api.Client, config Config) (Vault, error) {

	if config.SecretShares < config.SecretThreshold {
		return nil, errors.New("the secret threshold can't be bigger than the shares")
	}

	return &vault{
		keyStore: k,
		cl:       cl,
		config:   &config,
	}, nil
}

func (u *vault) Sealed() (bool, error) {
	resp, err := u.cl.Sys().SealStatus()
	if err != nil {
		return false, fmt.Errorf("error checking status: %s", err.Error())
	}
	return resp.Sealed, nil
}

// Unseal will attempt to unseal vault by retrieving keys from the kms service
// and sending unseal requests to vault. It will return an error if retrieving
// a key fails, or if the unseal progress is reset to 0 (indicating that a key)
// was invalid.
func (u *vault) Unseal() error {
	for i := 0; ; i++ {
		keyID := u.unsealKeyForID(i)

		logrus.Debugf("retrieving key from kms service...")
		k, err := u.keyStore.Get(keyID)

		if err != nil {
			return fmt.Errorf("unable to get key '%s': %s", keyID, err.Error())
		}

		logrus.Debugf("sending unseal request to vault...")
		resp, err := u.cl.Sys().Unseal(string(k))

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

func (u *vault) keyStoreNotFound(key string) (bool, error) {
	_, err := u.keyStore.Get(key)
	if _, ok := err.(*kv.NotFoundError); ok {
		return true, nil
	}
	return false, err
}

func (u *vault) keyStoreSet(key string, val []byte) error {
	notFound, err := u.keyStoreNotFound(key)
	if notFound {
		return u.keyStore.Set(key, val)
	} else if err == nil {
		return fmt.Errorf("error setting key '%s': it already exists", key)
	} else {
		return fmt.Errorf("error setting key '%s': %s", key, err.Error())
	}
}

// Init initializes Vault if is not initialized already
func (u *vault) Init() error {
	initialized, err := u.cl.Sys().InitStatus()
	if err != nil {
		return fmt.Errorf("error testing if vault is initialized: %s", err.Error())
	}
	if initialized {
		logrus.Info("vault is already initialized")
		return nil
	}

	// test backend first
	err = u.keyStore.Test(u.testKey())
	if err != nil {
		return fmt.Errorf("error testing keystore before init: %s", err.Error())
	}

	// test for an existing keys
	keys := []string{
		u.rootTokenKey(),
	}

	// add unseal keys
	for i := 0; i <= u.config.SecretShares; i++ {
		keys = append(keys, u.unsealKeyForID(i))
	}

	// test every key
	for _, key := range keys {
		notFound, err := u.keyStoreNotFound(key)
		if notFound && err != nil {
			return fmt.Errorf("error before init: checking key '%s' failed: %s", key, err.Error())
		} else if !notFound && err == nil {
			return fmt.Errorf("error before init: keystore value for '%s' already exists", key)
		}
	}

	resp, err := u.cl.Sys().Init(&api.InitRequest{
		SecretShares:    u.config.SecretShares,
		SecretThreshold: u.config.SecretThreshold,
	})

	if err != nil {
		return fmt.Errorf("error initialising vault: %s", err.Error())
	}

	for i, k := range resp.Keys {
		keyID := u.unsealKeyForID(i)
		err := u.keyStoreSet(keyID, []byte(k))

		if err != nil {
			return fmt.Errorf("error storing unseal key '%s': %s", keyID, err.Error())
		}
	}

	rootToken := resp.RootToken

	// this sets up a predefined root token
	if u.config.InitRootToken != "" {
		logrus.Info("setting up init root token, waiting for vault to be unsealed")

		count := 0
		wait := time.Second * 2
		for {
			sealed, err := u.Sealed()
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
		u.cl.SetToken(resp.RootToken)

		// setup root token with provided key
		_, err := u.cl.Auth().Token().CreateOrphan(&api.TokenCreateRequest{
			ID:          u.config.InitRootToken,
			Policies:    []string{"root"},
			DisplayName: "root-token",
			NoParent:    true,
		})
		if err != nil {
			return fmt.Errorf("unable to setup requested root token, (temporary root token: '%s'): %s", resp.RootToken, err)
		}

		// revoke the temporary token
		err = u.cl.Auth().Token().RevokeSelf(resp.RootToken)
		if err != nil {
			return fmt.Errorf("unable to revoke temporary root token: %s", err.Error())
		}

		rootToken = u.config.InitRootToken
	}

	if u.config.StoreRootToken {
		rootTokenKey := u.rootTokenKey()
		if err = u.keyStoreSet(rootTokenKey, []byte(resp.RootToken)); err != nil {
			return fmt.Errorf("error storing root token '%s' in key'%s'", rootToken, rootTokenKey)
		}
		logrus.WithField("key", rootTokenKey).Info("root token stored in key store")
	} else if u.config.InitRootToken == "" {
		logrus.WithField("root-token", resp.RootToken).Warnf("won't store root token in key store, this token grants full privileges to vault, so keep this secret")
	}

	return nil
}

func (u *vault) Configure() error {
	logrus.Debugf("retrieving key from kms service...")
	rootToken, err := u.keyStore.Get(u.rootTokenKey())

	if err != nil {
		return fmt.Errorf("unable to get key '%s': %s", u.rootTokenKey(), err.Error())
	}

	u.cl.SetToken(string(rootToken))
	defer u.cl.SetToken("")

	existingAuths, err := u.cl.Sys().ListAuth()

	if err != nil {
		return fmt.Errorf("error listing auth backends vault: %s", err.Error())
	}

	authMethods := []map[string]interface{}{}
	err = viper.UnmarshalKey("auth", &authMethods)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault auth methods config: %s", err.Error())
	}
	for _, authMethod := range authMethods {
		authMethodType := authMethod["type"].(string)

		path := authMethodType
		if pathOverwrite, ok := authMethod["path"]; ok {
			path = pathOverwrite.(string)
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
				Type: authMethodType,
			}

			err := u.cl.Sys().EnableAuthWithOptions(path, &options)

			if err != nil {
				return fmt.Errorf("error enabling %s auth method for vault: %s", authMethodType, err.Error())
			}
		}

		switch authMethodType {
		case "kubernetes":
			err = u.kubernetesAuthConfig(path)
			if err != nil {
				return fmt.Errorf("error configuring kubernetes auth for vault: %s", err.Error())
			}
			roles := authMethod["roles"].([]interface{})
			err = u.configureKubernetesRoles(roles)
			if err != nil {
				return fmt.Errorf("error configuring kubernetes auth roles for vault: %s", err.Error())
			}
		case "github":
			config := cast.ToStringMap(authMethod["config"])
			err = u.configureGithubConfig(config)
			if err != nil {
				return fmt.Errorf("error configuring github auth for vault: %s", err.Error())
			}
			mappings := cast.ToStringMap(authMethod["map"])
			err = u.configureGithubMappings(mappings)
			if err != nil {
				return fmt.Errorf("error configuring github mappings for vault: %s", err.Error())
			}
		case "aws":
			config := cast.ToStringMap(authMethod["config"])
			err = u.configureAwsConfig(config)
			if err != nil {
				return fmt.Errorf("error configuring aws auth for vault: %s", err.Error())
			}
			roles := authMethod["roles"].([]interface{})
			err = u.configureAwsRoles(roles)
			if err != nil {
				return fmt.Errorf("error configuring aws auth roles for vault: %s", err.Error())
			}
		}
	}

	err = u.configurePolicies()
	if err != nil {
		return fmt.Errorf("error configuring policies for vault: %s", err.Error())
	}

	err = u.configureSecretEngines()
	if err != nil {
		return fmt.Errorf("error configuring secret engines for vault: %s", err.Error())
	}

	return err
}

func (u *vault) unsealKeyForID(i int) string {
	return fmt.Sprint("vault-unseal-", i)
}

func (u *vault) rootTokenKey() string {
	return fmt.Sprint("vault-root")
}

func (u *vault) testKey() string {
	return fmt.Sprint("vault-test")
}

func (u *vault) kubernetesAuthConfig(path string) error {
	kubernetesCACert, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return err
	}
	tokenReviewerJWT, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return err
	}
	config := map[string]interface{}{
		"kubernetes_host":    fmt.Sprint("https://", os.Getenv("KUBERNETES_SERVICE_HOST")),
		"kubernetes_ca_cert": string(kubernetesCACert),
		"token_reviewer_jwt": string(tokenReviewerJWT),
	}
	_, err = u.cl.Logical().Write(fmt.Sprintf("auth/%s/config", path), config)
	return err
}

func (u *vault) configurePolicies() error {
	policies := []map[string]string{}
	err := viper.UnmarshalKey("policies", &policies)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault policy config: %s", err.Error())
	}

	for _, policy := range policies {
		err := u.cl.Sys().PutPolicy(policy["name"], policy["rules"])

		if err != nil {
			return fmt.Errorf("error putting %s policy into vault: %s", policy["name"], err.Error())
		}
	}

	return nil
}

func (u *vault) configureKubernetesRoles(roles []interface{}) error {
	for _, roleInterface := range roles {
		role := cast.ToStringMap(roleInterface)
		_, err := u.cl.Logical().Write(fmt.Sprint("auth/kubernetes/role/", role["name"]), role)

		if err != nil {
			return fmt.Errorf("error putting %s kubernetes role into vault: %s", role["name"], err.Error())
		}
	}
	return nil
}

func (u *vault) configureGithubConfig(config map[string]interface{}) error {
	// https://www.vaultproject.io/api/auth/github/index.html
	_, err := u.cl.Logical().Write("auth/github/config", config)

	if err != nil {
		return fmt.Errorf("error putting %s github config into vault: %s", config, err.Error())
	}
	return nil
}

func (u *vault) configureGithubMappings(mappings map[string]interface{}) error {
	for mappingType, mapping := range mappings {
		for userOrTeam, policy := range cast.ToStringMapString(mapping) {
			_, err := u.cl.Logical().Write(fmt.Sprintf("auth/github/map/%s/%s", mappingType, userOrTeam), map[string]interface{}{"value": policy})
			if err != nil {
				return fmt.Errorf("error putting %s github mapping into vault: %s", mappingType, err.Error())
			}
		}
	}
	return nil
}

func (u *vault) configureAwsConfig(config map[string]interface{}) error {
	// https://www.vaultproject.io/api/auth/aws/index.html
	_, err := u.cl.Logical().Write("auth/aws/config/client", config)

	if err != nil {
		return fmt.Errorf("error putting %s aws config into vault: %s", config, err.Error())
	}
	return nil
}

func (u *vault) configureAwsRoles(roles []interface{}) error {
	for _, roleInterface := range roles {
		role := cast.ToStringMap(roleInterface)
		_, err := u.cl.Logical().Write(fmt.Sprint("auth/aws/role/", role["name"]), role)

		if err != nil {
			return fmt.Errorf("error putting %s aws role into vault: %s", role["name"], err.Error())
		}
	}
	return nil
}

func (u *vault) configureSecretEngines() error {
	secretsEngines := []map[string]interface{}{}
	err := viper.UnmarshalKey("secrets", &secretsEngines)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault secrets config: %s", err.Error())
	}

	mounts, err := u.cl.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("error reading mounts from vault: %s", err.Error())
	}

	// Remove the default secret/ engine, until it is removed by default
	// From https://github.com/hashicorp/vault/blob/master/CHANGELOG.md#0100-april-10th-2018
	// > Removal of default secret/ mount: In 0.12 we will stop mounting secret/ by default at initialization time (it will still be available in dev mode).
	defaultSecret := mounts["secret/"]
	if defaultSecret != nil && defaultSecret.Options["version"] == "2" {
		secret, err := u.cl.Logical().List("secret")
		if err != nil {
			return fmt.Errorf("error listing keys in defaultSecret from vault: %s", err.Error())
		}
		if len(secret.Data) == 0 {
			err = u.cl.Sys().Unmount("secret")
			if err != nil {
				return fmt.Errorf("error unmounting defaultSecret from vault: %s", err.Error())
			}
		}
	}

	for _, secrentEngine := range secretsEngines {
		secretEngineType := secrentEngine["type"].(string)

		path := secretEngineType
		if pathOverwrite, ok := secrentEngine["path"]; ok {
			path = pathOverwrite.(string)
		}

		mounts, err := u.cl.Sys().ListMounts()
		if err != nil {
			return fmt.Errorf("error reading mounts from vault: %s", err.Error())
		}
		if mounts[path+"/"] == nil {
			input := api.MountInput{
				Type:        secretEngineType,
				Description: getOrDefault(secrentEngine, "description"),
				PluginName:  getOrDefault(secrentEngine, "plugin_name"),
				Options:     getOrDefaultStringMapString(secrentEngine, "options"),
			}
			err = u.cl.Sys().Mount(path, &input)
			if err != nil {
				return fmt.Errorf("error mounting %s into vault: %s", path, err.Error())
			}

			logrus.Debugln("mounted", secretEngineType, "to", path)

		} else {
			// input := api.MountConfigInput{}
			// err = u.cl.Sys().TuneMount(path, input)
		}

		// Configuration of the Secret Engine in a very generic manner, YAML config file should have the proper format
		configuration := getOrDefaultStringMap(secrentEngine, "configuration")
		for configOption, configData := range configuration {
			configData := configData.([]interface{})
			for _, subConfigData := range configData {
				subConfigData := subConfigData.(map[interface{}]interface{})
				configPath := fmt.Sprintf("%s/%s/%s", path, configOption, subConfigData["name"])
				_, err := u.cl.Logical().Write(configPath, cast.ToStringMap(subConfigData))

				if err != nil {
					if isOverwriteProbihitedError(err) {
						logrus.Debugln("Can't reconfigure", configPath, "please delete it manually")
						continue
					}
					return fmt.Errorf("error putting %+v -> %s config into vault: %s", configData, configPath, err.Error())
				}
			}
		}
	}

	return nil
}

func getOrDefault(m map[string]interface{}, key string) string {
	value := m[key]
	if value != nil {
		return value.(string)
	}
	return ""
}

func getOrDefaultStringMapString(m map[string]interface{}, key string) map[string]string {
	value := m[key]
	stringMap := map[string]string{}
	if value != nil {
		return cast.ToStringMapString(value)
	}
	return stringMap
}

func getOrDefaultStringMap(m map[string]interface{}, key string) map[string]interface{} {
	value := m[key]
	stringMap := map[string]interface{}{}
	if value != nil {
		return cast.ToStringMap(value)
	}
	return stringMap
}

func isOverwriteProbihitedError(err error) bool {
	return strings.Contains(err.Error(), "delete them before reconfiguring")
}
