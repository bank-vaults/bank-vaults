package vault

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

// DefaultConfigFile is the name of the default config file
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
	Init() error
	Sealed() (bool, error)
	Unseal() error
	Leader() (bool, error)
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

func (v *vault) Sealed() (bool, error) {
	resp, err := v.cl.Sys().SealStatus()
	if err != nil {
		return false, fmt.Errorf("error checking status: %s", err.Error())
	}
	return resp.Sealed, nil
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
	err = v.keyStore.Test(v.testKey())
	if err != nil {
		return fmt.Errorf("error testing keystore before init: %s", err.Error())
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
			return fmt.Errorf("error before init: keystore value for '%s' already exists", key)
		}
	}

	resp, err := v.cl.Sys().Init(&api.InitRequest{
		SecretShares:    v.config.SecretShares,
		SecretThreshold: v.config.SecretThreshold,
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

func (v *vault) Configure() error {
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

	existingAuths, err := v.cl.Sys().ListAuth()

	if err != nil {
		return fmt.Errorf("error listing auth backends vault: %s", err.Error())
	}

	authMethods := []map[string]interface{}{}
	err = viper.UnmarshalKey("auth", &authMethods)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault auth methods config: %s", err.Error())
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
			defaultConfig, err := v.kubernetesAuthConfigDefault()
			if err != nil {
				return fmt.Errorf("error getting default kubernetes auth config for vault: %s", err.Error())
			}
			// merge the config blocks
			for k, v := range config {
				defaultConfig[k] = v
			}
			config = defaultConfig
			err = v.kubernetesAuthConfig(path, config)
			if err != nil {
				return fmt.Errorf("error configuring kubernetes auth for vault: %s", err.Error())
			}
			roles := authMethod["roles"].([]interface{})
			err = v.configureKubernetesRoles(roles)
			if err != nil {
				return fmt.Errorf("error configuring kubernetes auth roles for vault: %s", err.Error())
			}
		case "github":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return fmt.Errorf("error finding config block for github: %s", err.Error())
			}
			err = v.configureGithubConfig(config)
			if err != nil {
				return fmt.Errorf("error configuring github auth for vault: %s", err.Error())
			}
			mappings, err := cast.ToStringMapE(authMethod["map"])
			if err != nil {
				return fmt.Errorf("error finding map block for github: %s", err.Error())
			}
			err = v.configureGithubMappings(mappings)
			if err != nil {
				return fmt.Errorf("error configuring github mappings for vault: %s", err.Error())
			}
		case "aws":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return fmt.Errorf("error finding config block for aws: %s", err.Error())
			}
			err = v.configureAwsConfig(config)
			if err != nil {
				return fmt.Errorf("error configuring aws auth for vault: %s", err.Error())
			}
			crossaccountrole, err := cast.ToSliceE(authMethod["crossaccountrole"])
			if err != nil {
				return nil
			}
			err = v.configureAWSCrossAccountRoles(crossaccountrole)
			if err != nil {
				return fmt.Errorf("error configuring aws auth cross account roles for vault: %s", err.Error())
			}
			roles, err := cast.ToSliceE(authMethod["roles"])
			if err != nil {
				return fmt.Errorf("error finding roles block for aws: %s", err.Error())
			}
			err = v.configureAwsRoles(roles)
			if err != nil {
				return fmt.Errorf("error configuring aws auth roles for vault: %s", err.Error())
			}
		case "ldap":
			config, err := cast.ToStringMapE(authMethod["config"])
			if err != nil {
				return fmt.Errorf("error finding config block for ldap: %s", err.Error())
			}
			err = v.configureLdapConfig(config)
			if err != nil {
				return fmt.Errorf("error configuring ldap auth for vault: %s", err.Error())
			}
			groups, err := cast.ToStringMapE(authMethod["groups"])
			if err != nil {
				return fmt.Errorf("error finding groups block for ldap: %s", err.Error())
			}

			err = v.configureLdapMappings("groups", groups)
			if err != nil {
				return fmt.Errorf("error configuring ldap groups for vault: %s", err.Error())
			}
			users, err := cast.ToStringMapE(authMethod["users"])
			if err != nil {
				return fmt.Errorf("error finding users block for ldap: %s", err.Error())
			}
			err = v.configureLdapMappings("users", users)
			if err != nil {
				return fmt.Errorf("error configuring ldap users for vault: %s", err.Error())
			}
		}
	}

	err = v.configurePolicies()
	if err != nil {
		return fmt.Errorf("error configuring policies for vault: %s", err.Error())
	}

	err = v.configureSecretEngines()
	if err != nil {
		return fmt.Errorf("error configuring secret engines for vault: %s", err.Error())
	}

	return err
}

func (*vault) unsealKeyForID(i int) string {
	return fmt.Sprint("vault-unseal-", i)
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

func (v *vault) kubernetesAuthConfig(path string, config map[string]interface{}) error {
	_, err := v.cl.Logical().Write(fmt.Sprintf("auth/%s/config", path), config)

	if err != nil {
		return fmt.Errorf("error putting %s kubernetes config into vault: %s", config, err.Error())
	}
	return nil
}

func (v *vault) configurePolicies() error {
	policies := []map[string]string{}
	err := viper.UnmarshalKey("policies", &policies)
	if err != nil {
		return fmt.Errorf("error unmarshalling vault policy config: %s", err.Error())
	}

	for _, policy := range policies {
		err := v.cl.Sys().PutPolicy(policy["name"], policy["rules"])

		if err != nil {
			return fmt.Errorf("error putting %s policy into vault: %s", policy["name"], err.Error())
		}
	}

	return nil
}

func (v *vault) configureKubernetesRoles(roles []interface{}) error {
	for _, roleInterface := range roles {
		role, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return fmt.Errorf("error converting role for kubernetes: %s", err.Error())
		}

		_, err = v.cl.Logical().Write(fmt.Sprint("auth/kubernetes/role/", role["name"]), role)

		if err != nil {
			return fmt.Errorf("error putting %s kubernetes role into vault: %s", role["name"], err.Error())
		}
	}
	return nil
}

func (v *vault) configureGithubConfig(config map[string]interface{}) error {
	// https://www.vaultproject.io/api/auth/github/index.html
	_, err := v.cl.Logical().Write("auth/github/config", config)

	if err != nil {
		return fmt.Errorf("error putting %s github config into vault: %s", config, err.Error())
	}
	return nil
}

func (v *vault) configureGithubMappings(mappings map[string]interface{}) error {
	for mappingType, mapping := range mappings {
		mapping, err := cast.ToStringMapStringE(mapping)
		if err != nil {
			return fmt.Errorf("error converting mapping for github: %s", err.Error())
		}
		for userOrTeam, policy := range mapping {
			_, err := v.cl.Logical().Write(fmt.Sprintf("auth/github/map/%s/%s", mappingType, userOrTeam), map[string]interface{}{"value": policy})
			if err != nil {
				return fmt.Errorf("error putting %s github mapping into vault: %s", mappingType, err.Error())
			}
		}
	}
	return nil
}

func (v *vault) configureAwsConfig(config map[string]interface{}) error {
	// https://www.vaultproject.io/api/auth/aws/index.html
	_, err := v.cl.Logical().Write("auth/aws/config/client", config)

	if err != nil {
		return fmt.Errorf("error putting %s aws config into vault: %s", config, err.Error())
	}
	return nil
}

func (v *vault) configureAwsRoles(roles []interface{}) error {
	for _, roleInterface := range roles {
		role, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return fmt.Errorf("error converting roles for aws: %s", err.Error())
		}
		_, err = v.cl.Logical().Write(fmt.Sprint("auth/aws/role/", role["name"]), role)

		if err != nil {
			return fmt.Errorf("error putting %s aws role into vault: %s", role["name"], err.Error())
		}
	}
	return nil
}

func (v *vault) configureAWSCrossAccountRoles(crossAccountRoles []interface{}) error {
	for _, roleInterface := range crossAccountRoles {
		crossAccountRole, err := cast.ToStringMapE(roleInterface)
		if err != nil {
			return fmt.Errorf("error converting cross account aws roles for aws: %s", err.Error())
		}
		_, err = v.cl.Logical().Write(fmt.Sprint("auth/aws/config/sts/", crossAccountRole["sts_account"]), crossAccountRole)

		if err != nil {
			return fmt.Errorf("error putting %s cross account aws role into vault: %s", crossAccountRole["sts_account"], err.Error())
		}
	}
	return nil
}

func (v *vault) configureLdapConfig(config map[string]interface{}) error {
	// https://www.vaultproject.io/api/auth/ldap/index.html
	_, err := v.cl.Logical().Write("auth/ldap/config", config)

	if err != nil {
		return fmt.Errorf("error putting %s ldap config into vault: %s", config, err.Error())
	}
	return nil
}

func (v *vault) configureLdapMappings(mappingType string, mappings map[string]interface{}) error {
	for userOrGroup, policy := range mappings {
		mapping, err := cast.ToStringMapE(policy)
		if err != nil {
			return fmt.Errorf("error converting mapping for ldap: %s", err.Error())
		}
		_, err = v.cl.Logical().Write(fmt.Sprintf("auth/ldap/%s/%s", mappingType, userOrGroup), mapping)
		if err != nil {
			return fmt.Errorf("error putting %s ldap mapping into vault: %s", mappingType, err.Error())
		}
	}
	return nil
}

func (v *vault) configureSecretEngines() error {
	secretsEngines := []map[string]interface{}{}
	err := viper.UnmarshalKey("secrets", &secretsEngines)
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
		}

		mounts, err := v.cl.Sys().ListMounts()
		if err != nil {
			return fmt.Errorf("error reading mounts from vault: %s", err.Error())
		}
		logrus.Debugf("Already existing mounts: %#v\n", mounts)
		if mounts[path+"/"] == nil {
			description, err := getOrDefault(secretEngine, "description")
			if err != nil {
				return fmt.Errorf("error getting description for secret engine: %s", err.Error())
			}
			pluginName, err := getOrDefault(secretEngine, "plugin_name")
			if err != nil {
				return fmt.Errorf("error getting plugin_name for secret engine: %s", err.Error())
			}
			options, err := getOrDefaultStringMapString(secretEngine, "options")
			if err != nil {
				return fmt.Errorf("error getting options for secret engine: %s", err.Error())
			}
			input := api.MountInput{
				Type:        secretEngineType,
				Description: description,
				PluginName:  pluginName,
				Options:     options,
			}
			logrus.Infof("Mounting secret engine with input: %#v\n", input)
			err = v.cl.Sys().Mount(path, &input)
			if err != nil {
				return fmt.Errorf("error mounting %s into vault: %s", path, err.Error())
			}

			logrus.Infoln("mounted", secretEngineType, "to", path)

		} else {
			options, err := getOrDefaultStringMapString(secretEngine, "options")
			if err != nil {
				return fmt.Errorf("error getting options for secret engine: %s", err.Error())
			}
			input := api.MountConfigInput{
				Options: options,
			}
			err = v.cl.Sys().TuneMount(path, input)
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
				if !ok {
					return fmt.Errorf("error finding sub config data name for secret engine")
				}
				configPath := fmt.Sprintf("%s/%s/%s", path, configOption, name)
				_, err = v.cl.Logical().Write(configPath, subConfigData)

				if err != nil {
					if isOverwriteProhibitedError(err) {
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

func getOrDefault(m map[string]interface{}, key string) (string, error) {
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

func isOverwriteProhibitedError(err error) bool {
	return strings.Contains(err.Error(), "delete them before reconfiguring")
}
