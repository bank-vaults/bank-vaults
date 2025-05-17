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
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"emperror.dev/errors"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

const (
	// DefaultConfigFile is the name of the default config file
	DefaultConfigFile = "vault-config.yml"

	keyRootToken = "vault-root"
	keyTestField = "vault-test"
)

// Vault is an interface that can be used to attempt to perform actions against
// a Vault server.
type Vault interface {
	Init() error
	RaftInitialized() (bool, error)
	RaftJoin(leaderAddress string) error
	Sealed() (bool, error)
	Active() (bool, error)
	Unseal() error
	Leader() (bool, error)
	LeaderAddress() (string, error)
	Configure(config map[string]interface{}) error
}

type KVService interface {
	Set(key string, value []byte) error
	Get(key string) ([]byte, error)
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

type purgeUnmanagedConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Exclude struct {
		Audit        bool `mapstructure:"audit"`
		Auth         bool `mapstructure:"auth"`
		Groups       bool `mapstructure:"groups"`
		GroupAliases bool `mapstructure:"group-aliases"`
		Plugins      bool `mapstructure:"plugins"`
		Policies     bool `mapstructure:"policies"`
		Secrets      bool `mapstructure:"secrets"`
	} `mapstructure:"exclude"`
}

type externalConfig struct {
	PurgeUnmanagedConfig purgeUnmanagedConfig `mapstructure:"purgeUnmanagedConfig"`
	Audit                []audit              `mapstructure:"audit"`
	Auth                 []auth               `mapstructure:"auth"`
	Groups               []group              `mapstructure:"groups"`
	GroupAliases         []groupAlias         `mapstructure:"group-aliases"`
	Plugins              []plugin             `mapstructure:"plugins"`
	Policies             []policy             `mapstructure:"policies"`
	Secrets              []secretEngine       `mapstructure:"secrets"`
	StartupSecrets       []startupSecret      `mapstructure:"startupSecrets"`
}

type kvTester struct {
	Service KVService
}

func (t kvTester) Test(key string) error {
	_, err := t.Service.Get(key)
	if err != nil {
		if !isNotFoundError(err) {
			return err //nolint:wrapcheck
		}
	}

	return t.Service.Set(key, []byte(key))
}

var _ Vault = &vault{}

// vault is an implementation of the Vault interface that will perform actions
// against a Vault server, using a provided KMS to retrieve
type vault struct {
	keyStore       KVService
	cl             *api.Client
	config         *Config
	externalConfig *externalConfig
	rotateCache    map[string]bool
}

// New returns a new vault Vault, or an error.
func New(k KVService, cl *api.Client, config Config) (Vault, error) {
	if config.SecretShares < config.SecretThreshold {
		return nil, errors.Errorf("the secret threshold can't be bigger than the shares [%d < %d]", config.SecretShares, config.SecretThreshold)
	}

	return &vault{
		keyStore:       k,
		cl:             cl,
		config:         &config,
		rotateCache:    map[string]bool{},
		externalConfig: &externalConfig{},
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
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	resp, err := v.cl.Logical().ReadRawWithContext(ctx, "sys/health")
	if err != nil {
		return false, errors.Wrap(err, "error checking status")
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error(fmt.Sprintf("error closing response body: %s", err.Error()))
		}
	}()

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

func (v *vault) LeaderAddress() (string, error) {
	resp, err := v.cl.Sys().Leader()
	if err != nil {
		return "", errors.Wrap(err, "error checking leader address")
	}

	return resp.LeaderAddress, nil
}

// Unseal will attempt to unseal vault by retrieving keys from the kms service
// and sending unseal requests to vault. It will return an error if retrieving
// a key fails, or if the unseal progress is reset to 0 (indicating that a key)
// was invalid.
func (v *vault) Unseal() error {
	defer runtime.GC()
	for i := 0; ; i++ {
		slog.Debug("retrieving key from kms service...")
		k, err := v.keyStore.Get(keyUnsealForID(i))
		if err != nil {
			return errors.Wrapf(err, "unable to get key '%s'", keyUnsealForID(i))
		}

		slog.Debug("sending unseal request to vault...")
		resp, err := v.cl.Sys().Unseal(string(k))
		if err != nil {
			return errors.Wrap(err, "fail to send unseal request to vault")
		}
		slog.Debug(fmt.Sprintf("got unseal response: %+v", *resp))

		if !resp.Sealed {
			return nil
		}

		// if progress is 0, we failed to unseal vault.
		if resp.Progress == 0 {
			return errors.New("failed to unseal vault, are you using the right unseal keys?")
		}
	}
}

func (v *vault) keyStoreNotFound(key string) (bool, error) {
	_, err := v.keyStore.Get(key)
	if isNotFoundError(err) {
		return true, nil
	}

	return false, err //nolint:wrapcheck
}

func (v *vault) keyStoreSet(key string, val []byte) error {
	notFound, err := v.keyStoreNotFound(key)
	if notFound {
		return v.keyStore.Set(key, val)
	}
	if err == nil {
		return errors.Errorf("error setting key '%s': it already exists", key)
	}

	return errors.Wrapf(err, "error setting key '%s'", key)
}

// Init initializes Vault if is not initialized already
func (v *vault) Init() error {
	initialized, err := v.cl.Sys().InitStatus()
	if err != nil {
		return errors.Wrap(err, "error testing if vault is initialized")
	}
	if initialized {
		slog.Info("vault is already initialized")

		return nil
	}
	slog.Info("initializing vault")

	// test backend first
	if v.config.PreFlightChecks {
		tester := kvTester{Service: v.keyStore}
		err = tester.Test(keyTestField)
		if err != nil {
			return errors.Wrap(err, "error testing keystore before init")
		}
	}

	// test for an existing keys
	keys := []string{
		keyRootToken,
	}

	// add unseal keys
	for i := 0; i <= v.config.SecretShares; i++ {
		keys = append(keys, keyUnsealForID(i))
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

	sealResp, err := v.cl.Sys().SealStatus()
	if err != nil {
		return errors.Wrap(err, "error getting seal status")
	}

	initRequest := api.InitRequest{}
	switch sealResp.RecoverySeal {
	case true:
		initRequest.RecoveryShares = v.config.SecretShares
		initRequest.RecoveryThreshold = v.config.SecretThreshold
	default:
		initRequest.SecretShares = v.config.SecretShares
		initRequest.SecretThreshold = v.config.SecretThreshold
	}

	resp, err := v.cl.Sys().Init(&initRequest)
	if err != nil {
		return errors.Wrap(err, "error initializing vault")
	}

	for i, k := range resp.Keys {
		err := v.keyStoreSet(keyUnsealForID(i), []byte(k))
		if err != nil {
			return errors.Wrapf(err, "error storing unseal key '%s'", keyUnsealForID(i))
		}
		slog.With(slog.String("key", keyUnsealForID(i))).Info("unseal key stored in key store")
	}

	for i, k := range resp.RecoveryKeys {
		err := v.keyStoreSet(keyRecoveryForID(i), []byte(k))
		if err != nil {
			return errors.Wrapf(err, "error storing recovery key '%s'", keyRecoveryForID(i))
		}
		slog.With(slog.String("key", keyRecoveryForID(i))).Info("recovery key stored in key store")
	}

	// this sets up a predefined root token
	rootToken := resp.RootToken
	if v.config.InitRootToken != "" {
		slog.Info("setting up init root token, waiting for vault to be unsealed")

		for {
			sealed, err := v.Sealed()
			if !sealed {
				break
			}
			if err == nil {
				slog.Info("vault still sealed, wait for unsealing")
			} else {
				slog.Info(fmt.Sprintf("vault not reachable: %s", err.Error()))
			}
			time.Sleep(time.Second * 2)
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
		if err = v.keyStoreSet(keyRootToken, []byte(resp.RootToken)); err != nil {
			return errors.Wrapf(err, "error storing root token '%s' in key'%s'", rootToken, keyRootToken)
		}
		slog.With(slog.String("key", keyRootToken)).Info("root token stored in key store")
	} else if v.config.InitRootToken == "" {
		slog.With(slog.String("root-token", resp.RootToken)).Warn("won't store root token in key store, this token grants full privileges to vault, so keep this secret")
	}

	return nil
}

// RaftInitialized in our case Vault is initialized when root key is stored in the Cloud KMS
func (v *vault) RaftInitialized() (bool, error) {
	// backward compatibility, use root token exsitence to determine if Vault is initialized
	if v.config.StoreRootToken {
		rootToken, err := v.keyStore.Get(keyRootToken)
		if err != nil {
			if isNotFoundError(err) {
				return false, nil
			}

			return false, errors.Wrapf(err, "unable to get key '%s'", keyRootToken)
		}

		if len(rootToken) > 0 {
			return true, nil
		}
	}
	// If root token is not stored in the key store (a valid option), use leader address to determine if Vault is already initialized
	leaderAPIAddr, err := v.LeaderAddress()
	if err != nil {
		return false, errors.Wrap(err, "error getting leader address")
	}
	// raft storage mode
	if leaderAPIAddr != "" {
		initialized, err := v.cl.Sys().InitStatus()
		if err != nil {
			return false, errors.Wrap(err, "error testing if vault is initialized")
		}

		if initialized {
			slog.Info("vault is already initialized, skipping raft join")

			return true, nil
		}
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
			slog.Info("vault is already initialized, skipping raft join")

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
		leaderCACert, err := os.ReadFile(raftCacertFile)
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
		slog.Info("vault joined raft cluster")

		return nil
	}

	return errors.New("vault hasn't joined raft cluster")
}

func (v *vault) Configure(config map[string]interface{}) error {
	var rootToken []byte

	slog.Debug("retrieving key from kms service...")

	if v.config.StoreRootToken {
		rootToken, err := v.keyStore.Get(keyRootToken)
		if err != nil {
			return errors.Wrapf(err, "unable to get key '%s'", keyRootToken)
		}
		v.cl.SetToken(string(rootToken))
	} else {
		var otp string
		var nonce string
		var encodedRootToken string
		var otpLength int

		slog.Debug("initiating generate-root token process...")

		// Cancel any inflight root token generation that is a remnant from a previous attempt
		err := v.cl.Sys().GenerateRootCancel()
		if err != nil {
			return errors.Wrapf(err, "unable to cancel generate root token process")
		}
		response, err := v.cl.Sys().GenerateRootInit("", "")
		if err != nil {
			return errors.Wrapf(err, "unable to initiate generate-root token process")
		}
		otp = response.OTP
		nonce = response.Nonce
		otpLength = response.OTPLength

		sealResp, err := v.cl.Sys().SealStatus()
		if err != nil {
			return errors.Wrap(err, "error getting seal status")
		}

		// Iterate over existing unseal/recovery keys
		for i := range response.Required {
			var keyID string
			if sealResp.RecoverySeal {
				keyID = keyRecoveryForID(i)
			} else {
				keyID = keyUnsealForID(i)
			}

			slog.Debug("retrieving key from kms service...")
			k, err := v.keyStore.Get(keyID)
			if err != nil {
				return errors.Wrapf(err, "unable to get key '%s'", keyID)
			}
			res, err := v.cl.Sys().GenerateRootUpdate(string(k), nonce)
			if err != nil {
				return errors.Wrapf(err, "unable to update generate-root token process with key %s", keyID)
			}

			if res.Complete {
				encodedRootToken = res.EncodedRootToken
				switch otpLength {
				case 0:
					// Backwards compat
					tokenBytes, err := XORBase64(encodedRootToken, otp)
					if err != nil {
						return errors.Wrapf(err, "error xoring encoded root token")
					}

					uuidToken, err := uuid.FormatUUID(tokenBytes)
					if err != nil {
						return errors.Wrapf(err, "error formatting base64 encoded root token")
					}
					rootToken = []byte(strings.TrimSpace(uuidToken))

				default:
					tokenBytes, err := base64.RawStdEncoding.DecodeString(encodedRootToken)
					if err != nil {
						return errors.Wrapf(err, "error decoding base64 encoded root token")
					}

					tokenBytes, err = XORBytes(tokenBytes, []byte(otp))
					if err != nil {
						return errors.Wrapf(err, "error xoring encoded root token")
					}
					rootToken = tokenBytes
				}
				v.cl.SetToken(string(rootToken))
				break
			} else if res.Complete && i == (response.Required-1) {
				err = v.cl.Sys().GenerateRootCancel()
				if err != nil {
					return errors.Wrapf(err, "unable to cancel generate root token process")
				}

				return errors.Wrapf(err, "unable to generate root token, all unseal keys were exhausted")
			}
		}
	}

	// Clear the token and GC it
	defer runtime.GC()
	defer v.cl.SetToken("")
	defer func() { rootToken = nil }()

	// Deep copy current vault externalConfig
	var loadedConfig externalConfig
	if err := mapstructure.Decode(v.externalConfig, &loadedConfig); err != nil {
		return errors.Wrap(err, "error while copying externalConfig")
	}

	// Load and merge config from input
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		// ErrorUnused is used for safety to avoid mistakes like typos in the config keys, which could lead to deletion
		// in Vault if the purge config is enabled.
		ErrorUnused:      true,
		WeaklyTypedInput: true,
		Result:           &loadedConfig,
	})
	if err != nil {
		return errors.Wrap(err, "error creating externalConfig decoder")
	}

	if err = decoder.Decode(config); err != nil {
		return errors.Wrap(err, "error decoding externalConfig")
	}

	// Update vault externalConfig with loaded data
	v.externalConfig = &loadedConfig

	if err = v.configureAuditDevices(); err != nil {
		return errors.Wrap(err, "error configuring audit devices for vault")
	}

	if err = v.configurePlugins(); err != nil {
		return errors.Wrap(err, "error configuring plugins for vault")
	}

	if err = v.configureAuthMethods(); err != nil {
		return errors.Wrap(err, "error configuring auth methods for vault")
	}

	if err = v.configureIdentityGroups(); err != nil {
		return errors.Wrap(err, "error writing groups configurations for vault")
	}

	if err = v.configurePolicies(); err != nil {
		return errors.Wrap(err, "error configuring policies for vault")
	}

	if err = v.configureSecretsEngines(); err != nil {
		return errors.Wrap(err, "error configuring secret engines for vault")
	}

	if err = v.configureStartupSecrets(); err != nil {
		return errors.Wrap(err, "error writing startup secrets to vault")
	}

	return err
}

func (v *vault) writeWithWarningCheck(path string, data map[string]interface{}) (*api.Secret, error) {
	sec, err := v.cl.Logical().Write(path, data)
	if err != nil {
		return nil, err
	}

	if sec != nil {
		for _, warning := range sec.Warnings {
			slog.Warn(warning)
		}
	}

	return sec, nil
}

type notFoundError interface {
	NotFound() bool
}

func isNotFoundError(err error) bool {
	var notFoundErr notFoundError
	if errors.As(err, &notFoundErr) && notFoundErr.NotFound() {
		return true
	}

	return false
}

// XORBytes takes two byte slices and XORs them together, returning the final
// byte slice. It is an error to pass in two byte slices that do not have the
// same length.
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.Errorf("length of byte slices is not equivalent: %d != %d", len(a), len(b))
	}

	buf := make([]byte, len(a))
	for i := range a {
		buf[i] = a[i] ^ b[i]
	}

	return buf, nil
}

// XORBase64 takes two base64-encoded strings and XORs the decoded byte slices
// together, returning the final byte slice. It is an error to pass in two
// strings that do not have the same length to their base64-decoded byte slice.
func XORBase64(a, b string) ([]byte, error) {
	aBytes, err := base64.StdEncoding.DecodeString(a)
	if err != nil {
		return nil, errors.New("error decoding first base64 value")
	}
	if len(aBytes) == 0 {
		return nil, errors.Errorf("decoded first base64 value is nil or empty")
	}

	bBytes, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		return nil, errors.New("error decoding second base64 value")
	}
	if len(bBytes) == 0 {
		return nil, errors.Errorf("decoded second base64 value is nil or empty")
	}

	return XORBytes(aBytes, bBytes)
}

func keyUnsealForID(i int) string {
	return fmt.Sprint("vault-unseal-", i)
}

func keyRecoveryForID(i int) string {
	return fmt.Sprint("vault-recovery-", i)
}
