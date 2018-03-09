package main

import (
	"flag"
	"io/ioutil"
	"os"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/go-kit/kit/log"
	vault "github.com/hashicorp/vault/api"
	fsnotify "gopkg.in/fsnotify.v1"
)

type KeyStorer interface {
	StoreKey(key string) error
	GetKeys() ([]string, error)
}

type config struct {
	configVolumeDir string
	vaultUrl        string
}

type configurator struct {
	cfg         config
	logger      log.Logger
	vaultClient *vault.Client
	keyStorer   KeyStorer
}

func newConfigurator(cfg config, vaultClient *vault.Client, keyStorer KeyStorer, logger log.Logger) *configurator {
	return &configurator{
		cfg:         cfg,
		vaultClient: vaultClient,
		keyStorer:   keyStorer,
		logger:      logger,
	}
}

func (w *configurator) InitVault() (rootToken string, err error) {
	inited, err := w.vaultClient.Sys().InitStatus()
	if err != nil {
		return "", err
	}
	if !inited {
		initRequest := vault.InitRequest{
			SecretShares:    5,
			SecretThreshold: 3,
		}
		initResponse, err := w.vaultClient.Sys().Init(&initRequest)
		if err != nil {
			return "", err
		}
		keys := initResponse.Keys
		for _, key := range keys {
			err := w.keyStorer.StoreKey(key)
			if err != nil {
				return "", err
			}
		}
		rootToken = initResponse.RootToken
	}

	sealStatusResponse, err := w.vaultClient.Sys().SealStatus()
	if err != nil {
		return "", err
	}
	if sealStatusResponse.Sealed {
		w.logger.Log("msg", "Vault is sealed, unsealing it now...")
		keys, err := w.keyStorer.GetKeys()
		if err != nil {
			return "", err
		}
		for _, key := range keys {
			println(key)
			sealStatusResponse, err := w.vaultClient.Sys().Unseal(key)
			if err != nil {
				return "", err
			}
			if !sealStatusResponse.Sealed {
				break
			}
		}
	}

	return "", err
}

func (w *configurator) ApplyPolicies() error {
	policiesDirectory := w.cfg.configVolumeDir + "/policies"
	policies, err := ioutil.ReadDir(policiesDirectory)
	if err != nil {
		return err
	}
	for _, policy := range policies {
		w.logger.Log("msg", "applying file: "+policy.Name())
		body, err := ioutil.ReadFile(policiesDirectory + "/" + policy.Name())
		if err != nil {
			return err
		}
		err = w.vaultClient.Sys().PutPolicy(policy.Name(), string(body))
		if err != nil {
			return err
		}
		w.logger.Log("msg", "applyed file: "+policy.Name())
	}
	return nil
}

func (w *configurator) ApplyVaultConfiguration() error {
	_, err := w.InitVault()
	if err != nil {
		return err
	}

	if err := w.ApplyPolicies(); err != nil {
		return err
	}
	return nil
}

func (w *configurator) Refresh() error {
	w.logger.Log("msg", "Updating rule files...")
	err := backoff.RetryNotify(w.ApplyVaultConfiguration, backoff.NewExponentialBackOff(), func(err error, next time.Duration) {
		w.logger.Log("msg", "Updating rule files temporarily failed.", "err", err, "next-retry", next)
	})
	if err != nil {
		w.logger.Log("msg", "Updating rule files failed.", "err", err)
		return err
	} else {
		w.logger.Log("msg", "Rule files updated.")
	}
	return nil
}

func (w *configurator) Run() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		w.logger.Log("msg", "Creating a new watcher failed.", "err", err)
		os.Exit(1)
	}
	defer watcher.Close()

	w.logger.Log("msg", "Starting...")
	err = w.Refresh()
	if err != nil {
		w.logger.Log("msg", "Initial loading of config volume failed.", "err", err)
		os.Exit(1)
	}
	err = watcher.Add(w.cfg.configVolumeDir)
	if err != nil {
		w.logger.Log("msg", "Adding config volume to be watched failed.", "err", err)
		os.Exit(1)
	}

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write {
				//if filepath.Base(event.Name) == "..data" {
				w.logger.Log("msg", "ConfigMap modified.")
				if err := w.Refresh(); err != nil {
					w.logger.Log("msg", "Rule files could not be refreshed.", "err", err)
					os.Exit(1)
				}
				//}
			}
		case err := <-watcher.Errors:
			w.logger.Log("err", err)
		}
	}
}

func main() {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	logger = log.With(logger, "ts", log.DefaultTimestampUTC)
	logger = log.With(logger, "caller", log.DefaultCaller)

	cfg := config{}
	flags := flag.NewFlagSet("vault-configurer", flag.ExitOnError)
	flags.StringVar(&cfg.configVolumeDir, "config-volume-dir", "./config", "The directory to watch for changes to configure Vault.")
	flags.StringVar(&cfg.vaultUrl, "vault-url", "http://localhost:8200", "The URL to call when intending to configure Vault.")
	flags.Parse(os.Args[1:])

	if cfg.configVolumeDir == "" {
		logger.Log("Missing directory to watch for configuration changes\n")
		flag.Usage()
		os.Exit(1)
	}

	if cfg.vaultUrl == "" {
		logger.Log("Missing URL to call Vault\n")
		flag.Usage()
		os.Exit(1)
	}

	vaultClient, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		panic("Failed to dial Vault: " + err.Error())
	}

	newConfigurator(cfg, vaultClient, &InMemoryKeyStorer{}, log.With(logger, "component", "volume-watcher")).Run()
}

type InMemoryKeyStorer struct {
	keys []string
}

func (ks *InMemoryKeyStorer) StoreKey(key string) error {
	ks.keys = append(ks.keys, key)
	return nil
}

func (ks *InMemoryKeyStorer) GetKeys() ([]string, error) {
	return ks.keys, nil
}
