package gckms

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

// googleKms is an implementation of the kv.Service interface, that encrypts
// and decrypts data using Google Cloud KMS before storing into another kv
// backend.
type googleKms struct {
	svc     *cloudkms.Service
	store   kv.Service
	keyPath string
}

var _ kv.Service = &googleKms{}

func New(store kv.Service, project, location, keyring, cryptoKey string) (kv.Service, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)

	if err != nil {
		return nil, fmt.Errorf("error creating google client: %s", err.Error())
	}

	kmsService, err := cloudkms.New(client)

	if err != nil {
		return nil, fmt.Errorf("error creating google kms service client: %s", err.Error())
	}

	return &googleKms{
		store:   store,
		svc:     kmsService,
		keyPath: fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", project, location, keyring, cryptoKey),
	}, nil
}

func (g *googleKms) encrypt(s []byte) ([]byte, error) {
	resp, err := g.svc.Projects.Locations.KeyRings.CryptoKeys.Encrypt(g.keyPath, &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(s),
	}).Do()

	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %s", err.Error())
	}

	return base64.StdEncoding.DecodeString(resp.Ciphertext)
}

func (g *googleKms) decrypt(s []byte) ([]byte, error) {
	resp, err := g.svc.Projects.Locations.KeyRings.CryptoKeys.Decrypt(g.keyPath, &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(s),
	}).Do()

	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %s", err.Error())
	}

	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

func (g *googleKms) Get(key string) ([]byte, error) {
	cipherText, err := g.store.Get(key)

	if err != nil {
		return nil, err
	}

	return g.decrypt(cipherText)
}

func (g *googleKms) Set(key string, val []byte) error {
	cipherText, err := g.encrypt(val)

	if err != nil {
		return err
	}

	return g.store.Set(key, cipherText)
}

func (g *googleKms) Test(key string) error {
	// TODO: Implement me properly
	return nil
}
