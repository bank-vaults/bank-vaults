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

package gckms

import (
	"context"
	"encoding/base64"
	"fmt"

	"emperror.dev/errors"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
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

// New creates a new kv.Service encrypted by Google KMS
func New(store kv.Service, project, location, keyring, cryptoKey string) (kv.Service, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, errors.Wrap(err, "error creating google client")
	}

	kmsService, err := cloudkms.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, errors.Wrap(err, "error creating google kms service client")
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
		return nil, errors.Wrap(err, "error encrypting data")
	}

	return base64.StdEncoding.DecodeString(resp.Ciphertext)
}

func (g *googleKms) decrypt(s []byte) ([]byte, error) {
	resp, err := g.svc.Projects.Locations.KeyRings.CryptoKeys.Decrypt(g.keyPath, &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(s),
	}).Do()
	if err != nil {
		return nil, errors.Wrap(err, "error decrypting data")
	}

	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

func (g *googleKms) Get(key string) ([]byte, error) {
	cipherText, err := g.store.Get(key)
	if err != nil {
		return nil, errors.Wrap(err, "error getting data")
	}

	return g.decrypt(cipherText)
}

func (g *googleKms) Set(key string, val []byte) error {
	cipherText, err := g.encrypt(val)
	if err != nil {
		return errors.Wrap(err, "error setting data")
	}

	return g.store.Set(key, cipherText)
}
