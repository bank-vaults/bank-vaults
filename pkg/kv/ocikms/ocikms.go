// Copyright © 2024 Bank-Vaults Maintainers
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

package ocikms

import (
	"context"
	"encoding/base64"

	"emperror.dev/errors"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"

	"github.com/bank-vaults/bank-vaults/pkg/kv"
)

// ociKms is an implementation of the kv.Service interface, that encrypts
// and decrypts and stores data using Oracle KMS.
type ociKms struct {
	svc     *keymanagement.KmsCryptoClient
	store   kv.Service
	keyOCID string
}

var _ kv.Service = &ociKms{}

// New creates a new kv.Service encrypted by Oracle KMS
func New(store kv.Service, keyOCID, endpoint string) (kv.Service, error) {
	client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(
		common.DefaultConfigProvider(),
		endpoint,
	)
	if err != nil {
		return nil, errors.Wrap(err, "error creating oracle secret client")
	}

	return &ociKms{
		store:   store,
		svc:     &client,
		keyOCID: keyOCID,
	}, nil
}

func (oci *ociKms) encrypt(b []byte) ([]byte, error) {
	request := keymanagement.EncryptRequest{
		EncryptDataDetails: keymanagement.EncryptDataDetails{
			KeyId:     &oci.keyOCID,
			Plaintext: common.String(base64.StdEncoding.EncodeToString(b)),
		},
	}
	response, err := oci.svc.Encrypt(context.Background(), request)
	if err != nil {
		return nil, errors.Wrap(err, "error encrypting data with oci")
	}

	return []byte(*response.Ciphertext), nil
}

func (oci *ociKms) decrypt(b []byte) ([]byte, error) {
	request := keymanagement.DecryptRequest{
		DecryptDataDetails: keymanagement.DecryptDataDetails{
			KeyId:      &oci.keyOCID,
			Ciphertext: common.String(string(b)),
		},
	}
	response, err := oci.svc.Decrypt(context.Background(), request)
	if err != nil {
		return nil, errors.Wrap(err, "error decrypting data with oci")
	}

	decodedBytes, err := base64.StdEncoding.DecodeString(*response.Plaintext)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding base64 data from oci")
	}

	return decodedBytes, nil
}

func (oci *ociKms) Get(key string) ([]byte, error) {
	cipherText, err := oci.store.Get(key)
	if err != nil {
		return nil, errors.Wrap(err, "error getting data")
	}

	return oci.decrypt(cipherText)
}

func (oci *ociKms) Set(key string, val []byte) error {
	cipherText, err := oci.encrypt(val)
	if err != nil {
		return errors.Wrap(err, "error setting data")
	}

	return oci.store.Set(key, cipherText)
}
