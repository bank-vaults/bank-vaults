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

package alibabakms

import (
	"emperror.dev/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"

	"github.com/bank-vaults/bank-vaults/pkg/kv"
)

type alibabaKMS struct {
	store     kv.Service
	kmsClient *kms.Client

	kmsID string
}

var _ kv.Service = &alibabaKMS{}

// New creates a new kv.Service encrypted by Alibaba KMS
func New(regionID, accessKeyID, accessKeySecret, kmsID string, store kv.Service) (kv.Service, error) {
	client, err := kms.NewClientWithAccessKey(regionID, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create KMS client")
	}

	client.GetConfig().Scheme = requests.HTTPS

	return &alibabaKMS{store: store, kmsClient: client, kmsID: kmsID}, nil
}

func (a *alibabaKMS) decrypt(cipherText []byte) ([]byte, error) {
	request := kms.CreateDecryptRequest()
	request.CiphertextBlob = string(cipherText)
	response, err := a.kmsClient.Decrypt(request)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to decrypt with KMS client")
	}

	return []byte(response.Plaintext), nil
}

func (a *alibabaKMS) Get(key string) ([]byte, error) {
	cipherText, err := a.store.Get(key)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get first with KMS client")
	}

	return a.decrypt(cipherText)
}

func (a *alibabaKMS) encrypt(plainText []byte) ([]byte, error) {
	request := kms.CreateEncryptRequest()
	request.KeyId = a.kmsID
	request.Plaintext = string(plainText)
	response, err := a.kmsClient.Encrypt(request)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to encrypt with KMS client")
	}

	return []byte(response.CiphertextBlob), nil
}

func (a *alibabaKMS) Set(key string, val []byte) error {
	cipherText, err := a.encrypt(val)
	if err != nil {
		return err
	}

	return a.store.Set(key, cipherText)
}
