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

package awskms

import (
	"emperror.dev/errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

const (
	// SseAES256 is an algorithm that can be used for Server-Side Encryption in AWS S3 buckets
	SseAES256 string = "AES256"
	// SseKMS is an algorithm that can be used for Server-Side Encryption in AWS S3 buckets
	SseKMS string = "aws:kms"
)

type awsKMS struct {
	store      kv.Service
	kmsService *kms.KMS

	kmsID string
}

var _ kv.Service = &awsKMS{}

// NewWithSession creates a new kv.Service encrypted by AWS KMS with and existing AWS Session
func NewWithSession(sess *session.Session, store kv.Service, kmsID string) (kv.Service, error) {
	if kmsID == "" {
		return nil, errors.Errorf("invalid kmsID specified: '%s'", kmsID)
	}

	return &awsKMS{
		store:      store,
		kmsService: kms.New(sess),
		kmsID:      kmsID,
	}, nil
}

// New creates a new kv.Service encrypted by AWS KMS
func New(store kv.Service, region string, kmsID string) (kv.Service, error) {
	sess := session.Must(session.NewSession(aws.NewConfig().WithRegion(region)))

	return NewWithSession(sess, store, kmsID)
}

func (a *awsKMS) decrypt(cipherText []byte) ([]byte, error) {
	out, err := a.kmsService.Decrypt(&kms.DecryptInput{
		CiphertextBlob: cipherText,
		EncryptionContext: map[string]*string{
			"Tool": aws.String("bank-vaults"),
		},
		GrantTokens: []*string{},
	})
	if err != nil {
		return nil, err
	}

	return out.Plaintext, nil
}

func (a *awsKMS) Get(key string) ([]byte, error) {
	cipherText, err := a.store.Get(key)
	if err != nil {
		return nil, err
	}

	return a.decrypt(cipherText)
}

func (a *awsKMS) encrypt(plainText []byte) ([]byte, error) {
	out, err := a.kmsService.Encrypt(&kms.EncryptInput{
		KeyId:     aws.String(a.kmsID),
		Plaintext: plainText,
		EncryptionContext: map[string]*string{
			"Tool": aws.String("bank-vaults"),
		},
		GrantTokens: []*string{},
	})
	if err != nil {
		return nil, err
	}

	return out.CiphertextBlob, nil
}

func (a *awsKMS) Set(key string, val []byte) error {
	cipherText, err := a.encrypt(val)
	if err != nil {
		return err
	}

	return a.store.Set(key, cipherText)
}
