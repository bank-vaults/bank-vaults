// Copyright © 2020 Banzai Cloud
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

package hsm

import (
	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type hsmKV struct {
	mechanism  pkcs11.Mechanism
	publicKey  p11.PublicKey
	privateKey p11.PrivateKey
	storage    kv.Service
	log        *logrus.Logger
}

type HSMConfig struct {
	SlotID   uint
	Pin      string
	KeyLabel string
}

// NewHSM: currently RSA keys are supported only
func NewHSM(config HSMConfig, storage kv.Service) (kv.Service, error) {

	log := logrus.New()

	module, err := p11.OpenModule("/usr/local/lib/softhsm/libsofthsm2.so")
	if err != nil {
		return nil, err
	}

	info, err := module.Info()
	if err != nil {
		return nil, err
	}

	log.Infof("HSM Information %+v", info)

	slots, err := module.Slots()
	if err != nil {
		return nil, err
	}

	log.Infof("HSM Searching for slot %d in HSM", config.SlotID)
	var slot p11.Slot
	for _, s := range slots {
		if s.ID() == config.SlotID {
			slot = s
			break
		}
	}

	if slot.ID() == 0 {
		return nil, errors.New("Can't find slot in HSM")
	}

	var bestMechanism *pkcs11.Mechanism
	bestMechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

	// TODO find the best mechanism the HSM supports
	// mechanisms, err := slot.Mechanisms()
	// if err != nil {
	// 	return nil, err
	// }
	// for _, mechanism := range mechanisms {
	// 	fmt.Printf("mechanism: %+v\n", mechanism)

	// 	info, err := mechanism.Info()
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	fmt.Printf("mechanism info: %+v\n", info)
	// }

	tokenInfo, err := slot.TokenInfo()
	if err != nil {
		return nil, err
	}

	log.Infof("HSM TokenInfo for slot %+v", tokenInfo)

	session, err := slot.OpenWriteSession()
	if err != nil {
		return nil, err
	}

	err = session.Login(config.Pin)
	if err != nil {
		return nil, err
	}

	privateKeyAttributes := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, config.KeyLabel)}

	// ignore "no objects found" error
	allObjects, _ := session.FindObjects(privateKeyAttributes)

	var publicKey p11.PublicKey
	var privateKey p11.PrivateKey

	if len(allObjects) == 0 {
		log.Info("generating private key in HSM...")
		request := generateRSAKeyPairRequest(config.KeyLabel)
		keyPair, err := session.GenerateKeyPair(request)
		if err != nil {
			return nil, err
		}

		privateKey = keyPair.Private
		publicKey = keyPair.Public
	} else {
		privateKey = p11.PrivateKey(allObjects[0])
		publicKey = p11.PublicKey(allObjects[1])
	}

	return &hsmKV{log: log, privateKey: privateKey, publicKey: publicKey, storage: storage, mechanism: *bestMechanism}, nil
}

func (h *hsmKV) Get(key string) ([]byte, error) {
	ciphertext, err := h.storage.Get(key)
	if err != nil {
		return nil, err
	}

	return h.privateKey.Decrypt(h.mechanism, ciphertext)
}

func (h *hsmKV) Set(key string, value []byte) error {
	ciphertext, err := h.publicKey.Encrypt(h.mechanism, value)
	if err != nil {
		return err
	}

	return h.storage.Set(key, ciphertext)
}

/*
Purpose: Generate RSA keypair with a given name and persistence.
Inputs: test object
	context
	session handle
	tokenLabel: string to set as the token labels
	tokenPersistent: boolean. Whether or not the token should be
			session based or persistent. If false, the
			token will not be saved in the HSM and is
			destroyed upon termination of the session.
Outputs: creates persistent or ephemeral tokens within the HSM.
Returns: object handles for public and private keys. Fatal on error.
*/
func generateRSAKeyPairRequest(tokenLabel string) p11.GenerateKeyPairRequest {
	/*
		inputs: test object, context, session handle
			tokenLabel: string to set as the token labels
			tokenPersistent: boolean. Whether or not the token should be
					session based or persistent. If false, the
					token will not be saved in the HSM and is
					destroyed upon termination of the session.
		outputs: creates persistent or ephemeral tokens within the HSM.
		returns: object handles for public and private keys.
	*/
	mechanism := *pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	return p11.GenerateKeyPairRequest{Mechanism: mechanism, PublicKeyAttributes: publicKeyTemplate, PrivateKeyAttributes: privateKeyTemplate}
}
