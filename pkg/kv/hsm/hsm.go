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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"emperror.dev/errors"
	"github.com/banzaicloud/bank-vaults/pkg/kv"
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"github.com/sirupsen/logrus"
)

type cryptoFunc func([]byte) ([]byte, error)

type hsmKV struct {
	mechanism  pkcs11.Mechanism
	publicKey  p11.PublicKey
	privateKey p11.PrivateKey
	storage    kv.Service
	log        *logrus.Logger
	encrypt    cryptoFunc
	decrypt    cryptoFunc
}

type HSMConfig struct {
	ModulePath string
	SlotID     uint
	Pin        string
	KeyLabel   string
}

// NewHSM: currently RSA keys are supported only
func NewHSM(config HSMConfig, storage kv.Service) (kv.Service, error) {

	log := logrus.New()

	module, err := p11.OpenModule(config.ModulePath)
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

	log.Infof("HSM Searching for slot %d in HSM slots %+v", config.SlotID, slots)
	var slot p11.Slot
	for _, s := range slots {
		if s.ID() == config.SlotID {
			slot = s
			break
		}
	}

	tokenInfo, err := slot.TokenInfo()
	if err != nil {
		return nil, errors.WrapIf(err, "can't find HSM slot")
	}

	log.Infof("HSM TokenInfo for slot %d: %+v", config.SlotID, tokenInfo)

	bestMechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

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

	slotInfo, err := slot.Info()
	if err != nil {
		return nil, errors.WrapIf(err, "can't get HSM slot info")
	}

	log.Infof("HSM SlotInfo for slot %d: %+v", config.SlotID, slotInfo)

	session, err := slot.OpenWriteSession()
	if err != nil {
		return nil, err
	}

	err = session.Login(config.Pin)
	if err != nil {
		return nil, err
	}

	privateKeyAttributes := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, config.KeyLabel)}

	// ignore "no objects found" error, and check the size insted
	allObjects, _ := session.FindObjects(privateKeyAttributes)

	var publicKey p11.PublicKey
	var privateKey p11.PrivateKey

	if len(allObjects) == 0 {

		log.Info("generating key pair in HSM...")

		request := generateRSAKeyPairRequest(config.KeyLabel)
		keyPair, err := session.GenerateKeyPair(request)
		if err != nil {
			return nil, err
		}

		privateKey = keyPair.Private
		publicKey = keyPair.Public

	} else {

		log.Infof("found existing objects in HSM: %+v", allObjects)

		privateKey = p11.PrivateKey(allObjects[0])
		publicKey = p11.PublicKey(allObjects[1])
	}

	// Some devices doesn't support encryption, just storing public keys, in this case we have to extract the key
	// and encrypt with on the computer with the corresping Go crypto package.
	var encrypt cryptoFunc

	if info.ManufacturerID == "OpenSC Project" {

		log.Info("this HSM device doesn't support encryption, extracting public key and doing encrytion on the computer")

		publicKeyValue, err := allObjects[1].Value()
		if err != nil {
			return nil, err
		}

		publicKey, err := x509.ParsePKCS1PublicKey(publicKeyValue)
		if err != nil {
			return nil, errors.WrapIf(err, "can't parse public key from HSM device")
		}

		encrypt = func(plaintext []byte) ([]byte, error) {
			return rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
		}
	} else {
		encrypt = func(plaintext []byte) ([]byte, error) {
			return publicKey.Encrypt(*bestMechanism, plaintext)
		}
	}

	decrypt := func(ciphertext []byte) ([]byte, error) {
		return privateKey.Decrypt(*bestMechanism, ciphertext)
	}

	return &hsmKV{
		log:        log,
		privateKey: privateKey,
		publicKey:  publicKey,
		storage:    storage,
		mechanism:  *bestMechanism,
		encrypt:    encrypt,
		decrypt:    decrypt,
	}, nil
}

func (h *hsmKV) Get(key string) ([]byte, error) {
	ciphertext, err := h.storage.Get(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := h.decrypt(ciphertext)
	if err != nil {
		return nil, errors.WrapIf(err, "can't decrypt data with HSM")
	}

	return plaintext, nil
}

func (h *hsmKV) Set(key string, value []byte) error {
	ciphertext, err := h.encrypt(value)
	if err != nil {
		return errors.WrapIf(err, "can't encrypt data with HSM")
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
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}

	return p11.GenerateKeyPairRequest{Mechanism: mechanism, PublicKeyAttributes: publicKeyTemplate, PrivateKeyAttributes: privateKeyTemplate}
}
