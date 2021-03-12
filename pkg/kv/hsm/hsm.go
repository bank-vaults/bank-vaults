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
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"github.com/sirupsen/logrus"

	"github.com/banzaicloud/bank-vaults/pkg/kv"
)

const noObjectsFoundErrMsg = "no objects found"

type cryptoFunc func([]byte) ([]byte, error)

type hsmCrypto struct {
	mechanism  pkcs11.Mechanism
	publicKey  p11.PublicKey
	privateKey p11.PrivateKey
	storage    kv.Service
	log        *logrus.Logger
	session    p11.Session
	encrypt    cryptoFunc
	decrypt    cryptoFunc
}

// Config holds the HSM access information
type Config struct {
	ModulePath string
	SlotID     uint
	TokenLabel string
	Pin        string
	KeyLabel   string
}

// New returns a HSM backed KV encryptor. Currently RSA keys are supported only.
func New(config Config, storage kv.Service) (kv.Service, error) {
	log := logrus.New()

	if config.KeyLabel == "" {
		return nil, errors.New("key label is required")
	}

	module, err := p11.OpenModule(config.ModulePath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open p11 module: %s", config.ModulePath)
	}

	info, err := module.Info()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get module info")
	}

	log.Infof("HSM Information %+v", info)

	slots, err := module.Slots()
	if err != nil {
		return nil, errors.Wrap(err, "failed to list module slots")
	}

	log.Infof("HSM Searching for slot in HSM slots %+v", slots)
	var slot *p11.Slot
	for _, s := range slots {
		if config.TokenLabel == "" {
			if s.ID() == config.SlotID {
				slot = &s // nolint:gosec
				log.Infof("found HSM slot %d in HSM by slot ID", slot.ID())

				break
			}
		} else {
			tokenInfo, err := s.TokenInfo()
			if err != nil {
				return nil, errors.WrapIf(err, "can't query token info from slot")
			}
			if tokenInfo.Label == config.TokenLabel {
				slot = &s // nolint:gosec
				log.Infof("found HSM slot %d in HSM by token label", slot.ID())

				break
			}
		}
	}

	if slot == nil {
		return nil, errors.New("can't find HSM slot")
	}

	tokenInfo, err := slot.TokenInfo()
	if err != nil {
		return nil, errors.WrapIf(err, "can't query token info from slot")
	}

	log.Infof("HSM TokenInfo %+v", tokenInfo)

	bestMechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

	// // TODO find the best mechanism the HSM supports
	// mechanisms, err := slot.Mechanisms()
	// if err != nil {
	// 	return nil, err
	// }
	// for _, mechanism := range mechanisms {
	// 	info, err := mechanism.Info()
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	fmt.Printf("RSA mechanism info: %+v supports encrypt: %t\n", info, info.Flags&pkcs11.CKA_ENCRYPT == pkcs11.CKA_ENCRYPT)
	// }

	slotInfo, err := slot.Info()
	if err != nil {
		return nil, errors.WrapIf(err, "can't get HSM slot info")
	}

	log.Infof("HSM SlotInfo for slot %d: %+v", config.SlotID, slotInfo)

	session, err := slot.OpenWriteSession()
	if err != nil {
		return nil, errors.WrapIf(err, "opening session with HSM failed")
	}

	err = session.Login(config.Pin)
	if err != nil {
		return nil, errors.WrapIf(err, "login to HSM failed")
	}

	publicKeyAttributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, config.KeyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}
	privateKeyAttributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, config.KeyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	var publicKey p11.PublicKey
	var privateKey p11.PrivateKey

	publicKeyObj, publicKeyErr := session.FindObject(publicKeyAttributes)
	privateKeyObj, privateKeyErr := session.FindObject(privateKeyAttributes)

	// ignore "no objects found" errors and generate a key
	if publicKeyErr != nil && privateKeyErr != nil {
		log.Info("generating key pair in HSM...")

		request := generateRSAKeyPairRequest(config.KeyLabel)
		keyPair, err := session.GenerateKeyPair(request)
		if err != nil {
			return nil, errors.WrapIf(err, "GenerateKeyPair in HSM failed")
		}

		publicKey = keyPair.Public
		privateKey = keyPair.Private
	} else if publicKeyErr == nil && privateKeyErr == nil {
		log.Infof("found objects with label %q in HSM", config.KeyLabel)

		publicKey = p11.PublicKey(publicKeyObj)
		privateKey = p11.PrivateKey(privateKeyObj)
	} else {
		return nil, errors.WrapIf(errors.Combine(publicKeyErr, privateKeyErr), "only one of the keys found with the specified label")
	}

	// Some HSM devices doesn't support encryption, just storing public keys,
	// in this case we have to extract the key and encrypt externally with
	// the corresponding Go crypto package.
	var encrypt cryptoFunc

	if info.ManufacturerID == "OpenSC Project" {
		log.Info("this HSM doesn't support on-device encryption, extracting public key and doing encrytion on the computer")

		publicKeyValue, err := p11.Object(publicKey).Value()
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

	// Decryption is always done on the HSM device.
	decrypt := func(ciphertext []byte) ([]byte, error) {
		return privateKey.Decrypt(*bestMechanism, ciphertext)
	}

	// TODO
	// session.Close()

	if storage == nil {
		log.Info("no storage backend specified for HSM, using on device storage")
		storage = &hsmStorage{session: session}
	}

	return &hsmCrypto{
		log:        log,
		session:    session,
		privateKey: privateKey,
		publicKey:  publicKey,
		storage:    storage,
		mechanism:  *bestMechanism,
		encrypt:    encrypt,
		decrypt:    decrypt,
	}, nil
}

func (h *hsmCrypto) Get(key string) ([]byte, error) {
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

func (h *hsmCrypto) Set(key string, value []byte) error {
	ciphertext, err := h.encrypt(value)
	if err != nil {
		return errors.WrapIf(err, "can't encrypt data with HSM")
	}

	return h.storage.Set(key, ciphertext)
}

/*
Purpose: Generate RSA keypair with a given tokenLabel and persistence.
	tokenLabel: string to set as the token labels
*/
func generateRSAKeyPairRequest(tokenLabel string) p11.GenerateKeyPairRequest {
	mechanism := *pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // persist the key token
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // persist the key token
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}

	return p11.GenerateKeyPairRequest{
		Mechanism:            mechanism,
		PublicKeyAttributes:  publicKeyTemplate,
		PrivateKeyAttributes: privateKeyTemplate,
	}
}

type hsmStorage struct {
	session p11.Session
}

func (h *hsmStorage) Get(key string) ([]byte, error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, key),
	}

	object, err := h.session.FindObject(attributes)
	if err != nil {
		if err.Error() == noObjectsFoundErrMsg {
			return nil, kv.NewNotFoundError("object doesn't exist in HSM: %s", key)
		}

		return nil, errors.Wrap(err, "failed to read object from HSM")
	}

	return object.Value()
}

func (h *hsmStorage) Set(key string, value []byte) error {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, value),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, key),
	}

	_, err := h.session.CreateObject(attributes)

	return errors.Wrap(err, "failed to write object to HSM")
}
