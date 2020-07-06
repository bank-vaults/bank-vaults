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

package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"time"

	"emperror.dev/errors"
)

// PeerCertificateRequest contains a set of options configurable for peer certificate generation.
type PeerCertificateRequest struct {
	Subject     pkix.Name
	Validity    time.Duration
	DNSNames    []string
	IPAddresses []net.IP

	notBefore time.Time
}

// PeerCertificate contains the generated certificate and key in PEM encoded format.
type PeerCertificate struct {
	Certificate []byte
	Key         []byte
}

// GeneratePeerCertificate generates peer TLS certificate and key signed by a parent CA.
func GeneratePeerCertificate(req PeerCertificateRequest, signerCert *x509.Certificate, signerKey crypto.Signer) (*PeerCertificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, defaultKeyBits)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate rsa key")
	}

	keyBytes, err := keyToBytes(key)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate serial number")
	}

	validity := req.Validity
	if validity < 1 {
		validity = defaultValidity
	}

	notBefore := req.notBefore
	if notBefore.IsZero() {
		notBefore = time.Now()
	}
	notAfter := notBefore.Add(validity)

	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               req.Subject,
		IPAddresses:           req.IPAddresses,
		DNSNames:              req.DNSNames,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, signerCert, key.Public(), signerKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create x509 certificate")
	}

	certBytes, err := certToBytes(cert)
	if err != nil {
		return nil, err
	}

	return &PeerCertificate{
		Certificate: certBytes,
		Key:         keyBytes,
	}, nil
}
