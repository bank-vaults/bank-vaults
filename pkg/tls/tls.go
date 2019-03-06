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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
)

var serialNumberLimit *big.Int

func init() {
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
}

const (
	defaultValidity = 365 * 24 * time.Hour
	defaultKeyBits  = 2048
)

// CertificateChain represents a full certificate chain with a root CA, a server, client and peer certificate
// All values are in PEM format
type CertificateChain struct {
	CAKey      string `mapstructure:"caKey"`
	CACert     string `mapstructure:"caCert"`
	ServerKey  string `mapstructure:"serverKey"`
	ServerCert string `mapstructure:"serverCert"`
	ClientKey  string `mapstructure:"clientKey"`
	ClientCert string `mapstructure:"clientCert"`
	PeerKey    string `mapstructure:"peerKey"`
	PeerCert   string `mapstructure:"peerCert"`
}

// GenerateTLS generates ca, server, client and peer TLS certificates.
// hosts: Comma-separated hostnames and IPs to generate a certificate for
// validity: Duration that certificate is valid for, in Go Duration format
func GenerateTLS(hosts string, validity string) (*CertificateChain, error) {
	notBefore := time.Now()
	validityDuration, err := time.ParseDuration(validity)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	notAfter := notBefore.Add(validityDuration)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	caKeyBytes, err := keyToBytes(caKey)
	if err != nil {
		return nil, err
	}

	caCertTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Banzai Cloud"},
			CommonName:   "Banzai Cloud Generated Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCert, err := x509.CreateCertificate(rand.Reader, &caCertTemplate, &caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCertBytes, err := certToBytes(caCert)
	if err != nil {
		return nil, err
	}

	serverCertRequest := ServerCertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Banzai Cloud"},
			CommonName:   "Banzai Cloud Generated Server Cert",
		},
		Validity:  validityDuration,
		notBefore: notBefore,
	}
	for _, h := range strings.Split(hosts, ",") {
		if ip := net.ParseIP(h); ip != nil {
			serverCertRequest.IPAddresses = append(serverCertRequest.IPAddresses, ip)
		} else {
			serverCertRequest.DNSNames = append(serverCertRequest.DNSNames, h)
		}
	}

	serverCert, err := GenerateServerCertificate(serverCertRequest, &caCertTemplate, caKey)
	if err != nil {
		return nil, err
	}

	clientCertRequest := ClientCertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Banzai Cloud"},
			CommonName:   "Banzai Cloud Generated Client Cert",
		},
		Validity:  validityDuration,
		notBefore: notBefore,
	}

	clientCert, err := GenerateClientCertificate(clientCertRequest, &caCertTemplate, caKey)
	if err != nil {
		return nil, err
	}

	peerCertRequest := PeerCertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Banzai Cloud"},
			CommonName:   "Banzai Cloud Generated Peer Cert",
		},
		Validity:  validityDuration,
		notBefore: notBefore,
	}
	for _, h := range strings.Split(hosts, ",") {
		if ip := net.ParseIP(h); ip != nil {
			peerCertRequest.IPAddresses = append(peerCertRequest.IPAddresses, ip)
		} else {
			peerCertRequest.DNSNames = append(peerCertRequest.DNSNames, h)
		}
	}

	peerCert, err := GeneratePeerCertificate(peerCertRequest, &caCertTemplate, caKey)
	if err != nil {
		return nil, err
	}

	cc := CertificateChain{
		CAKey:      string(caKeyBytes),
		CACert:     string(caCertBytes),
		ServerKey:  string(serverCert.Key),
		ServerCert: string(serverCert.Certificate),
		ClientKey:  string(clientCert.Key),
		ClientCert: string(clientCert.Certificate),
		PeerKey:    string(peerCert.Key),
		PeerCert:   string(peerCert.Certificate),
	}

	return &cc, nil
}

func keyToBytes(key *rsa.PrivateKey) ([]byte, error) {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	var buf bytes.Buffer

	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, errors.WithStack(err)
	}

	return buf.Bytes(), nil
}

func certToBytes(certBytes []byte) ([]byte, error) {
	var buf bytes.Buffer

	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, errors.WithStack(err)
	}

	return buf.Bytes(), nil
}
