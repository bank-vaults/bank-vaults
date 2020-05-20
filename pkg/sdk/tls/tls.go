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

	"emperror.dev/errors"
)

var serialNumberLimit *big.Int

func init() {
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
}

const (
	defaultValidity = 365 * 24 * time.Hour
	defaultKeyBits  = 2048
)

var (
	// InvalidHostNameError is returned when you have a hostname that has already been covered by a wildcard hostname
	InvalidHostNameError = errors.New("invalid host name, this has been already covered by the wildcard")

	// InvalidCAError will be returned if the provided CA is invalid
	InvalidCAError = errors.New("the CA provided is not valid")

	// NoCAError will be returned if the CA provided was empty
	EmptyCAError = errors.New("an empty CA was provided")

	// ExpiredCAError will be returned if the CA does not meet the required threshold of validity
	ExpiredCAError = errors.New("the CA provided will expired before the provided threshold")
)

// CertificateManager contains a certificate chain and methods to generate certificates on that chain
type CertificateManager struct {
	caCertTemplate *x509.Certificate
	caKey          *rsa.PrivateKey

	sHosts *separatedCertHosts

	notBefore        time.Time
	validityDuration time.Duration
	notAfter         time.Time

	Chain *CertificateChain
}

// NewCertificateManager will return a new instance of the CertificateManager
func NewCertificateManager(hosts string, validity string) (*CertificateManager, error) {
	cm := CertificateManager{
		Chain: &CertificateChain{},
	}

	var err error
	cm.notBefore, cm.validityDuration, cm.notAfter, err = getTimes(validity)
	if err != nil {
		return nil, err
	}

	cm.sHosts = NewSeparatedCertHosts(hosts)
	err = cm.sHosts.validate()
	if err != nil {
		return nil, err
	}

	return &cm, nil
}

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

type separatedCertHosts struct {
	WildCardHosts []string
	Hosts         []string
	IPs           []net.IP
}

// NewSeparatedCertHosts creates a new seperatedCertsHosts struct by parsing and separating the comma-separated
// host names and IPs.
func NewSeparatedCertHosts(hosts string) *separatedCertHosts {
	sHosts := separatedCertHosts{}
	for _, h := range strings.Split(hosts, ",") {
		if ip := net.ParseIP(h); ip != nil {
			sHosts.IPs = append(sHosts.IPs, ip)
		} else {
			if strings.HasPrefix(h, "*.") {
				sHosts.WildCardHosts = append(sHosts.WildCardHosts, h)
			} else {
				sHosts.Hosts = append(sHosts.Hosts, h)
			}
		}
	}
	return &sHosts
}

// validate validates the hostnames in case of wildCard host is present
// eg.: *.foo.bar boo.foo.bar is not allowed, but coo.boo.foo.bar is valid
func (sh *separatedCertHosts) validate() error {
	if len(sh.WildCardHosts) == 0 {
		return nil
	} else {
		for _, wildCardHost := range sh.WildCardHosts {
			hostWithoutWildCard := strings.ReplaceAll(wildCardHost, "*", "")
			for _, host := range sh.Hosts {
				if strings.Contains(host, hostWithoutWildCard) {
					if !strings.Contains(strings.ReplaceAll(host, hostWithoutWildCard, ""), ".") {
						return errors.WithStack(InvalidHostNameError)
					}
				}
			}
		}
	}
	return nil
}

// GetCertExpirationDate will return a PEM encoded certificate's expiration date
func GetCertExpirationDate(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "failed to parse certificate")
	}

	return cert.NotAfter, nil
}

func getTimes(validity string) (notBefore time.Time, validityDuration time.Duration, notAfter time.Time, err error) {
	notBefore = time.Now()

	validityDuration, err = time.ParseDuration(validity)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	notAfter = notBefore.Add(validityDuration)
	return
}

// NewChain generates ca, server, client and peer TLS certificates.
// hosts: Comma-separated hostnames and IPs to generate a certificate for
// validity: Duration that certificate is valid for, in Go Duration format
func (cc *CertificateManager) NewChain() error {
	err := cc.GenerateCA()
	if err != nil {
		return errors.Wrap(err, "error generating new certificate authority")
	}

	err = cc.GenerateServer()
	if err != nil {
		return errors.Wrap(err, "error generating new server certificate")
	}

	err = cc.GenerateClient()
	if err != nil {
		return errors.Wrap(err, "error generating new server certificate")
	}

	err = cc.GeneratePeer()
	if err != nil {
		return errors.Wrap(err, "error generating new server certificate")
	}

	return nil
}

func keyToBytes(key *rsa.PrivateKey) ([]byte, error) {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	var buf bytes.Buffer

	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, errors.Wrap(err, "failed to PEM encode private key")
	}

	return buf.Bytes(), nil
}

func certToBytes(certBytes []byte) ([]byte, error) {
	var buf bytes.Buffer

	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, errors.Wrap(err, "failed to PEM encode certificate")
	}

	return buf.Bytes(), nil
}

// LoadCA will load an existing certifiate authority into the CertificateManager and underlying chain
func (cc *CertificateManager) LoadCA(caCertBytes []byte, caKeyBytes []byte, expirationThreshold time.Duration) error {
	if len(caCertBytes) == 0 || len(caKeyBytes) == 0 {
		return EmptyCAError
	}

	// Get CA expiration date
	tlsExpiration, err := GetCertExpirationDate(caCertBytes)
	if err != nil {
		return errors.Wrap(err, "unable to get the CA expiration date")
	}

	if time.Until(tlsExpiration) < expirationThreshold {
		return ExpiredCAError
	}

	caCertPem, _ := pem.Decode(caCertBytes)
	if caCertPem == nil {
		return errors.Wrap(InvalidCAError, "no PEM encoded CA certificate could be found")
	}
	caKeyPem, _ := pem.Decode(caKeyBytes)
	if caKeyPem == nil {
		return errors.Wrap(InvalidCAError, "no PEM encoded CA key could be found")
	}

	if caCertPem.Type != "CERTIFICATE" {
		return errors.Wrap(InvalidCAError, "the CA certificate was not of type CERTIFICATE")
	}

	if caKeyPem.Type != "RSA PRIVATE KEY" {
		return errors.Wrap(InvalidCAError, "the CA certificate was not of type RSA PRIVATE KEY")
	}

	caCert, err := x509.ParseCertificate(caCertPem.Bytes)
	if err != nil {
		return errors.Wrap(err, "the CA certificate was not not x509 parsable")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(caKeyPem.Bytes)
	if err != nil {
		return errors.Wrap(err, "the CA key was not not PKCS1 parsable")
	}

	cc.caCertTemplate = caCert
	cc.caKey = caKey
	cc.Chain.CACert = string(caCertBytes)
	cc.Chain.CAKey = string(caKeyBytes)
	return nil
}

// GenerateCA will generate a new certificate authority
func (c *CertificateManager) GenerateCA() error {
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.WithStack(err)
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.WithStack(err)
	}

	caKeyBytes, err := keyToBytes(caKey)
	if err != nil {
		return err
	}

	caCertTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Banzai Cloud"},
			CommonName:   "Banzai Cloud Generated Root CA",
		},
		NotBefore:             c.notBefore,
		NotAfter:              c.notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCert, err := x509.CreateCertificate(rand.Reader, &caCertTemplate, &caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCertBytes, err := certToBytes(caCert)
	if err != nil {
		return err
	}

	c.caCertTemplate = &caCertTemplate
	c.caKey = caKey

	c.Chain.CACert = string(caCertBytes)
	c.Chain.CAKey = string(caKeyBytes)
	return nil
}

// GenerateServer will generate a new server TLS certificate signed by the CA within the chain
func (c *CertificateManager) GenerateServer() error {
	serverCertRequest := ServerCertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Banzai Cloud"},
			CommonName:   "Banzai Cloud Generated Server Cert",
		},
		Validity:  c.validityDuration,
		notBefore: c.notBefore,
	}
	if len(c.sHosts.WildCardHosts) != 0 {
		serverCertRequest.Subject.CommonName = c.sHosts.WildCardHosts[0]
		serverCertRequest.DNSNames = append(serverCertRequest.DNSNames, c.sHosts.WildCardHosts...)
	}
	serverCertRequest.IPAddresses = append(serverCertRequest.IPAddresses, c.sHosts.IPs...)
	serverCertRequest.DNSNames = append(serverCertRequest.DNSNames, c.sHosts.Hosts...)

	serverCert, err := GenerateServerCertificate(serverCertRequest, c.caCertTemplate, c.caKey)
	if err != nil {
		return err
	}

	c.Chain.ServerKey = string(serverCert.Key)
	c.Chain.ServerCert = string(serverCert.Certificate)
	return nil
}

// GenerateClient will generate a new client TLS certificate signed by the CA within the chain
func (c *CertificateManager) GenerateClient() error {
	clientCertRequest := ClientCertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Banzai Cloud"},
			CommonName:   "Banzai Cloud Generated Client Cert",
		},
		Validity:  c.validityDuration,
		notBefore: c.notBefore,
	}

	clientCert, err := GenerateClientCertificate(clientCertRequest, c.caCertTemplate, c.caKey)
	if err != nil {
		return err
	}

	c.Chain.ClientKey = string(clientCert.Key)
	c.Chain.ClientCert = string(clientCert.Certificate)
	return nil
}

// GeneratePeer will generate a new peer TLS certificate signed by the CA within the chain
func (c *CertificateManager) GeneratePeer() error {
	peerCertRequest := PeerCertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Banzai Cloud"},
			CommonName:   "Banzai Cloud Generated Peer Cert",
		},
		Validity:  c.validityDuration,
		notBefore: c.notBefore,
	}

	if len(c.sHosts.WildCardHosts) != 0 {
		peerCertRequest.Subject.CommonName = c.sHosts.WildCardHosts[0]
		peerCertRequest.DNSNames = append(peerCertRequest.DNSNames, c.sHosts.WildCardHosts...)
	}
	peerCertRequest.IPAddresses = append(peerCertRequest.IPAddresses, c.sHosts.IPs...)
	peerCertRequest.DNSNames = append(peerCertRequest.DNSNames, c.sHosts.Hosts...)

	peerCert, err := GeneratePeerCertificate(peerCertRequest, c.caCertTemplate, c.caKey)
	if err != nil {
		return err
	}

	c.Chain.PeerKey = string(peerCert.Key)
	c.Chain.PeerCert = string(peerCert.Certificate)
	return nil
}

// GenerateTLS generates ca, server, client and peer TLS certificates.
// hosts: Comma-separated hostnames and IPs to generate a certificate for
// validity: Duration that certificate is valid for, in Go Duration format
func GenerateTLS(hosts string, validity string) (*CertificateChain, error) {
	cm, err := NewCertificateManager(hosts, validity)
	if err != nil {
		return nil, err
	}

	if err = cm.NewChain(); err != nil {
		return nil, err
	}

	return cm.Chain, nil
}
