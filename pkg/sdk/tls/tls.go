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
	"crypto/x509"
	"time"

	"github.com/bank-vaults/vault-sdk/tls"
)

var (
	// ErrInvalidHostName is returned when you have a hostname that has already been covered by a wildcard hostname.
	//
	// Deprecated: use [tls.ErrInvalidHostName] instead.
	ErrInvalidHostName = tls.ErrInvalidHostName

	// ErrInvalidCA will be returned if the provided CA is invalid.
	//
	// Deprecated: use [tls.ErrInvalidCA] instead.
	ErrInvalidCA = tls.ErrInvalidCA

	// ErrEmptyCA will be returned if the CA provided was empty.
	//
	// Deprecated: use [tls.ErrEmptyCA] instead.
	ErrEmptyCA = tls.ErrEmptyCA

	// ErrExpiredCA will be returned if the CA does not meet the required threshold of validity.
	//
	// Deprecated: use [tls.ErrExpiredCA] instead.
	ErrExpiredCA = tls.ErrExpiredCA
)

// CertificateManager contains a certificate chain and methods to generate certificates on that chain.
//
// Deprecated: use [tls.CertificateManager] instead.
type CertificateManager = tls.CertificateManager

// NewCertificateManager will return a new instance of the CertificateManager.
//
// Deprecated: use [tls.CertificateManager] instead.
func NewCertificateManager(hosts string, validity string) (*CertificateManager, error) {
	return tls.NewCertificateManager(hosts, validity)
}

// CertificateChain represents a full certificate chain with a root CA, a server, client and peer certificate.
// All values are in PEM format.
//
// Deprecated: use [tls.CertificateChain] instead.
type CertificateChain = tls.CertificateChain

// Deprecated: use [tls.SeparatedCertHosts] instead.
type SeparatedCertHosts = tls.SeparatedCertHosts

// NewSeparatedCertHosts creates a new seperatedCertsHosts struct by parsing and separating the comma-separated
// host names and IPs.
//
// Deprecated: use [tls.NewSeparatedCertHosts] instead.
func NewSeparatedCertHosts(hosts string) *SeparatedCertHosts {
	return tls.NewSeparatedCertHosts(hosts)
}

// GetCertExpirationDate will return a PEM encoded certificate's expiration date.
//
// Deprecated: use [tls.GetCertExpirationDate] instead.
func GetCertExpirationDate(certPEM []byte) (time.Time, error) {
	return tls.GetCertExpirationDate(certPEM)
}

// Deprecated: use [tls.PEMToCertificate] instead.
func PEMToCertificate(certPEM []byte) (*x509.Certificate, error) {
	return tls.PEMToCertificate(certPEM)
}

// GenerateTLS generates ca, server, client and peer TLS certificates.
// hosts: Comma-separated hostnames and IPs to generate a certificate for
// validity: Duration that certificate is valid for, in Go Duration format
//
// Deprecated: use [tls.GenerateTLS] instead.
func GenerateTLS(hosts string, validity string) (*CertificateChain, error) {
	return tls.GenerateTLS(hosts, validity)
}
