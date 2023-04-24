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
	"crypto/x509"

	"github.com/bank-vaults/vault-sdk/tls"
)

// ServerCertificateRequest contains a set of options configurable for server certificate generation.
//
// Deprecated: use [tls.ServerCertificateRequest] instead.
type ServerCertificateRequest = tls.ServerCertificateRequest

// ServerCertificate contains the generated certificate and key in PEM encoded format.
//
// Deprecated: use [tls.ServerCertificate] instead.
type ServerCertificate = tls.ServerCertificate

// GenerateServerCertificate generates server TLS certificate and key signed by a parent CA.
//
// Deprecated: use [tls.ServerCertificate] instead.
func GenerateServerCertificate(req ServerCertificateRequest, signerCert *x509.Certificate, signerKey crypto.Signer) (*ServerCertificate, error) {
	return tls.GenerateServerCertificate(req, signerCert, signerKey)
}
