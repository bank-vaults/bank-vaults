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

// PeerCertificateRequest contains a set of options configurable for peer certificate generation.
//
// Deprecated: use [tls.PeerCertificateRequest] instead.
type PeerCertificateRequest = tls.PeerCertificateRequest

// PeerCertificate contains the generated certificate and key in PEM encoded format.
//
// Deprecated: use [tls.PeerCertificate] instead.
type PeerCertificate = tls.PeerCertificate

// GeneratePeerCertificate generates peer TLS certificate and key signed by a parent CA.
//
// Deprecated: use [tls.GeneratePeerCertificate] instead.
func GeneratePeerCertificate(req PeerCertificateRequest, signerCert *x509.Certificate, signerKey crypto.Signer) (*PeerCertificate, error) {
	return tls.GeneratePeerCertificate(req, signerCert, signerKey)
}
