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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWildCardValidation(t *testing.T) {
	tests := []struct {
		name  string
		hosts string
	}{
		{
			name:  "Not a valid host name",
			hosts: "*.banzaicloud.com,127.0.0.1,beta.banzaicloud.com",
		},
		{
			name:  "Valid host name",
			hosts: "*.banzaicloud.com,127.0.0.1,alpha.beta.banzaicloud.com",
		},
	}
	for _, test := range tests {
		sHosts := NewSeparatedCertHosts(test.hosts)
		t.Run(test.name, func(t *testing.T) {
			err := sHosts.validate()
			if err != nil {
				if err.Error() != InvalidHostNameError.Error() {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestGenerateTLS(t *testing.T) {
	cc, err := GenerateTLS("localhost,127.0.0.1", "1h")
	if err != nil {
		t.Fatal(err)
	}

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(cc.CACert))

	serverCert, err := tls.X509KeyPair([]byte(cc.ServerCert), []byte(cc.ServerKey))
	if err != nil {
		t.Fatal(err)
	}

	tlsConfig := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                caCertPool,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		Certificates:             []tls.Certificate{serverCert},
	}

	tlsConfig.BuildNameToCertificate()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("This is an example TLS server.\n"))
	}))

	server.Listener = tls.NewListener(server.Listener, tlsConfig)

	server.Start()

	// Load client cert
	clientCert, err := tls.X509KeyPair([]byte(cc.ClientCert), []byte(cc.ClientKey))
	if err != nil {
		t.Fatal(err)
	}

	// Setup HTTPS client
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	}
	clientTLSConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: clientTLSConfig}
	client := &http.Client{Transport: transport}

	tests := []string{
		server.Listener.Addr().String(), // Should work with IP address as well
		strings.Replace(server.Listener.Addr().String(), "127.0.0.1", "localhost", 1),
	}

	for _, test := range tests {
		test := test

		t.Run(strings.Split(test, ":")[0], func(t *testing.T) {
			req, err := http.NewRequest("GET", "https://"+test, nil)
			if err != nil {
				t.Fatal(err)
			}

			_, err = client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
		})
	}

	server.Close()
}
