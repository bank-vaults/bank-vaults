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
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
			err := sHosts.Validate()
			if err != nil {
				if err.Error() != ErrInvalidHostName.Error() {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestGenerateTLS(t *testing.T) {
	cm, err := NewCertificateManager("localhost,127.0.0.1", "1h")
	if err != nil {
		t.Fatal(err)
	}

	err = cm.NewChain()
	if err != nil {
		t.Fatal(err)
	}

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(cm.Chain.CACert))

	serverCert, err := tls.X509KeyPair([]byte(cm.Chain.ServerCert), []byte(cm.Chain.ServerKey))
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
		_, err := w.Write([]byte("This is an example TLS server.\n"))
		if err != nil {
			t.Fatal(err)
		}
	}))

	server.Listener = tls.NewListener(server.Listener, tlsConfig)

	server.Start()

	// Load client cert
	clientCert, err := tls.X509KeyPair([]byte(cm.Chain.ClientCert), []byte(cm.Chain.ClientKey))
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
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+test, nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			resp.Body.Close()
		})
	}

	server.Close()
}

func TestLoadAndRegenerateTLS(t *testing.T) {
	cmTemp, err := NewCertificateManager("localhost,127.0.0.1", "1h")
	if err != nil {
		t.Fatal(err)
	}

	err = cmTemp.NewChain()
	if err != nil {
		t.Fatal(err)
	}

	cm, err := NewCertificateManager("localhost,127.0.0.1", "1h")
	if err != nil {
		t.Fatal(err)
	}

	// Load an existing certificate authority
	err = cm.LoadCA([]byte(cmTemp.Chain.CACert), []byte(cmTemp.Chain.CAKey), time.Minute*50)
	if err != nil {
		t.Fatal(err)
	}

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(cm.Chain.CACert))

	err = cm.GenerateServer()
	// Generate the Server TLS certificate
	if err != nil {
		t.Fatal(err)
	}

	err = cm.GenerateClient()
	// Generate the Client TLS certificate
	if err != nil {
		t.Fatal(err)
	}

	serverCert, err := tls.X509KeyPair([]byte(cm.Chain.ServerCert), []byte(cm.Chain.ServerKey))
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
		_, err := w.Write([]byte("This is an example TLS server.\n"))
		if err != nil {
			t.Fatal(err)
		}
	}))

	server.Listener = tls.NewListener(server.Listener, tlsConfig)

	server.Start()

	// Load client cert
	clientCert, err := tls.X509KeyPair([]byte(cm.Chain.ClientCert), []byte(cm.Chain.ClientKey))
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
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+test, nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			resp.Body.Close()
		})
	}

	server.Close()
}
