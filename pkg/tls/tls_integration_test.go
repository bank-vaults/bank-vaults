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
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

const (
	ServerKey  = "server.key"
	ServerCert = "server.crt"
)

func helloServer(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example TLS server.\n"))
}

func TestGenerateTLS(t *testing.T) {
	cc, err := GenerateTLS("localhost", "1h")
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile(ServerKey, []byte(cc.ServerKey), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(ServerCert, []byte(cc.ServerCert), 0600)
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(ServerKey)
	defer os.Remove(ServerCert)

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(cc.CACert))

	tlsConfig := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                caCertPool,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}

	tlsConfig.BuildNameToCertificate()

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/", helloServer)

	go server.ListenAndServeTLS(ServerCert, ServerKey)

	// Load client cert
	cert, err := tls.X509KeyPair([]byte(cc.ClientCert), []byte(cc.ClientKey))
	if err != nil {
		t.Fatal(err)
	}

	// Setup HTTPS client
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	clientTLSConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: clientTLSConfig}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequest("GET", "https://localhost:8443/", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	server.Close()
}
