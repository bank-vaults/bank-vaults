package tls

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
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

	err = ioutil.WriteFile("server.pem", []byte(cc.ServerKey), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile("server.cert", []byte(cc.ServerCert), 0600)
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove("server.pem")
	defer os.Remove("server.cert")

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

	go server.ListenAndServeTLS("server.cert", "server.pem")

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
