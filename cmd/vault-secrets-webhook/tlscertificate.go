// Copyright © 2023 Banzai Cloud
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

package main

import (
	"crypto/tls"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

type CertificateReloader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func NewCertificateReloader(certPath string, keyPath string) (*CertificateReloader, error) {
	result := &CertificateReloader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	result.cert = &cert

	go result.watchCertificate()

	return result, nil
}

func (kpr *CertificateReloader) watchCertificate() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logrus.Fatal(err)
	}
	defer watcher.Close()

	certDir, _ := filepath.Split(kpr.certPath)
	logrus.Infof("watching directory for changes: %s", certDir)
	err = watcher.Add(certDir)
	if err != nil {
		logrus.Fatal(err)
	}

	for {
		select {
		case event := <-watcher.Events:
			if (event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write) && filepath.Base(event.Name) == "..data" {
				if err := kpr.Reload(); err != nil {
					logrus.Errorf("Keeping old certificate because the new one could not be loaded: %s", err.Error())
				} else {
					logrus.Infof("Certificate has change, reloading: %s", kpr.certPath)
				}
			}
		case err := <-watcher.Errors:
			logrus.Errorf("watcher event error: %s", err.Error())
		}
	}
}

func (kpr *CertificateReloader) Reload() error {
	newCert, err := tls.LoadX509KeyPair(kpr.certPath, kpr.keyPath)
	if err != nil {
		return err
	}
	kpr.certMu.Lock()
	defer kpr.certMu.Unlock()
	kpr.cert = &newCert
	return nil
}

func (kpr *CertificateReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMu.RLock()
		defer kpr.certMu.RUnlock()
		return kpr.cert, nil
	}
}
