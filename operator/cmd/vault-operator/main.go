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

package main

import (
	"context"
	"net/http"
	"os"
	"runtime"

	stub "github.com/banzaicloud/bank-vaults/operator/pkg/stub"
	sdk "github.com/operator-framework/operator-sdk/pkg/sdk"
	sdkVersion "github.com/operator-framework/operator-sdk/version"

	"github.com/sirupsen/logrus"
)

const (
	operatorNamespace = "OPERATOR_NAMESPACE"
	livenessPort      = "8080"
)

func printVersion(namespace string) {
	logrus.Infof("Go Version: %s", runtime.Version())
	logrus.Infof("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)
	logrus.Infof("operator-sdk Version: %v", sdkVersion.Version)
	logrus.Infof("operator namespace: %s", namespace)
}

func handleLiveness() {
	logrus.Infof("Liveness probe listening on: %s", livenessPort)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logrus.Debug("ping")
	})
	err := http.ListenAndServe(":"+livenessPort, nil)
	if err != nil {
		logrus.Errorf("failed to start health probe: %v\n", err)
	}
}

func main() {
	ns := os.Getenv(operatorNamespace)
	printVersion(ns)
	sdk.Watch("vault.banzaicloud.com/v1alpha1", "Vault", ns, 5)
	sdk.Handle(stub.NewHandler())
	// Start the health probe
	go handleLiveness()
	sdk.Run(context.TODO())
}
