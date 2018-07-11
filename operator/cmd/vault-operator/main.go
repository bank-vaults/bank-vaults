package main

import (
	"context"
	"os"
	"runtime"

	stub "github.com/banzaicloud/bank-vaults/operator/pkg/stub"
	sdk "github.com/operator-framework/operator-sdk/pkg/sdk"
	sdkVersion "github.com/operator-framework/operator-sdk/version"

	"github.com/sirupsen/logrus"
)

const operatorNamespace = "OPERATOR_NAMESPACE"

func printVersion(namespace string) {
	logrus.Infof("Go Version: %s", runtime.Version())
	logrus.Infof("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)
	logrus.Infof("operator-sdk Version: %v", sdkVersion.Version)
	logrus.Infof("operator namespace: %s", namespace)
}

func main() {
	ns := os.Getenv(operatorNamespace)
	printVersion(ns)
	sdk.Watch("vault.banzaicloud.com/v1alpha1", "Vault", ns, 5)
	sdk.Handle(stub.NewHandler())
	sdk.Run(context.TODO())
}
