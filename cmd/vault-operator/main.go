package main

import (
	"context"
	"runtime"

	stub "github.com/banzaicloud/bank-vaults/pkg/stub"
	sdk "github.com/operator-framework/operator-sdk/pkg/sdk"
	sdkVersion "github.com/operator-framework/operator-sdk/version"

	"github.com/sirupsen/logrus"
)

func printVersion() {
	logrus.Infof("Go Version: %s", runtime.Version())
	logrus.Infof("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH)
	logrus.Infof("operator-sdk Version: %v", sdkVersion.Version)
}

func main() {
	printVersion()
	sdk.Watch("vault.banzaicloud.com/v1alpha1", "Vault", "default", 5)
	sdk.Handle(stub.NewHandler())
	sdk.Run(context.TODO())
}
