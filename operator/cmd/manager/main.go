package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/banzaicloud/bank-vaults/operator/pkg/apis"
	"github.com/banzaicloud/bank-vaults/operator/pkg/controller"
	"github.com/operator-framework/operator-sdk/pkg/k8sutil"
	"github.com/operator-framework/operator-sdk/pkg/leader"
	"github.com/operator-framework/operator-sdk/pkg/ready"
	sdkVersion "github.com/operator-framework/operator-sdk/version"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"
)

var log = logf.Log.WithName("cmd")

const (
	operatorNamespace = "OPERATOR_NAMESPACE"
	livenessPort      = "8080"
)


func printVersion() {
	log.Info(fmt.Sprintf("Go Version: %s", runtime.Version()))
	log.Info(fmt.Sprintf("Go OS/Arch: %s/%s", runtime.GOOS, runtime.GOARCH))
	log.Info(fmt.Sprintf("operator-sdk Version: %v", sdkVersion.Version))
}

func handleLiveness() {
	log.Info("Liveness probe listening on: %s", livenessPort)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.V(2).Info("ping")
	})
	err := http.ListenAndServe(":"+livenessPort, nil)
	if err != nil {
		log.Error(err, "failed to start health probe: %v\n")
	}
}

func main() {
	flag.Parse()

	// The logger instantiated here can be changed to any logger
	// implementing the logr.Logger interface. This logger will
	// be propagated through the whole operator, generating
	// uniform and structured logs.
	logf.SetLogger(logf.ZapLogger(false))

	printVersion()

	var namespace string
	var err error
	namespace, isSet := os.LookupEnv(operatorNamespace)

	if !isSet {
		namespace, err = k8sutil.GetWatchNamespace()
		if err != nil {
			log.Error(err, "failed to get watch namespace")
			os.Exit(1)
		}
	}
	log.Info("Watched namespace:", namespace)

	// Get a config to talk to the apiserver
	cfg, err := config.GetConfig()
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	// Become the leader before proceeding
	leader.Become(context.TODO(), "vault-operator-lock")

	r := ready.NewFileReady()
	err = r.Set()
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}
	defer r.Unset()

	// Create a new Cmd to provide shared dependencies and start components
	mgr, err := manager.New(cfg, manager.Options{Namespace: namespace})
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	log.Info("Registering Components.")

	// Setup Scheme for all resources
	if err := apis.AddToScheme(mgr.GetScheme()); err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	// Setup all Controllers
	if err := controller.AddToManager(mgr); err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	log.Info("Starting the Cmd.")

	// Start the health probe
	go handleLiveness()

	// Start the Cmd
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Error(err, "manager exited non-zero")
		os.Exit(1)
	}
}
