package main

import (
	"os"
	"time"

	"github.com/banzaicloud/bank-vaults/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const cfgUnsealPeriod = "unseal-period"
const cfgInit = "init"
const cfgOnce = "once"

type unsealCfg struct {
	unsealPeriod time.Duration
	proceedInit  bool
	runOnce      bool
}

var unsealConfig unsealCfg

var exporter Exporter

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseals Vault with with unseal keys stored in one of the supported Cloud Provider options.",
	Long: `It will continuously attempt to unseal the target Vault instance, by retrieving unseal keys
from one of the followings:
- Google Cloud KMS keyring (backed by GCS)
- AWS KMS keyring (backed by S3)
- Azure Key Vault
- Kubernetes Secrets (should be used only for development purposes)`,
	Run: func(cmd *cobra.Command, args []string) {
		appConfig.BindPFlag(cfgUnsealPeriod, cmd.PersistentFlags().Lookup(cfgUnsealPeriod))
		appConfig.BindPFlag(cfgInit, cmd.PersistentFlags().Lookup(cfgInit))
		appConfig.BindPFlag(cfgOnce, cmd.PersistentFlags().Lookup(cfgOnce))
		appConfig.BindPFlag(cfgInitRootToken, cmd.PersistentFlags().Lookup(cfgInitRootToken))
		appConfig.BindPFlag(cfgStoreRootToken, cmd.PersistentFlags().Lookup(cfgStoreRootToken))
		unsealConfig.unsealPeriod = appConfig.GetDuration(cfgUnsealPeriod)
		unsealConfig.proceedInit = appConfig.GetBool(cfgInit)
		unsealConfig.runOnce = appConfig.GetBool(cfgOnce)

		store, err := kvStoreForConfig(appConfig)

		if err != nil {
			logrus.Fatalf("error creating kv store: %s", err.Error())
		}

		cl, err := api.NewClient(nil)

		if err != nil {
			logrus.Fatalf("error connecting to vault: %s", err.Error())
		}

		vaultConfig, err := vaultConfigForConfig(appConfig)

		if err != nil {
			logrus.Fatalf("error building vault config: %s", err.Error())
		}

		v, err := vault.New(store, cl, vaultConfig)

		if err != nil {
			logrus.Fatalf("error creating vault helper: %s", err.Error())
		}

		go 	metrics()
		for {
			func() {
				if unsealConfig.proceedInit {
					logrus.Infof("initializing vault...")
					if err = v.Init(); err != nil {
						logrus.Fatalf("error initializing vault: %s", err.Error())
					} else {
						unsealConfig.proceedInit = false
					}
				}

				logrus.Infof("checking if vault is sealed...")
				sealed, err := v.Sealed()
				if err != nil {
					logrus.Errorf("error checking if vault is sealed: %s", err.Error())
					exitIfNecessary(1)
					return
				}

				exporter.Initialized=true
				logrus.Infof("vault sealed: %t", sealed)
				exporter.Sealed=sealed

				// If vault is not sealed, we stop here and wait another unsealPeriod
				if !sealed {
					exitIfNecessary(0)
					return
				}

				if err = v.Unseal(); err != nil {
					logrus.Errorf("error unsealing vault: %s", err.Error())
					exitIfNecessary(1)
					return
				}

				logrus.Infof("successfully unsealed vault")
				exitIfNecessary(0)
			}()

			// wait unsealPeriod before trying again
			time.Sleep(unsealConfig.unsealPeriod)
		}
	},
}

func exitIfNecessary(code int) {
	if unsealConfig.runOnce {
		os.Exit(code)
	}
}


const prometheusNS = "vault"
var (
	initialized = prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNS, "", "initialized"),
		"Is the Vault initialised.",
		nil, nil,
	)
	sealed = prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNS, "", "sealed"),
		"Is the Vault node sealed.",
		nil, nil,
	)
)

type Exporter struct {
	Sealed bool
	Initialized bool
}
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- initialized
	ch <- sealed
}

func bToF(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		sealed, prometheus.GaugeValue, bToF(e.Sealed),
	)
	ch <- prometheus.MustNewConstMetric(
		initialized, prometheus.GaugeValue, bToF(e.Initialized),
	)
}
func metrics(){
	var defaultMetricsPath = "/metrics"
	var defaultMetricsPort = ":9091"
	logrus.Infof("vault metrics exporter enabled: %s%s",defaultMetricsPort, defaultMetricsPath)
	prometheus.MustRegister(&exporter)
	server := gin.New()
	server.Use(gin.Logger(), gin.ErrorLogger())
	server.GET(defaultMetricsPath, gin.WrapH(promhttp.Handler()))
	server.Run(defaultMetricsPort)
}

func init() {
	unsealCmd.PersistentFlags().Duration(cfgUnsealPeriod, time.Second*30, "How often to attempt to unseal the vault instance")
	unsealCmd.PersistentFlags().Bool(cfgInit, false, "Initialize vault instantce if not yet initialized")
	unsealCmd.PersistentFlags().Bool(cfgOnce, false, "Run unseal only once")
	unsealCmd.PersistentFlags().String(cfgInitRootToken, "", "root token for the new vault cluster (only if -init=true)")
	unsealCmd.PersistentFlags().Bool(cfgStoreRootToken, true, "should the root token be stored in the key store (only if -init=true)")

	rootCmd.AddCommand(unsealCmd)
}
