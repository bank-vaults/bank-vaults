package main

import (
	"github.com/banzaicloud/bank-vaults/pkg/vault"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const prometheusNS = "vault"

var (
	initializedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNS, "sys", "initialized"),
		"Is the Vault node initialized.",
		nil, nil,
	)
	sealedDesc = prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNS, "sys", "sealed"),
		"Is the Vault node sealed.",
		nil, nil,
	)
	leaderDesc = prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNS, "sys", "leader"),
		"Is the Vault node the leader.",
		nil, nil,
	)
)

type prometheusExporter struct {
	Vault vault.Vault
}

func (e *prometheusExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- initializedDesc
	ch <- sealedDesc
	ch <- leaderDesc
}

func bToF(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (e *prometheusExporter) Collect(ch chan<- prometheus.Metric) {

	sealed, err := e.Vault.Sealed()
	if err != nil {
		logrus.Errorf("error checking if vault is sealed: %s", err.Error())
		return
	}

	leader, err := e.Vault.Leader()
	if err != nil {
		logrus.Errorf("error checking if vault is leader: %s", err.Error())
		return
	}

	ch <- prometheus.MustNewConstMetric(
		initializedDesc, prometheus.GaugeValue, bToF(true),
	)
	ch <- prometheus.MustNewConstMetric(
		sealedDesc, prometheus.GaugeValue, bToF(sealed),
	)
	ch <- prometheus.MustNewConstMetric(
		leaderDesc, prometheus.GaugeValue, bToF(leader),
	)
}

func (e prometheusExporter) Run() {
	var defaultMetricsPath = "/metrics"
	var defaultMetricsPort = ":9091"
	logrus.Infof("vault metrics exporter enabled: %s%s", defaultMetricsPort, defaultMetricsPath)
	prometheus.MustRegister(&e)
	server := gin.New()
	server.Use(gin.Logger(), gin.ErrorLogger())
	server.GET(defaultMetricsPath, gin.WrapH(promhttp.Handler()))
	server.Run(defaultMetricsPort)
}
