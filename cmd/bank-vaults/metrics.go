package main

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var metrics prometheusExporter

const prometheusNS = "vault"

var (
	initialized = prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNS, "", "initialized"),
		"Is the Vault node initialized.",
		nil, nil,
	)
	sealed = prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNS, "", "sealed"),
		"Is the Vault node sealed.",
		nil, nil,
	)
)

type prometheusExporter struct {
	Sealed      bool
	Initialized bool
}

func (e *prometheusExporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- initialized
	ch <- sealed
}

func bToF(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (e *prometheusExporter) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		sealed, prometheus.GaugeValue, bToF(e.Sealed),
	)
	ch <- prometheus.MustNewConstMetric(
		initialized, prometheus.GaugeValue, bToF(e.Initialized),
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
