package main

import (
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const PROMETHEUS_NAMESPACE = "vuls"

type vulsCollector struct {
	cveContents       *prometheus.Desc
	resultLastScanned *prometheus.Desc
}

func newVulsCollector() *vulsCollector {
	return &vulsCollector{
		cveContents: prometheus.NewDesc(
			prometheus.BuildFQName(PROMETHEUS_NAMESPACE, "cve", "contents"),
			"Aggregated Findings from CVE Contents exported by Vuls",
			[]string{"database", "severity", "serverName"}, nil,
		),
		resultLastScanned: prometheus.NewDesc(
			prometheus.BuildFQName(PROMETHEUS_NAMESPACE, "server", "last_scanned"),
			"Gauge to provide a timestamp on the server results Last Scanned by Vuls",
			[]string{"serverName"}, nil,
		),
	}
}

func (collector *vulsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.cveContents
	ch <- collector.resultLastScanned
}

func (collector *vulsCollector) Collect(ch chan<- prometheus.Metric) {
	vulsResults := parseResults()

	for server, results := range vulsResults {
		timestamp, _ := time.Parse(time.RFC3339Nano, results.ScannedAt)
		ch <- prometheus.MustNewConstMetric(
			collector.resultLastScanned,
			prometheus.GaugeValue,
			float64(timestamp.Unix()),
			server,
		)

		databaseSeverities := results.aggregateSeverities()

		for database, severities := range databaseSeverities {
			_, none := severities["none"]
			if len(severities) == 1 && none {
				if flagVerbose {
					log.Printf("[TRACE] no severities found for %s - skipping.", database)
				}
				continue
			}
			for severity, findings := range severities {
				ch <- prometheus.MustNewConstMetric(
					collector.cveContents,
					prometheus.GaugeValue,
					float64(findings),
					database, severity, server,
				)
			}
		}
	}
}
