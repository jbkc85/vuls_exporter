package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
)

type results struct {
	CVEs       map[string]cve `json:"scannedCves"`
	ReportedAt string         `json:"reportedAt"`
	ScannedAt  string         `json:"scannedAt"`
	ServerName string         `json:"serverName"`
}

var (
	exporterParseCommand = &cobra.Command{
		Use:   "parse",
		Short: "Parse results from Vuls.",
		Run:   testParseResults,
	}

	resultLastScannedGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "vuls",
			Subsystem: "server",
			Name:      "last_scanned",
			Help:      "Gauge to provide a timestamp on the server results Last Scanned.",
		}, []string{"serverName"},
	)
	// server results metrics:
	// - last scanned

)

func registerResultsMetrics() {
	prometheus.MustRegister(resultLastScannedGauge)
}

func testParseResults(cmd *cobra.Command, args []string) {
	initializeConfig()
	log.Printf("%v", parseResults())
}

func parseResults() map[string]results {
	parsedResults := make(map[string]results)

	matches, err := filepath.Glob(flagResultsPath + "/*.json")
	if err != nil {
		log.Fatalf("[FATAL] Unable to parse results directory for JSON files.  Error: %s", err)
	}

	log.Printf("%s | %v", flagResultsPath, matches)

	for _, match := range matches {
		var res results
		resultsFile, err := os.Open(match)
		if err != nil {
			log.Fatal(err)
		}
		defer resultsFile.Close()

		reportBytes, _ := ioutil.ReadAll(resultsFile)
		err = json.Unmarshal(reportBytes, &res)
		if err != nil {
			log.Fatal(err)
		}
		//		timestamp, _ := time.Parse(time.RFC3339Nano, res.ScannedAt)
		//		resultLastScannedGauge.WithLabelValues(
		//			res.ServerName,
		//		).Set(float64(timestamp.Unix()))
		parsedResults[res.ServerName] = res
	}
	return parsedResults
}

func (r *results) aggregateSeverities() map[string]map[string]int {
	severityResults := make(map[string]map[string]int)
	for _, cveMeta := range r.CVEs {
		for database, contents := range cveMeta.Contents {
			if _, ok := severityResults[database]; !ok {
				severityResults[database] = make(map[string]int)
			}
			severity := contents[0].returnCVSSeverity()
			if _, ok := severityResults[database][severity]; !ok {
				severityResults[database][severity] = 1
			} else {
				severityResults[database][severity] = severityResults[database][severity] + 1
			}
		}
	}
	return severityResults
}

func (r *results) resultMetrics() {
	for cveName, cveMeta := range r.CVEs {
		for database, content := range cveMeta.Contents {
			cveContentsGauge.WithLabelValues(
				cveName,
				database,
				content[0].returnCVSSeverity(),
				r.ServerName,
			).Set(1)
		}
	}
}
