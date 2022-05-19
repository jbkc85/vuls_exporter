package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

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
)

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

type severityResult struct {
	CVEs      int `json:"cves"`
	OpenCVEs  int `json:"open_cves"`
	FixedCVEs int `json:"fixed_cves"`
}

func (r *results) aggregateSeverities() map[string]map[string]severityResult {
	severityResults := make(map[string]map[string]severityResult)
	for _, cveMeta := range r.CVEs {
		for database, contents := range cveMeta.Contents {
			cveFixed := 0
			cveNotFixed := 0
			if _, ok := severityResults[database]; !ok {
				severityResults[database] = make(map[string]severityResult)
			}
			if returnFixState(cveMeta.AffectedPackages) {
				cveFixed++
			} else {
				cveNotFixed++
			}
			severity := contents[0].returnCVSSeverity()
			if _, ok := severityResults[database][severity]; !ok {
				severityResults[database][severity] = severityResult{
					CVEs:      1,
					FixedCVEs: cveFixed,
					OpenCVEs:  cveNotFixed,
				}
			} else {
				newResults := severityResults[database][severity]
				newResults.CVEs++
				newResults.FixedCVEs = newResults.FixedCVEs + cveFixed
				newResults.OpenCVEs = newResults.OpenCVEs + cveNotFixed
				severityResults[database][severity] = newResults
			}
		}
	}
	return severityResults
}
