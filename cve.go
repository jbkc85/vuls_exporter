package main

import "github.com/prometheus/client_golang/prometheus"

type cve struct {
	AffectedPackages []cveAffectedPackages   `json:"affectedPackages"`
	CVEID            string                  `json:"cveID"`
	Confidence       []cveConfidences        `json:"confidences"`
	Contents         map[string][]cveContent `json:"cveContents"`
}

type cveConfidences struct {
	DetectionMethod string `json:"detectionMethod"`
	Score           int    `json:"score"`
}

type cveAffectedPackages struct {
	FixState    string `json:"fixState"`
	Name        string `json:"name"`
	NotFixedYet bool   `json:"notFixedYet"`
}

type cveContent struct {
	CVEID         string  `json:"cveID"`
	CVSS2Score    float32 `json:"cvss2Score"`
	CVSS2Severity string  `json:"cvss2Severity"`
	CVSS3Score    float32 `json:"cvss3Score"`
	CVSS3Severity string  `json:"cvss3Severity"`
	Title         string  `json:"title"`
	Type          string  `json:"type"`
}

var (
	cveContentsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "vuls",
			Subsystem: "cve",
			Name:      "contents",
			Help:      "CVE Contents found on the matched group or scanned hosts.",
		}, []string{"name", "database", "severity", "serverName"},
	)
)

func (cc *cveContent) returnCVSSeverity() string {
	var score float32
	if cc.CVSS3Score != 0 {
		score = cc.CVSS3Score
	} else {
		score = cc.CVSS2Score
	}

	switch {
	case score == 0:
		return "none"
	case score > 0 && score < 4:
		return "low"
	case score > 3.9 && score < 7:
		return "medium"
	case score > 6.9 && score < 9:
		return "high"
	default:
		return "critical"
	}
}

func registerCVEMetrics() {
	prometheus.MustRegister(cveContentsGauge)
}
