package main

import (
	"log"

	"github.com/spf13/cobra"
)

var vulsExporter = &cobra.Command{
	Use:           "vuls_exporter",
	Short:         "exporter to provide an interface between Vuls reports and Prometheus.",
	Long:          `vuls_exporter exposes generated 'reports' as metrics to Prometheus for aggregation and compact viewing purposes.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func main() {
	if err := vulsExporter.Execute(); err != nil {
		log.Fatal(err)
	}
}
