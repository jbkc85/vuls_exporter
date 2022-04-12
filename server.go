package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

var exporterServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start neo4j_exporter server.",
	Run:   startServer,
}

func startServer(cmd *cobra.Command, args []string) {
	initializeConfig()
	collector := newVulsCollector()
	prometheus.MustRegister(collector)
	router := mux.NewRouter()
	router.HandleFunc("/", healthHandler)
	router.Handle("/metrics", promhttp.Handler())

	log.Fatal(
		http.ListenAndServe(
			":"+flagPort,
			router,
		),
	)
}

type healthReturn struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(healthReturn{
		Status:  "ok",
		Message: "",
	})
}
