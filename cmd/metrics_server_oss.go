//go:build !commercial

package cmd

import (
	"net/http"

	"github.com/ory/x/prometheusx"
)

// registerMetricsRoute registers the Prometheus scrape endpoint on the metrics
// HTTP server. Exposes the default Prometheus registry (Go runtime + Talos
// collectors registered via the internal/metrics blank import) at
// /metrics/prometheus for Alloy to scrape.
func registerMetricsRoute(mux *http.ServeMux) {
	prometheusx.SetMuxRoutes(mux)
}
