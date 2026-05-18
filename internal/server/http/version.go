package http

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ory-corp/talos/internal/contextx"
	"github.com/ory-corp/talos/internal/version"
)

type versionResponse struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	BuildTime  string `json:"build_time"`
	ConfigHash string `json:"config_hash"`
}

func (s *GatewayServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Raw() returns map[string]any from koanf. encoding/json sorts
	// map keys deterministically, so the output is stable.
	rawConfig := map[string]any{}
	if underlying := s.config.UnderlyingProvider(ctx); underlying != nil {
		rawConfig = underlying.Raw()
	}
	configJSON, err := json.Marshal(rawConfig)
	if err != nil {
		http.Error(w, "marshal config", http.StatusInternalServerError)
		return
	}

	// Build hash input: hostname + ":" + tenantID + ":" + configJSON
	// Only trust X-Forwarded-Host when explicitly configured to prevent header-injection.
	hostname := s.effectiveHost(ctx, r)
	tenantID := contextx.NetworkIDFromContext(ctx).String()

	hashInput := fmt.Sprintf("%s:%s:%s", hostname, tenantID, configJSON)
	hash := sha256.Sum256([]byte(hashInput))

	resp := versionResponse{
		Version:    version.Version,
		Commit:     version.Commit,
		BuildTime:  version.BuildTime,
		ConfigHash: fmt.Sprintf("%x", hash),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
	}
}

// reviewed - @aeneasr - 2026-03-26
