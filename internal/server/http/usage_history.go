// Package http provides gRPC-Gateway HTTP/REST server functionality.
package http

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// usageHistoryRecord is the JSON shape returned by handleSelfUsageHistory.
type usageHistoryRecord struct {
	Model      string    `json:"model"`
	CostMicros int64     `json:"costMicros"`
	CreatedAt  time.Time `json:"createdAt"`
}

// handleSelfUsageHistory serves GET /v2alpha1/self/usageHistory.
//
// Trust model: X-User-Id must be injected by the trusted edge (Oathkeeper from
// a Kratos session). A missing or empty header → 401. The meter is queried for
// up to `limit` records (query param, default 50, max 100).
func (s *GatewayServer) handleSelfUsageHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeUsageHistoryError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.meter == nil {
		writeUsageHistoryError(w, http.StatusNotImplemented, "usage history not available")
		return
	}

	actorID := strings.TrimSpace(r.Header.Get("X-User-Id"))
	if actorID == "" {
		writeUsageHistoryError(w, http.StatusUnauthorized, "X-User-Id is required (deploy behind an edge that injects it from a Kratos session)")
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if n, err := strconv.Atoi(lStr); err == nil && n > 0 {
			limit = n
		}
	}

	records, err := s.meter.ListUsage(r.Context(), actorID, limit)
	if err != nil {
		writeUsageHistoryError(w, http.StatusInternalServerError, "failed to retrieve usage history")
		return
	}

	out := make([]usageHistoryRecord, len(records))
	for i, rec := range records {
		out[i] = usageHistoryRecord{
			Model:      rec.Model,
			CostMicros: rec.CostMicros,
			CreatedAt:  rec.CreatedAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"records": out})
}

func writeUsageHistoryError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": message})
}
