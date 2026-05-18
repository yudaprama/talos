// Package clientip provides context helpers for extracting and resolving client IP addresses.
// IP-related HTTP headers are captured into context by middleware and resolved at verification
// time using the per-key ClientIPSource configuration.
package clientip

import (
	"cmp"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

type contextKey int

const requestInfoKey contextKey = iota

// RequestInfo holds all IP-related request headers for deferred resolution.
// Captured once by middleware; resolved per-key at verification time.
type RequestInfo struct {
	RemoteAddr     string
	CFConnectingIP string
	TrueClientIP   string
	XForwardedFor  string
	XRealIP        string
}

// WithRequestInfo captures IP-related headers from the request into context.
// Should be called early in the middleware chain before gRPC-Gateway processing.
func WithRequestInfo(ctx context.Context, r *http.Request) context.Context {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	info := RequestInfo{
		RemoteAddr: host,

		// These headers are captured here but only used when the operator explicitly sets
		// client_ip_source to one of the header-based sources (2–5). The default source
		// (UNSPECIFIED/0) always uses RemoteAddr and is unaffected by these values.
		//
		// When a header-based source is configured, Talos MUST run behind a trusted reverse
		// proxy that strips or overwrites the header before it reaches the service. Without
		// this, clients can spoof their IP address.
		CFConnectingIP: r.Header.Get("Cf-Connecting-Ip"),
		TrueClientIP:   r.Header.Get("True-Client-Ip"),
		XForwardedFor:  r.Header.Get("X-Forwarded-For"),
		XRealIP:        r.Header.Get("X-Real-Ip"),
	}
	return context.WithValue(ctx, requestInfoKey, info)
}

// ResolveClientIP extracts the client IP using the specified source strategy.
// Falls back to RemoteAddr if the chosen header is empty.
// The source parameter maps to the ClientIPSource proto enum values.
func ResolveClientIP(ctx context.Context, source int32) net.IP {
	info, ok := ctx.Value(requestInfoKey).(RequestInfo)
	if !ok {
		return nil
	}

	var raw string
	switch source {
	case 1: // CLIENT_IP_SOURCE_REMOTE_ADDR
		raw = info.RemoteAddr
	case 2: // CLIENT_IP_SOURCE_CF_CONNECTING_IP
		raw = cmp.Or(info.CFConnectingIP, info.RemoteAddr)
	case 3: // CLIENT_IP_SOURCE_X_FORWARDED_FOR
		raw = cmp.Or(firstFromXFF(info.XForwardedFor), info.RemoteAddr)
	case 4: // CLIENT_IP_SOURCE_X_REAL_IP
		raw = cmp.Or(info.XRealIP, info.RemoteAddr)
	case 5: // CLIENT_IP_SOURCE_TRUE_CLIENT_IP
		raw = cmp.Or(info.TrueClientIP, info.RemoteAddr)
	default: // CLIENT_IP_SOURCE_UNSPECIFIED (0) — use remote address
		raw = info.RemoteAddr
	}

	return net.ParseIP(strings.TrimSpace(raw))
}

// firstFromXFF extracts the leftmost (client) IP from an X-Forwarded-For header value.
// X-Forwarded-For format: "client, proxy1, proxy2"
func firstFromXFF(xff string) string {
	if xff == "" {
		return ""
	}
	if i := strings.IndexByte(xff, ','); i > 0 {
		return strings.TrimSpace(xff[:i])
	}
	return strings.TrimSpace(xff)
}

// ValidateCIDRs validates that each string is a valid CIDR notation.
// Returns an error describing the first invalid entry.
func ValidateCIDRs(cidrs []string) error {
	for _, cidr := range cidrs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return err
		}
	}
	return nil
}

// CheckIP returns true if ip falls within any of the provided CIDR ranges.
func CheckIP(ip net.IP, cidrs []string) (bool, error) {
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return false, err
		}
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// UnmarshalCIDRs parses a JSON array into a slice of CIDR strings.
// Returns nil for empty or "[]" input.
func UnmarshalCIDRs(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "[]" {
		return nil
	}
	var cidrs []string
	if err := json.Unmarshal(raw, &cidrs); err != nil {
		return nil
	}
	return cidrs
}

// HasRestriction returns true if the allowed CIDRs represents a non-empty restriction.
// Treats nil, empty, "[]", and "null" as no restriction. The "null" case occurs when
// a nil json.RawMessage survives a JSON marshal/unmarshal roundtrip (e.g., cache).
func HasRestriction(allowedCIDRs json.RawMessage) bool {
	s := string(allowedCIDRs)
	return len(allowedCIDRs) > 0 && s != "[]" && s != "null"
}
