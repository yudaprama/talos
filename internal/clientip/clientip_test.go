package clientip

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithRequestInfo(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.1:12345"
	r.Header.Set("Cf-Connecting-Ip", "1.2.3.4")
	r.Header.Set("True-Client-Ip", "5.6.7.8")
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	r.Header.Set("X-Real-Ip", "172.16.0.1")

	ctx := WithRequestInfo(context.Background(), r)
	info, ok := ctx.Value(requestInfoKey).(RequestInfo)
	if !ok {
		t.Fatal("expected RequestInfo in context")
	}
	if info.RemoteAddr != "192.168.1.1" {
		t.Errorf("RemoteAddr = %q, want %q", info.RemoteAddr, "192.168.1.1")
	}
	if info.CFConnectingIP != "1.2.3.4" {
		t.Errorf("CFConnectingIP = %q, want %q", info.CFConnectingIP, "1.2.3.4")
	}
	if info.TrueClientIP != "5.6.7.8" {
		t.Errorf("TrueClientIP = %q, want %q", info.TrueClientIP, "5.6.7.8")
	}
	if info.XForwardedFor != "10.0.0.1, 10.0.0.2" {
		t.Errorf("XForwardedFor = %q, want %q", info.XForwardedFor, "10.0.0.1, 10.0.0.2")
	}
	if info.XRealIP != "172.16.0.1" {
		t.Errorf("XRealIP = %q, want %q", info.XRealIP, "172.16.0.1")
	}
}

func TestResolveClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		info   RequestInfo
		source int32
		want   string
	}{
		{
			name:   "unspecified uses RemoteAddr",
			info:   RequestInfo{RemoteAddr: "192.168.1.1"},
			source: 0,
			want:   "192.168.1.1",
		},
		{
			name:   "remote addr source",
			info:   RequestInfo{RemoteAddr: "10.0.0.1", CFConnectingIP: "1.2.3.4"},
			source: 1,
			want:   "10.0.0.1",
		},
		{
			name:   "cloudflare CF-Connecting-IP",
			info:   RequestInfo{RemoteAddr: "10.0.0.1", CFConnectingIP: "1.2.3.4"},
			source: 2,
			want:   "1.2.3.4",
		},
		{
			name:   "cloudflare falls back to RemoteAddr",
			info:   RequestInfo{RemoteAddr: "10.0.0.1"},
			source: 2,
			want:   "10.0.0.1",
		},
		{
			name:   "X-Forwarded-For leftmost IP",
			info:   RequestInfo{RemoteAddr: "10.0.0.1", XForwardedFor: "1.1.1.1, 2.2.2.2, 3.3.3.3"},
			source: 3,
			want:   "1.1.1.1",
		},
		{
			name:   "X-Forwarded-For single IP",
			info:   RequestInfo{RemoteAddr: "10.0.0.1", XForwardedFor: "1.1.1.1"},
			source: 3,
			want:   "1.1.1.1",
		},
		{
			name:   "X-Forwarded-For falls back to RemoteAddr",
			info:   RequestInfo{RemoteAddr: "10.0.0.1"},
			source: 3,
			want:   "10.0.0.1",
		},
		{
			name:   "X-Real-IP",
			info:   RequestInfo{RemoteAddr: "10.0.0.1", XRealIP: "172.16.0.1"},
			source: 4,
			want:   "172.16.0.1",
		},
		{
			name:   "True-Client-IP",
			info:   RequestInfo{RemoteAddr: "10.0.0.1", TrueClientIP: "5.6.7.8"},
			source: 5,
			want:   "5.6.7.8",
		},
		{
			name:   "IPv6 address",
			info:   RequestInfo{RemoteAddr: "::1"},
			source: 0,
			want:   "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.WithValue(context.Background(), requestInfoKey, tt.info)
			got := ResolveClientIP(ctx, tt.source)
			want := net.ParseIP(tt.want)
			if !got.Equal(want) {
				t.Errorf("ResolveClientIP() = %v, want %v", got, want)
			}
		})
	}
}

func TestResolveClientIP_NoContext(t *testing.T) {
	t.Parallel()
	got := ResolveClientIP(context.Background(), 0)
	if got != nil {
		t.Errorf("expected nil IP without context, got %v", got)
	}
}

func TestValidateCIDRs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
	}{
		{name: "empty", cidrs: nil, wantErr: false},
		{name: "valid IPv4", cidrs: []string{"10.0.0.0/8", "192.168.1.0/24"}, wantErr: false},
		{name: "valid IPv6", cidrs: []string{"2001:db8::/32", "::1/128"}, wantErr: false},
		{name: "valid mixed", cidrs: []string{"10.0.0.0/8", "2001:db8::/32"}, wantErr: false},
		{name: "invalid CIDR", cidrs: []string{"10.0.0.0/8", "not-a-cidr"}, wantErr: true},
		{name: "bare IP", cidrs: []string{"10.0.0.1"}, wantErr: true},
		{name: "empty string", cidrs: []string{""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateCIDRs(tt.cidrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCIDRs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		ip    string
		cidrs []string
		want  bool
	}{
		{name: "match in range", ip: "10.0.0.5", cidrs: []string{"10.0.0.0/8"}, want: true},
		{name: "no match", ip: "192.168.1.1", cidrs: []string{"10.0.0.0/8"}, want: false},
		{name: "match second CIDR", ip: "192.168.1.1", cidrs: []string{"10.0.0.0/8", "192.168.0.0/16"}, want: true},
		{name: "exact match /32", ip: "1.2.3.4", cidrs: []string{"1.2.3.4/32"}, want: true},
		{name: "IPv6 match", ip: "2001:db8::1", cidrs: []string{"2001:db8::/32"}, want: true},
		{name: "IPv6 no match", ip: "2001:db9::1", cidrs: []string{"2001:db8::/32"}, want: false},
		{name: "empty CIDRs", ip: "10.0.0.1", cidrs: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			got, err := CheckIP(ip, tt.cidrs)
			if err != nil {
				t.Fatalf("CheckIP() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("CheckIP(%s, %v) = %v, want %v", tt.ip, tt.cidrs, got, tt.want)
			}
		})
	}
}

func TestUnmarshalCIDRs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
		want int
	}{
		{name: "nil", raw: nil, want: 0},
		{name: "empty array", raw: json.RawMessage("[]"), want: 0},
		{name: "one entry", raw: json.RawMessage(`["10.0.0.0/8"]`), want: 1},
		{name: "two entries", raw: json.RawMessage(`["10.0.0.0/8","192.168.0.0/16"]`), want: 2},
		{name: "invalid json", raw: json.RawMessage("not-json"), want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := UnmarshalCIDRs(tt.raw)
			if len(got) != tt.want {
				t.Errorf("UnmarshalCIDRs(%q) len = %d, want %d", string(tt.raw), len(got), tt.want)
			}
		})
	}
}

func TestHasRestriction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{"nil", nil, false},
		{"empty array", json.RawMessage("[]"), false},
		{"null from JSON roundtrip", json.RawMessage("null"), false},
		{"non-empty", json.RawMessage(`["10.0.0.0/8"]`), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := HasRestriction(tt.raw); got != tt.want {
				t.Errorf("HasRestriction(%q) = %v, want %v", string(tt.raw), got, tt.want)
			}
		})
	}
}

// TODO add more advesarial tets

// reviewed - @aeneasr - 2026-03-25
