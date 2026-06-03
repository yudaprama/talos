package validation

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	talosv2alpha1 "github.com/ory/talos/pkg/api/talos/v2alpha1"
)

func TestValidateAndNormalizeIssueRequest(t *testing.T) {
	t.Parallel()

	defaultTTL := 24 * time.Hour

	tests := []struct {
		name    string
		req     *talosv2alpha1.IssueApiKeyRequest
		wantErr bool
		check   func(t *testing.T, result CreateKeyRequest)
	}{
		{
			name: "basic request with defaults",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-123",
			},
			wantErr: false,
			check: func(t *testing.T, result CreateKeyRequest) {
				t.Helper()
				if result.Name != "test-key" {
					t.Errorf("Name = %s, want test-key", result.Name)
				}
				if result.ActorID != "user-123" {
					t.Errorf("ActorID = %s, want user-123", result.ActorID)
				}
				if result.TTL != defaultTTL {
					t.Errorf("TTL = %v, want %v", result.TTL, defaultTTL)
				}
				if result.ExpiresAt == nil {
					t.Error("ExpiresAt should not be nil")
				}
				if string(result.Fields.Scopes) != "[]" {
					t.Errorf("Scopes = %s, want []", result.Fields.Scopes)
				}
				if string(result.Fields.Metadata) != "{}" {
					t.Errorf("Metadata = %s, want {}", result.Fields.Metadata)
				}
			},
		},
		{
			name: "request with scopes",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-123",
				Scopes:  []string{"read", "write"},
			},
			wantErr: false,
			check: func(t *testing.T, result CreateKeyRequest) {
				t.Helper()
				if string(result.Fields.Scopes) != `["read","write"]` {
					t.Errorf("Scopes = %s, want [\"read\",\"write\"]", result.Fields.Scopes)
				}
			},
		},
		{
			name: "request with metadata",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-123",
				Metadata: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{
						"project": "test-project",
					})
					return s
				}(),
			},
			wantErr: false,
			check: func(t *testing.T, result CreateKeyRequest) {
				t.Helper()
				// Check metadata contains the expected key-value
				metadataStr := string(result.Fields.Metadata)
				if !strings.Contains(metadataStr, "project") || !strings.Contains(metadataStr, "test-project") {
					t.Errorf("Metadata = %s, should contain project=test-project", metadataStr)
				}
			},
		},
		{
			name: "request with custom TTL",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-123",
				Ttl:     durationpb.New(2 * time.Hour),
			},
			wantErr: false,
			check: func(t *testing.T, result CreateKeyRequest) {
				t.Helper()
				if result.TTL != 2*time.Hour {
					t.Errorf("TTL = %v, want 2h", result.TTL)
				}
			},
		},
		{
			name: "request with rate limit policy",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-123",
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  100,
					Window: durationpb.New(60 * time.Second),
				},
			},
			wantErr: false,
			check: func(t *testing.T, result CreateKeyRequest) {
				t.Helper()
				if result.Fields.RateLimitQuota == nil || *result.Fields.RateLimitQuota != 100 {
					t.Errorf("RateLimitQuota = %v, want 100", result.Fields.RateLimitQuota)
				}
				if result.Fields.RateLimitWindow == nil || *result.Fields.RateLimitWindow != 60 {
					t.Errorf("RateLimitWindow = %v, want 60", result.Fields.RateLimitWindow)
				}
			},
		},
		{
			name: "request with zero TTL is rejected (non-expiring keys unsupported)",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-123",
				Ttl:     durationpb.New(0),
			},
			wantErr: true,
		},
		{
			name: "request with oversized metadata",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-123",
				Metadata: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{
						"data": strings.Repeat("x", MaxMetadataSize+1),
					})
					return s
				}(),
			},
			wantErr: true,
		},
		{
			name: "request with all fields",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "full-key",
				ActorId: "user-456",
				Scopes:  []string{"admin"},
				Metadata: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{
						"env": "prod",
					})
					return s
				}(),
				Ttl: durationpb.New(7 * 24 * time.Hour),
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  1000,
					Window: durationpb.New(3600 * time.Second),
				},
			},
			wantErr: false,
			check: func(t *testing.T, result CreateKeyRequest) {
				t.Helper()
				if result.Name != "full-key" {
					t.Errorf("Name = %s, want full-key", result.Name)
				}
				if result.ActorID != "user-456" {
					t.Errorf("ActorID = %s, want user-456", result.ActorID)
				}
				if result.TTL != 7*24*time.Hour {
					t.Errorf("TTL = %v, want 168h", result.TTL)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ValidateAndNormalizeIssueRequest(tt.req, defaultTTL, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAndNormalizeIssueRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestValidateAndNormalizeImportRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *talosv2alpha1.ImportApiKeyRequest
		wantErr bool
		check   func(t *testing.T, result ImportKeyRequest)
	}{
		{
			name: "valid import request",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				Name:    "imported-key",
				ActorId: "user-123",
			},
			wantErr: false,
			check: func(t *testing.T, result ImportKeyRequest) {
				t.Helper()
				if result.RawKey != "sk_test_1234567890" {
					t.Errorf("RawKey = %s, want sk_test_1234567890", result.RawKey)
				}
				if result.Name != "imported-key" {
					t.Errorf("Name = %s, want imported-key", result.Name)
				}
				if result.ActorID != "user-123" {
					t.Errorf("ActorID = %s, want user-123", result.ActorID)
				}
			},
		},
		{
			name: "missing raw_key",
			req: &talosv2alpha1.ImportApiKeyRequest{
				Name:    "imported-key",
				ActorId: "user-123",
			},
			wantErr: true,
		},
		{
			name: "empty raw_key",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "",
				Name:    "imported-key",
				ActorId: "user-123",
			},
			wantErr: true,
		},
		{
			name: "missing name",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				ActorId: "user-123",
			},
			wantErr: true,
		},
		{
			name: "empty name",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				Name:    "",
				ActorId: "user-123",
			},
			wantErr: true,
		},
		{
			name: "missing actor_id",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey: "sk_test_1234567890",
				Name:   "imported-key",
			},
			wantErr: true,
		},
		{
			name: "empty actor_id",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				Name:    "imported-key",
				ActorId: "",
			},
			wantErr: true,
		},
		{
			name: "with scopes",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				Name:    "imported-key",
				ActorId: "user-123",
				Scopes:  []string{"read", "write"},
			},
			wantErr: false,
			check: func(t *testing.T, result ImportKeyRequest) {
				t.Helper()
				if string(result.Fields.Scopes) != `["read","write"]` {
					t.Errorf("Scopes = %s, want [\"read\",\"write\"]", result.Fields.Scopes)
				}
			},
		},
		{
			name: "with metadata",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				Name:    "imported-key",
				ActorId: "user-123",
				Metadata: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{
						"source": "external",
					})
					return s
				}(),
			},
			wantErr: false,
			check: func(t *testing.T, result ImportKeyRequest) {
				t.Helper()
				metadataStr := string(result.Fields.Metadata)
				if !strings.Contains(metadataStr, "source") || !strings.Contains(metadataStr, "external") {
					t.Errorf("Metadata = %s, should contain source=external", metadataStr)
				}
			},
		},
		{
			name: "with TTL",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				Name:    "imported-key",
				ActorId: "user-123",
				Ttl:     durationpb.New(48 * time.Hour),
			},
			wantErr: false,
			check: func(t *testing.T, result ImportKeyRequest) {
				t.Helper()
				if result.ExpiresAt == nil {
					t.Error("ExpiresAt should not be nil")
				}
			},
		},
		{
			name: "with zero TTL is rejected (non-expiring keys unsupported)",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				Name:    "imported-key",
				ActorId: "user-123",
				Ttl:     durationpb.New(0),
			},
			wantErr: true,
		},
		{
			name: "with rate limit",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				Name:    "imported-key",
				ActorId: "user-123",
				RateLimitPolicy: &talosv2alpha1.RateLimitPolicy{
					Quota:  500,
					Window: durationpb.New(300 * time.Second),
				},
			},
			wantErr: false,
			check: func(t *testing.T, result ImportKeyRequest) {
				t.Helper()
				if result.Fields.RateLimitQuota == nil || *result.Fields.RateLimitQuota != 500 {
					t.Errorf("RateLimitQuota = %v, want 500", result.Fields.RateLimitQuota)
				}
			},
		},
		{
			name: "with oversized metadata",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_1234567890",
				Name:    "imported-key",
				ActorId: "user-123",
				Metadata: func() *structpb.Struct {
					s, _ := structpb.NewStruct(map[string]any{
						"data": strings.Repeat("x", MaxMetadataSize+1),
					})
					return s
				}(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ValidateAndNormalizeImportRequest(tt.req, 24*time.Hour, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAndNormalizeImportRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestValidateAndNormalizeIssueRequest_MaxTTL(t *testing.T) {
	t.Parallel()

	defaultTTL := 24 * time.Hour
	maxTTL := 48 * time.Hour

	tests := []struct {
		name    string
		req     *talosv2alpha1.IssueApiKeyRequest
		maxTTL  time.Duration
		wantErr bool
		check   func(t *testing.T, result CreateKeyRequest)
	}{
		{
			name: "TTL equals maxTTL (boundary)",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-1",
				Ttl:     durationpb.New(maxTTL),
			},
			maxTTL:  maxTTL,
			wantErr: false,
			check: func(t *testing.T, result CreateKeyRequest) {
				t.Helper()
				if result.TTL != maxTTL {
					t.Errorf("TTL = %v, want %v", result.TTL, maxTTL)
				}
			},
		},
		{
			name: "TTL exceeds maxTTL is rejected",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-1",
				Ttl:     durationpb.New(maxTTL + time.Hour),
			},
			maxTTL:  maxTTL,
			wantErr: true,
		},
		{
			name: "zero TTL is rejected when maxTTL is set",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-1",
				Ttl:     durationpb.New(0),
			},
			maxTTL:  maxTTL,
			wantErr: true,
		},
		{
			name: "nil TTL with defaultTTL over maxTTL is rejected",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-1",
			},
			maxTTL:  2 * time.Hour,
			wantErr: true,
		},
		{
			name: "maxTTL disabled (zero) accepts any TTL",
			req: &talosv2alpha1.IssueApiKeyRequest{
				Name:    "test-key",
				ActorId: "user-1",
				Ttl:     durationpb.New(8760 * time.Hour), // 1 year
			},
			maxTTL:  0,
			wantErr: false,
			check: func(t *testing.T, result CreateKeyRequest) {
				t.Helper()
				if result.TTL != 8760*time.Hour {
					t.Errorf("TTL = %v, want 8760h", result.TTL)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ValidateAndNormalizeIssueRequest(tt.req, defaultTTL, tt.maxTTL)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAndNormalizeIssueRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestValidateAndNormalizeImportRequest_MaxTTL(t *testing.T) {
	t.Parallel()

	defaultTTL := 24 * time.Hour
	maxTTL := 48 * time.Hour

	tests := []struct {
		name    string
		req     *talosv2alpha1.ImportApiKeyRequest
		maxTTL  time.Duration
		wantErr bool
		check   func(t *testing.T, result ImportKeyRequest)
	}{
		{
			name: "TTL equals maxTTL (boundary)",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_boundary",
				Name:    "imported-key",
				ActorId: "user-1",
				Ttl:     durationpb.New(maxTTL),
			},
			maxTTL:  maxTTL,
			wantErr: false,
			check: func(t *testing.T, result ImportKeyRequest) {
				t.Helper()
				if result.ExpiresAt == nil {
					t.Error("ExpiresAt should not be nil")
				}
			},
		},
		{
			name: "TTL exceeds maxTTL is rejected",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_over",
				Name:    "imported-key",
				ActorId: "user-1",
				Ttl:     durationpb.New(maxTTL + time.Hour),
			},
			maxTTL:  maxTTL,
			wantErr: true,
		},
		{
			name: "zero TTL is rejected when maxTTL is set",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_noexpiry",
				Name:    "imported-key",
				ActorId: "user-1",
				Ttl:     durationpb.New(0),
			},
			maxTTL:  maxTTL,
			wantErr: true,
		},
		{
			name: "maxTTL disabled (zero) accepts any TTL",
			req: &talosv2alpha1.ImportApiKeyRequest{
				RawKey:  "sk_test_any",
				Name:    "imported-key",
				ActorId: "user-1",
				Ttl:     durationpb.New(8760 * time.Hour), // 1 year
			},
			maxTTL:  0,
			wantErr: false,
			check: func(t *testing.T, result ImportKeyRequest) {
				t.Helper()
				if result.ExpiresAt == nil {
					t.Error("ExpiresAt should not be nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ValidateAndNormalizeImportRequest(tt.req, defaultTTL, tt.maxTTL)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAndNormalizeImportRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
