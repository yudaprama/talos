package validation

import (
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

func TestNormalizeCreateFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		scopes     []string
		metadata   *structpb.Struct
		rateLimit  *talosv2alpha1.RateLimitPolicy
		wantScopes string
		wantMeta   string
		wantQuota  *int64
		wantWindow *int64
		wantErr    bool
	}{
		{
			name:       "empty fields",
			scopes:     nil,
			metadata:   nil,
			rateLimit:  nil,
			wantScopes: "[]",
			wantMeta:   "{}",
			wantQuota:  nil,
			wantWindow: nil,
			wantErr:    false,
		},
		{
			name:       "nil scopes",
			scopes:     nil,
			metadata:   nil,
			rateLimit:  nil,
			wantScopes: "[]",
			wantMeta:   "{}",
			wantErr:    false,
		},
		{
			name:       "empty scopes slice",
			scopes:     []string{},
			metadata:   nil,
			rateLimit:  nil,
			wantScopes: "[]",
			wantMeta:   "{}",
			wantErr:    false,
		},
		{
			name:       "with scopes",
			scopes:     []string{"read", "write"},
			metadata:   nil,
			rateLimit:  nil,
			wantScopes: `["read","write"]`,
			wantMeta:   "{}",
			wantErr:    false,
		},
		{
			name:       "with single scope",
			scopes:     []string{"admin"},
			metadata:   nil,
			rateLimit:  nil,
			wantScopes: `["admin"]`,
			wantMeta:   "{}",
			wantErr:    false,
		},
		{
			name:   "with metadata",
			scopes: nil,
			metadata: func() *structpb.Struct {
				s, _ := structpb.NewStruct(map[string]any{
					"key": "value",
				})
				return s
			}(),
			rateLimit:  nil,
			wantScopes: "[]",
			wantMeta:   `{"key":"value"}`,
			wantErr:    false,
		},
		{
			name:   "with complex metadata",
			scopes: nil,
			metadata: func() *structpb.Struct {
				s, _ := structpb.NewStruct(map[string]any{
					"user":   "john",
					"age":    30,
					"active": true,
					"tags":   []any{"tag1", "tag2"},
					"nested": map[string]any{"foo": "bar"},
				})
				return s
			}(),
			rateLimit:  nil,
			wantScopes: "[]",
			wantMeta:   `{"active":true,"age":30,"nested":{"foo":"bar"},"tags":["tag1","tag2"],"user":"john"}`,
			wantErr:    false,
		},
		{
			name:       "with rate limit policy",
			scopes:     nil,
			metadata:   nil,
			rateLimit:  &talosv2alpha1.RateLimitPolicy{Quota: 100, Window: durationpb.New(60 * time.Second)},
			wantScopes: "[]",
			wantMeta:   "{}",
			wantQuota:  func() *int64 { v := int64(100); return &v }(),
			wantWindow: func() *int64 { v := int64(60); return &v }(),
			wantErr:    false,
		},
		{
			name:   "all fields populated",
			scopes: []string{"read", "write", "admin"},
			metadata: func() *structpb.Struct {
				s, _ := structpb.NewStruct(map[string]any{
					"project": "test",
				})
				return s
			}(),
			rateLimit:  &talosv2alpha1.RateLimitPolicy{Quota: 1000, Window: durationpb.New(3600 * time.Second)},
			wantScopes: `["read","write","admin"]`,
			wantMeta:   `{"project":"test"}`,
			wantQuota:  func() *int64 { v := int64(1000); return &v }(),
			wantWindow: func() *int64 { v := int64(3600); return &v }(),
			wantErr:    false,
		},
		{
			name:       "rate limit with zero quota",
			scopes:     nil,
			metadata:   nil,
			rateLimit:  &talosv2alpha1.RateLimitPolicy{Quota: 0, Window: durationpb.New(60 * time.Second)},
			wantScopes: "[]",
			wantMeta:   "{}",
			wantQuota:  func() *int64 { v := int64(0); return &v }(),
			wantWindow: func() *int64 { v := int64(60); return &v }(),
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizeCreateFields(tt.scopes, tt.metadata, tt.rateLimit, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeCreateFields() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Check scopes
			if string(got.Scopes) != tt.wantScopes {
				t.Errorf("Scopes = %s, want %s", got.Scopes, tt.wantScopes)
			}

			// Verify scopes is valid JSON
			if !json.Valid(got.Scopes) {
				t.Errorf("Scopes is not valid JSON: %s", got.Scopes)
			}

			// Check metadata - compare as parsed JSON to ignore whitespace differences
			var gotMetaMap, wantMetaMap map[string]any
			if err := json.Unmarshal(got.Metadata, &gotMetaMap); err != nil {
				t.Fatalf("Failed to unmarshal got.Metadata: %v", err)
			}
			if err := json.Unmarshal([]byte(tt.wantMeta), &wantMetaMap); err != nil {
				t.Fatalf("Failed to unmarshal wantMeta: %v", err)
			}
			// Simple comparison for test purposes
			gotMetaStr, _ := json.Marshal(gotMetaMap)
			wantMetaStr, _ := json.Marshal(wantMetaMap)
			if string(gotMetaStr) != string(wantMetaStr) {
				t.Errorf("Metadata = %s, want %s", gotMetaStr, wantMetaStr)
			}

			// Verify metadata is valid JSON
			if !json.Valid(got.Metadata) {
				t.Errorf("Metadata is not valid JSON: %s", got.Metadata)
			}

			// Check rate limit quota
			if (got.RateLimitQuota == nil) != (tt.wantQuota == nil) {
				t.Errorf("RateLimitQuota nil mismatch: got %v, want %v", got.RateLimitQuota, tt.wantQuota)
			} else if got.RateLimitQuota != nil && *got.RateLimitQuota != *tt.wantQuota {
				t.Errorf("RateLimitQuota = %d, want %d", *got.RateLimitQuota, *tt.wantQuota)
			}

			// Check rate limit window
			if (got.RateLimitWindow == nil) != (tt.wantWindow == nil) {
				t.Errorf("RateLimitWindow nil mismatch: got %v, want %v", got.RateLimitWindow, tt.wantWindow)
			} else if got.RateLimitWindow != nil && *got.RateLimitWindow != *tt.wantWindow {
				t.Errorf("RateLimitWindow = %d, want %d", *got.RateLimitWindow, *tt.wantWindow)
			}
		})
	}
}

func TestConvertTTL(t *testing.T) {
	t.Parallel()

	defaultTTL := 24 * time.Hour

	tests := []struct {
		name       string
		pbDuration *durationpb.Duration
		defaultTTL time.Duration
		want       time.Duration
	}{
		{
			name:       "nil duration uses default",
			pbDuration: nil,
			defaultTTL: defaultTTL,
			want:       defaultTTL,
		},
		{
			name:       "explicit zero duration means no expiry",
			pbDuration: durationpb.New(0),
			defaultTTL: defaultTTL,
			want:       0,
		},
		{
			name:       "negative duration uses default",
			pbDuration: durationpb.New(-1 * time.Hour),
			defaultTTL: defaultTTL,
			want:       defaultTTL,
		},
		{
			name:       "positive duration uses provided",
			pbDuration: durationpb.New(2 * time.Hour),
			defaultTTL: defaultTTL,
			want:       2 * time.Hour,
		},
		{
			name:       "one minute duration",
			pbDuration: durationpb.New(1 * time.Minute),
			defaultTTL: defaultTTL,
			want:       1 * time.Minute,
		},
		{
			name:       "one week duration",
			pbDuration: durationpb.New(7 * 24 * time.Hour),
			defaultTTL: defaultTTL,
			want:       7 * 24 * time.Hour,
		},
		{
			name:       "zero default TTL with nil duration",
			pbDuration: nil,
			defaultTTL: 0,
			want:       0,
		},
		{
			name:       "zero default TTL with positive duration",
			pbDuration: durationpb.New(5 * time.Hour),
			defaultTTL: 0,
			want:       5 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ConvertTTL(tt.pbDuration, tt.defaultTTL)
			if got != tt.want {
				t.Errorf("ConvertTTL() = %v, want %v", got, tt.want)
			}
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
