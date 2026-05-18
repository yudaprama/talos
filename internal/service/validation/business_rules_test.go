package validation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cockroachdb/errors"

	"github.com/ory/herodot"
)

func TestValidateMetadataSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata json.RawMessage
		wantErr  bool
	}{
		{
			name:     "empty metadata",
			metadata: json.RawMessage(`{}`),
			wantErr:  false,
		},
		{
			name:     "small metadata",
			metadata: json.RawMessage(`{"key":"value"}`),
			wantErr:  false,
		},
		{
			name:     "exactly at limit",
			metadata: json.RawMessage(strings.Repeat("x", MaxMetadataSize)),
			wantErr:  false,
		},
		{
			name:     "one byte over limit",
			metadata: json.RawMessage(strings.Repeat("x", MaxMetadataSize+1)),
			wantErr:  true,
		},
		{
			name:     "significantly over limit",
			metadata: json.RawMessage(strings.Repeat("x", MaxMetadataSize*2)),
			wantErr:  true,
		},
		{
			name:     "nil metadata",
			metadata: nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateMetadataSize(tt.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMetadataSize() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil {
				// Verify error is wrapped with stack trace
				if !errors.HasType(err, (*herodot.DefaultError)(nil)) {
					t.Errorf("Expected herodot.DefaultError, got %T", err)
				}
			}
		})
	}
}

// reviewed - @aeneasr - 2026-03-26
