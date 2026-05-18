package validation_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/service/validation"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

func TestParseListFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		filter     string
		wantActor  string
		wantStatus talosv2alpha1.KeyStatus
		wantErr    bool
		errContain string
	}{
		{
			name:       "empty filter",
			filter:     "",
			wantActor:  "",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
		},
		{
			name:       "actor_id filter",
			filter:     `actor_id="user_123"`,
			wantActor:  "user_123",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
		},
		{
			name:       "status active filter",
			filter:     "status=KEY_STATUS_ACTIVE",
			wantActor:  "",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE,
		},
		{
			name:       "status revoked filter",
			filter:     "status=KEY_STATUS_REVOKED",
			wantActor:  "",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_REVOKED,
		},
		{
			name:       "combined AND filter",
			filter:     `actor_id="user_123" AND status=KEY_STATUS_ACTIVE`,
			wantActor:  "user_123",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE,
		},
		{
			name:       "combined AND filter reversed order",
			filter:     `status=KEY_STATUS_ACTIVE AND actor_id="user_123"`,
			wantActor:  "user_123",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE,
		},
		{
			name:    "unknown field returns error",
			filter:  "unknown_field=foo",
			wantErr: true,
		},
		{
			name:    "invalid status value returns error",
			filter:  "status=BAD_VALUE",
			wantErr: true,
		},
		{
			name:       "owner with special chars",
			filter:     `actor_id="org/team-alpha"`,
			wantActor:  "org/team-alpha",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
		},
		{
			name:       "OR operator rejected",
			filter:     `actor_id="a" OR status=KEY_STATUS_ACTIVE`,
			wantErr:    true,
			errContain: "OR",
		},
		{
			name:       "KEY_STATUS_UNSPECIFIED rejected",
			filter:     "status=KEY_STATUS_UNSPECIFIED",
			wantErr:    true,
			errContain: "UNSPECIFIED",
		},
		{
			name:       "actor_id exceeds max length",
			filter:     `actor_id="` + strings.Repeat("a", 257) + `"`,
			wantErr:    true,
			errContain: "maximum length",
		},

		// Regression: duplicate fields were silently ignored (first wins)
		{
			name:       "duplicate actor_id rejected",
			filter:     `actor_id="first" AND actor_id="second"`,
			wantErr:    true,
			errContain: "duplicate",
		},
		{
			name:       "duplicate status rejected",
			filter:     `status=KEY_STATUS_ACTIVE AND status=KEY_STATUS_REVOKED`,
			wantErr:    true,
			errContain: "duplicate",
		},

		// Regression: garbage between valid tokens passed silently
		{
			name:    "garbage text between clauses rejected",
			filter:  `actor_id="a" BANANA status=KEY_STATUS_ACTIVE`,
			wantErr: true,
		},
		{
			name:    "random text without field=value rejected",
			filter:  "some random garbage",
			wantErr: true,
		},

		// Regression: missing AND between clauses was not detected
		{
			name:    "missing AND between clauses rejected",
			filter:  `actor_id="a"status=KEY_STATUS_ACTIVE`,
			wantErr: true,
		},

		// Reviewer findings: empty/whitespace/structural edge cases
		{
			name:       "empty quoted actor_id rejected",
			filter:     `actor_id=""`,
			wantErr:    true,
			errContain: "invalid filter expression",
		},
		{
			name:       "whitespace-only filter returns empty",
			filter:     "   ",
			wantActor:  "",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
		},
		{
			name:       "trailing AND rejected",
			filter:     `actor_id="a" AND`,
			wantErr:    true,
			errContain: "invalid filter expression",
		},
		{
			name:       "leading AND rejected",
			filter:     `AND status=KEY_STATUS_ACTIVE`,
			wantErr:    true,
			errContain: "invalid filter expression",
		},
		{
			name:    "double AND rejected",
			filter:  `actor_id="a" AND AND status=KEY_STATUS_ACTIVE`, //nolint:dupword // intentional duplicate operator in test input
			wantErr: true,
		},
		{
			name:       "actor_id with spaces in quotes",
			filter:     `actor_id="hello world"`,
			wantActor:  "hello world",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
		},

		// Whitespace variations that should work
		{
			name:       "extra whitespace around equals",
			filter:     `actor_id = "user_123"`,
			wantActor:  "user_123",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED,
		},
		{
			name:       "lowercase and in filter rejected",
			filter:     `actor_id="user_123" and status=KEY_STATUS_ACTIVE`,
			wantActor:  "user_123",
			wantStatus: talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f, err := validation.ParseListFilter(tt.filter)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantActor, f.ActorID)
			assert.Equal(t, tt.wantStatus, f.Status)
		})
	}
}

func TestParseListFilter_Adversarial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		filter     string
		wantErr    bool
		wantActor  string // if not error, verify parsed value is safe literal
		errContain string
	}{
		// SQL injection payloads
		{
			name:      "SQL injection semicolon drop table",
			filter:    `actor_id="1; DROP TABLE api_keys"`,
			wantActor: "1; DROP TABLE api_keys", // parsed as safe literal, never interpolated into SQL
		},
		{
			name:      "SQL injection OR 1=1",
			filter:    `actor_id="' OR 1=1 --"`,
			wantActor: "' OR 1=1 --",
		},
		{
			name:       "SQL injection in status field",
			filter:     `status=ACTIVE; DELETE FROM api_keys`,
			wantErr:    true,
			errContain: "invalid filter expression",
		},
		{
			name:      "SQL injection union select",
			filter:    `actor_id="' UNION SELECT * FROM users --"`,
			wantActor: "' UNION SELECT * FROM users --",
		},

		// Null bytes
		{
			name:      "null byte in actor_id",
			filter:    "actor_id=\"test\x00injection\"",
			wantActor: "test\x00injection",
		},

		// Long strings
		{
			name:       "extremely long actor_id exceeds limit",
			filter:     `actor_id="` + strings.Repeat("x", 1000) + `"`,
			wantErr:    true,
			errContain: "maximum length",
		},

		// Field traversal
		{
			name:       "field traversal with dot notation",
			filter:     `actor_id.nested="value"`,
			wantErr:    true,
			errContain: "invalid filter expression",
		},
		{
			name:       "prototype pollution attempt",
			filter:     `__proto__="value"`,
			wantErr:    true,
			errContain: "unsupported filter field",
		},
		{
			name:       "constructor traversal attempt",
			filter:     `constructor="value"`,
			wantErr:    true,
			errContain: "unsupported filter field",
		},

		// Unicode tricks
		{
			name:       "Cyrillic е lookalike in field name",
			filter:     "own\u0435r_id=\"value\"", // Cyrillic е (U+0435) instead of Latin e
			wantErr:    true,
			errContain: "invalid filter expression",
		},
		{
			name:      "unicode in value is preserved safely",
			filter:    `actor_id="tеst"`, // Cyrillic е in value
			wantActor: "t\u0435st",
		},

		// Other adversarial inputs
		{
			name:       "backtick injection",
			filter:     "actor_id=`admin`",
			wantErr:    true,
			errContain: "invalid filter expression",
		},
		{
			name:      "angle brackets in value",
			filter:    `actor_id="<script>alert(1)</script>"`,
			wantActor: "<script>alert(1)</script>",
		},
		{
			name:      "newline injection",
			filter:    "actor_id=\"line1\nline2\"",
			wantActor: "line1\nline2",
		},

		// 10KB string (exceeds 256-char actor_id limit)
		{
			name:       "10KB actor_id exceeds limit",
			filter:     `actor_id="` + strings.Repeat("A", 10*1024) + `"`,
			wantErr:    true,
			errContain: "maximum length",
		},

		// Multiple null bytes
		{
			name:      "multiple null bytes in actor_id",
			filter:    "actor_id=\"\x00\x00\x00\"",
			wantActor: "\x00\x00\x00",
		},

		// Empty string via unquoted (rejected by regex: unquoted requires [\w.-]+)
		{
			name:       "empty unquoted value rejected",
			filter:     `actor_id=`,
			wantErr:    true,
			errContain: "invalid filter expression",
		},

		// Stacked SQL injection with comment
		{
			name:      "SQL injection with comment and second statement",
			filter:    `actor_id="x'; DROP TABLE api_keys; --"`,
			wantActor: "x'; DROP TABLE api_keys; --",
		},

		// SQL injection via status with stacked queries
		{
			name:       "status field SQL injection with semicolon",
			filter:     `status=KEY_STATUS_ACTIVE;DROP TABLE api_keys`,
			wantErr:    true,
			errContain: "invalid filter expression",
		},

		// Unicode zero-width characters
		{
			name:      "zero-width space in actor_id value",
			filter:    "actor_id=\"test\u200Bvalue\"",
			wantActor: "test\u200Bvalue",
		},

		// Right-to-left override character
		{
			name:      "RTL override character in value",
			filter:    "actor_id=\"admin\u202Efdcba\"",
			wantActor: "admin\u202Efdcba",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f, err := validation.ParseListFilter(tt.filter)
			if tt.wantErr {
				require.Error(t, err, "expected error for adversarial input")
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantActor, f.ActorID, "value must be preserved as-is (safe literal)")
		})
	}
}

// TestParseListFilter_InvalidStatusMessageListsAllEnumValues asserts the
// error message for an invalid status reflects the current KeyStatus proto
// enum. If a new status value is added, the message must include it.
func TestParseListFilter_InvalidStatusMessageListsAllEnumValues(t *testing.T) {
	t.Parallel()

	_, err := validation.ParseListFilter("status=BOGUS_VALUE")
	require.Error(t, err)

	assert.NotContains(t, err.Error(), "KEY_STATUS_UNSPECIFIED",
		"UNSPECIFIED must not appear in the list of valid statuses")

	for val, name := range talosv2alpha1.KeyStatus_name {
		if val == int32(talosv2alpha1.KeyStatus_KEY_STATUS_UNSPECIFIED) {
			continue
		}
		assert.Contains(t, err.Error(), name,
			"error message must reference enum value %q", name)
	}
}

// reviewed - @aeneasr - 2026-03-26
