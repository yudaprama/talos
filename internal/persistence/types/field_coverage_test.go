// This file is a drift sentinel: when sqlc regenerates models from updated
// schema, the generated struct's field set changes, but the manual mapping
// sites in convert.go / params.go / per-driver files do not. Without this
// test, drift surfaces only as silently dropped columns at runtime. The
// canonical field lists below pin the expected sqlc model shape; updating
// them is the explicit signal to update every mapping site.
package persistencetypes

import (
	"reflect"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"

	db "github.com/ory/talos/internal/persistence/sqlc/generated"
)

// assertFieldCount verifies that a struct has the expected number of fields.
// When sqlc regenerates a model (e.g. after adding a DB column), the field count
// changes and this test fails. The developer must then update every manual
// mapping site (convert.go, params.go, driver files) and bump the expected count.
func assertFieldCount(t *testing.T, v any, expected int) {
	t.Helper()
	rt := reflect.TypeOf(v)
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	actual := rt.NumField()
	if actual != expected {
		t.Errorf("%s: expected %d fields, got %d — update all manual mapping sites and bump the expected count",
			rt.Name(), expected, actual)
	}
}

// canonicalFieldNames returns the sorted set of exported field names on v.
func canonicalFieldNames(t *testing.T, v any) []string {
	t.Helper()
	rt := reflect.TypeOf(v)
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	names := make([]string, 0, rt.NumField())
	for f := range rt.Fields() {
		if !f.IsExported() {
			continue
		}
		names = append(names, f.Name)
	}
	sort.Strings(names)
	return names
}

// canonicalIssuedAPIKeyFields is the single source of truth that fails loudly
// with a diff when sqlc regenerates and the struct shape drifts.
func canonicalIssuedAPIKeyFields() []string {
	return []string{
		"ActorID",
		"AllowedCidrs",
		"CreatedAt",
		"ExpiresAt",
		"KeyID",
		"LastUsedAt",
		"Metadata",
		"NID",
		"Name",
		"RateLimitQuota",
		"RateLimitWindow",
		"RequestID",
		"RevocationReason",
		"RevocationReasonText",
		"Scopes",
		"Status",
		"TokenPrefix",
		"UpdatedAt",
		"Version",
		"Visibility",
	}
}

// canonicalImportedAPIKeyFields is the single source of truth that fails loudly
// with a diff when sqlc regenerates and the struct shape drifts.
func canonicalImportedAPIKeyFields() []string {
	return []string{
		"ActorID",
		"AllowedCidrs",
		"CreatedAt",
		"ExpiresAt",
		"KeyID",
		"LastUsedAt",
		"Metadata",
		"NID",
		"Name",
		"RateLimitQuota",
		"RateLimitWindow",
		"RequestID",
		"RevocationReason",
		"RevocationReasonText",
		"Scopes",
		"Status",
		"UpdatedAt",
		"Visibility",
	}
}

func TestFieldCounts_ManualMappingStructs(t *testing.T) {
	t.Parallel()

	// sqlc-generated models
	assertFieldCount(t, db.IssuedApiKey{}, 20)
	assertFieldCount(t, db.ImportedApiKey{}, 18)

	// Param structs with manual field-by-field mapping
	assertFieldCount(t, CreateIssuedAPIKeyParams{}, 12)
	assertFieldCount(t, RotateIssuedAPIKeyParams{}, 12)
	assertFieldCount(t, CreateImportedKeyParams{}, 12)
	assertFieldCount(t, UpdateIssuedAPIKeyParams{}, 7)
	assertFieldCount(t, UpdateImportedKeyParams{}, 7)
	assertFieldCount(t, RevokeIssuedAPIKeyParams{}, 4)
	assertFieldCount(t, RevokeImportedKeyParams{}, 4)
}

func TestCanonicalFieldNames_ManualMappingStructs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    any
		want []string
	}{
		{
			name: "CreateIssuedAPIKeyParams",
			v:    CreateIssuedAPIKeyParams{},
			want: []string{
				"ActorID",
				"AllowedCIDRs",
				"ExpiresAt",
				"KeyID",
				"Metadata",
				"Name",
				"RateLimitQuota",
				"RateLimitWindow",
				"RequestID",
				"Scopes",
				"TokenPrefix",
				"Visibility",
			},
		},
		{
			name: "RotateIssuedAPIKeyParams",
			v:    RotateIssuedAPIKeyParams{},
			want: []string{
				"ActorID",
				"AllowedCIDRs",
				"ExpiresAt",
				"Metadata",
				"Name",
				"NewKeyID",
				"OldKeyID",
				"RateLimitQuota",
				"RateLimitWindow",
				"Scopes",
				"TokenPrefix",
				"Visibility",
			},
		},
		{
			name: "CreateImportedKeyParams",
			v:    CreateImportedKeyParams{},
			want: []string{
				"ActorID",
				"AllowedCIDRs",
				"ExpiresAt",
				"KeyID",
				"Metadata",
				"Name",
				"RateLimitQuota",
				"RateLimitWindow",
				"RequestID",
				"Scopes",
				"Status",
				"Visibility",
			},
		},
		{
			name: "UpdateIssuedAPIKeyParams",
			v:    UpdateIssuedAPIKeyParams{},
			want: []string{
				"AllowedCIDRs",
				"KeyID",
				"Metadata",
				"Name",
				"RateLimitQuota",
				"RateLimitWindow",
				"Scopes",
			},
		},
		{
			name: "UpdateImportedKeyParams",
			v:    UpdateImportedKeyParams{},
			want: []string{
				"AllowedCIDRs",
				"KeyID",
				"Metadata",
				"Name",
				"RateLimitQuota",
				"RateLimitWindow",
				"Scopes",
			},
		},
		{
			name: "RevokeIssuedAPIKeyParams",
			v:    RevokeIssuedAPIKeyParams{},
			want: []string{
				"Description",
				"ExpiresAt",
				"KeyID",
				"Reason",
			},
		},
		{
			name: "RevokeImportedKeyParams",
			v:    RevokeImportedKeyParams{},
			want: []string{
				"Description",
				"ExpiresAt",
				"KeyID",
				"Reason",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tt.want, canonicalFieldNames(t, tt.v)); diff != "" {
				t.Errorf("%s field-name drift (-canonical +got):\n%s", tt.name, diff)
			}
		})
	}
}

// TestCanonicalFieldNames_OSSModels guards against sqlc-regenerated rename
// drift on the OSS sqlc structs. A field renamed by a developer-edited query
// fails this test with a clear name diff.
func TestCanonicalFieldNames_OSSModels(t *testing.T) {
	t.Parallel()

	got := canonicalFieldNames(t, db.IssuedApiKey{})
	if diff := cmp.Diff(canonicalIssuedAPIKeyFields(), got); diff != "" {
		t.Errorf("db.IssuedApiKey field-name drift (-canonical +got):\n%s", diff)
	}

	got = canonicalFieldNames(t, db.ImportedApiKey{})
	if diff := cmp.Diff(canonicalImportedAPIKeyFields(), got); diff != "" {
		t.Errorf("db.ImportedApiKey field-name drift (-canonical +got):\n%s", diff)
	}
}
