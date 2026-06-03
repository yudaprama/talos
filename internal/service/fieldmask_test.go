package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ory/herodot"
)

func TestFieldMask_UnknownPath(t *testing.T) {
	t.Parallel()
	allowed := []string{"name", "scopes", "metadata", "ip_restriction"}
	tests := []struct {
		name      string
		paths     []string
		wantError bool
	}{
		{"empty mask is accepted", nil, false},
		{"single allowed path", []string{"name"}, false},
		{"all allowed paths", []string{"name", "scopes", "metadata"}, false},
		{"single unknown path is rejected", []string{"bogus"}, true},
		{"mix of allowed and unknown is rejected", []string{"name", "bogus"}, true},
		{"case sensitive mismatch on single word is rejected", []string{"Name"}, true},
		{"lowerCamelCase path is normalized to snake_case", []string{"ipRestriction"}, false},
		{"lowerCamelCase unknown path is still rejected", []string{"unknownField"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := newFieldMaskValidated(tt.paths, allowed)
			if tt.wantError {
				require.Error(t, err)
				var herodotErr *herodot.DefaultError
				require.ErrorAs(t, err, &herodotErr)
				assert.Contains(t, herodotErr.ReasonField, "unknown update_mask path")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFieldMask_HasNormalizesCamelCase(t *testing.T) {
	t.Parallel()
	m := newFieldMask([]string{"ipRestriction", "rateLimitPolicy.window"})
	assert.True(t, m.has("ip_restriction"), "camelCase path must match snake_case lookup")
	assert.True(t, m.has("rate_limit_policy"), "dotted camelCase path must match prefix lookup")
}

func TestFieldMask_ApplyString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		paths    []string
		field    string
		reqVal   string
		existing string
		want     string
	}{
		{"mask with field set - uses request value", []string{"name"}, "name", "new", "old", "new"},
		{"mask with field set to empty - explicit clear", []string{"name"}, "name", "", "old", ""},
		{"mask without field - preserves existing", []string{"scopes"}, "name", "new", "old", "old"},
		{"no mask, non-empty request - legacy update", nil, "name", "new", "old", "new"},
		{"no mask, empty request - preserves existing", nil, "name", "", "old", "old"},
		{"empty paths slice - legacy behavior", []string{}, "name", "new", "old", "new"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := newFieldMask(tt.paths)
			got := m.applyString(tt.field, tt.reqVal, tt.existing)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFieldMask_ApplySlice(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		paths    []string
		field    string
		reqVal   []string
		existing []string
		want     []string
	}{
		{"mask with field set - uses request value", []string{"scopes"}, "scopes", []string{"admin"}, []string{"read"}, []string{"admin"}},
		{"mask with field set to nil - explicit clear", []string{"scopes"}, "scopes", nil, []string{"read"}, nil},
		{"mask with field set to empty - explicit clear", []string{"scopes"}, "scopes", []string{}, []string{"read"}, []string{}},
		{"mask without field - preserves existing", []string{"name"}, "scopes", []string{"admin"}, []string{"read"}, []string{"read"}},
		{"no mask, non-empty request - legacy update", nil, "scopes", []string{"admin"}, []string{"read"}, []string{"admin"}},
		{"no mask, empty request - preserves existing", nil, "scopes", []string{}, []string{"read"}, []string{"read"}},
		{"no mask, nil request - preserves existing", nil, "scopes", nil, []string{"read"}, []string{"read"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := newFieldMask(tt.paths)
			got := applySlice(m, tt.field, tt.reqVal, tt.existing)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFieldMask_ApplyMetadata(t *testing.T) {
	t.Parallel()

	makeStruct := func(t *testing.T, m map[string]any) *structpb.Struct {
		t.Helper()
		s, err := structpb.NewStruct(m)
		require.NoError(t, err)
		return s
	}

	existing := json.RawMessage(`{"env":"staging"}`)

	t.Run("mask with metadata in mask - uses request value", func(t *testing.T) {
		t.Parallel()
		m := newFieldMask([]string{"metadata"})
		got, err := m.applyMetadata(makeStruct(t, map[string]any{"env": "prod"}), existing)
		require.NoError(t, err)
		assert.JSONEq(t, `{"env":"prod"}`, string(got))
	})

	t.Run("mask with metadata in mask nil value - clears to empty object", func(t *testing.T) {
		t.Parallel()
		m := newFieldMask([]string{"metadata"})
		got, err := m.applyMetadata(nil, existing)
		require.NoError(t, err)
		assert.JSONEq(t, `{}`, string(got))
	})

	t.Run("mask without metadata - preserves existing", func(t *testing.T) {
		t.Parallel()
		m := newFieldMask([]string{"name"})
		got, err := m.applyMetadata(makeStruct(t, map[string]any{"env": "prod"}), existing)
		require.NoError(t, err)
		assert.JSONEq(t, `{"env":"staging"}`, string(got))
	})

	t.Run("no mask with metadata - legacy update", func(t *testing.T) {
		t.Parallel()
		m := newFieldMask(nil)
		got, err := m.applyMetadata(makeStruct(t, map[string]any{"env": "prod"}), existing)
		require.NoError(t, err)
		assert.JSONEq(t, `{"env":"prod"}`, string(got))
	})

	t.Run("no mask without metadata - preserves existing", func(t *testing.T) {
		t.Parallel()
		m := newFieldMask(nil)
		got, err := m.applyMetadata(nil, existing)
		require.NoError(t, err)
		assert.JSONEq(t, `{"env":"staging"}`, string(got))
	})
}
