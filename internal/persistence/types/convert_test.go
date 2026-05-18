package persistencetypes

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ory-corp/talos/internal/contextx"
	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
)

func TestImportedAPIKeyToIssuedAPIKey_PreservesSharedFields(t *testing.T) {
	t.Parallel()

	nid := uuid.Must(uuid.NewV4())
	ctx := context.WithValue(t.Context(), contextx.NIDKey{}, nid)

	expiresAt := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	lastUsedAt := expiresAt.Add(-time.Hour)
	actorID := "actor-sentinel"
	revocationReasonText := "revocation-sentinel"
	requestID := "request-sentinel"
	quota := int64(17)
	window := int64(29)

	imported := db.ImportedApiKey{
		NID:                  uuid.Must(uuid.NewV4()),
		KeyID:                "key-sentinel",
		Name:                 "name-sentinel",
		ActorID:              &actorID,
		Scopes:               json.RawMessage(`["scope-sentinel"]`),
		Status:               1,
		Metadata:             json.RawMessage(`{"metadata":"sentinel"}`),
		LastUsedAt:           &lastUsedAt,
		ExpiresAt:            &expiresAt,
		CreatedAt:            expiresAt.Add(-2 * time.Hour),
		UpdatedAt:            expiresAt.Add(-time.Minute),
		RateLimitQuota:       &quota,
		RateLimitWindow:      &window,
		RevocationReason:     2,
		RevocationReasonText: &revocationReasonText,
		AllowedCidrs:         json.RawMessage(`["10.0.0.0/8"]`),
		RequestID:            &requestID,
		Visibility:           2,
	}

	got := ImportedAPIKeyToIssuedAPIKey(ctx, imported)

	assert.Equal(t, nid, got.NID, "NID must come from context, not the imported row")
	assert.Equal(t, "imported", got.TokenPrefix)
	assert.Equal(t, int64(0), got.Version)

	assertCommonFieldsEqual(t, imported, got, "NID")
}

func assertCommonFieldsEqual(t *testing.T, imported db.ImportedApiKey, got db.IssuedApiKey, ignored ...string) {
	t.Helper()

	ignoredSet := make(map[string]struct{}, len(ignored))
	for _, name := range ignored {
		ignoredSet[name] = struct{}{}
	}

	importedValue := reflect.ValueOf(imported)
	importedType := importedValue.Type()
	gotValue := reflect.ValueOf(got)

	for i := range importedType.NumField() {
		field := importedType.Field(i)
		if !field.IsExported() {
			continue
		}
		if _, skip := ignoredSet[field.Name]; skip {
			continue
		}
		gotField := gotValue.FieldByName(field.Name)
		if !gotField.IsValid() {
			continue
		}

		assert.Equalf(t,
			importedValue.Field(i).Interface(),
			gotField.Interface(),
			"shared field %s must be preserved by ImportedAPIKeyToIssuedAPIKey", field.Name)
	}
}
