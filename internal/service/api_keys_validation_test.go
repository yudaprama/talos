package service

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	db "github.com/ory-corp/talos/internal/persistence/sqlc/generated"
	talosv2alpha1 "github.com/ory-corp/talos/pkg/api/talos/v2alpha1"
)

func dbAPIKeyCommonFieldsT(t *testing.T, key db.IssuedApiKey) dbAPIKeyFields {
	t.Helper()
	fields, err := dbAPIKeyCommonFields(key)
	require.NoError(t, err)
	return fields
}

func TestDbAPIKeyCommonFields_MapsSharedFields(t *testing.T) {
	t.Parallel()

	quota := int64(100)
	window := int64(60)
	actorID := "actor-123"
	fields := dbAPIKeyCommonFieldsT(t, db.IssuedApiKey{
		KeyID:           "key-123",
		Name:            "Test Key",
		ActorID:         &actorID,
		Scopes:          json.RawMessage(`["read","write"]`),
		Metadata:        json.RawMessage(`{"env":"test"}`),
		Status:          int32(talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE),
		CreatedAt:       time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC),
		UpdatedAt:       time.Date(2026, 4, 2, 10, 0, 0, 0, time.UTC),
		RateLimitQuota:  &quota,
		RateLimitWindow: &window,
		AllowedCidrs:    json.RawMessage(`["10.0.0.0/8"]`),
		Visibility:      int32(talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC),
	})

	assert.Equal(t, "key-123", fields.keyID)
	assert.Equal(t, "Test Key", fields.name)
	assert.Equal(t, actorID, fields.actorID)
	assert.Equal(t, []string{"read", "write"}, fields.scopes)
	require.NotNil(t, fields.metadata)
	assert.Equal(t, talosv2alpha1.KeyStatus_KEY_STATUS_ACTIVE, fields.status)
	require.NotNil(t, fields.createTime)
	require.NotNil(t, fields.updateTime)
	require.NotNil(t, fields.rateLimitPolicy)
	assert.Equal(t, quota, fields.rateLimitPolicy.Quota)
	require.NotNil(t, fields.ipRestriction)
	assert.Equal(t, []string{"10.0.0.0/8"}, fields.ipRestriction.AllowedCidrs)
	assert.Equal(t, talosv2alpha1.KeyVisibility_KEY_VISIBILITY_PUBLIC, fields.visibility)
}

func TestDbAPIKeyCommonFields_MalformedScopes(t *testing.T) {
	t.Parallel()

	_, err := dbAPIKeyCommonFields(db.IssuedApiKey{
		KeyID:  "key-bad-scopes",
		Scopes: json.RawMessage(`{"oops"`),
	})
	require.Error(t, err)
}
