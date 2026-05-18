package events

import (
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
)

func TestEventToAttributes_MinimalEvent(t *testing.T) {
	t.Parallel()

	event := &AuditEvent{
		EventType: EventAPIKeyCreated,
		NetworkID: uuid.Nil,
	}

	attrs := eventToAttributes(event)

	// Should have exactly 1 core attribute (network_id)
	assert.Len(t, attrs, 1)
	assertAttributeValue(t, attrs, AttrNetworkID.String(), uuid.Nil.String())
}

func TestEventToAttributes_FullEvent(t *testing.T) {
	t.Parallel()

	expiry := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	event := &AuditEvent{
		EventType: EventAPIKeyCreated,
		NetworkID: uuid.Nil,

		KeyID:      "01H...",
		Prefix:     "talos",
		KeyType:    "issued",
		Operation:  "create_key",
		Reason:     "user_requested",
		ActorID:    "user-123",
		Visibility: "public",
		Expiry:     &expiry,
		Metadata: map[string]string{
			"algorithm": "jwt",
			"ttl":       "3600",
		},
	}

	attrs := eventToAttributes(event)

	// Should have 11 attributes (1 core + 8 optional + 2 metadata)
	assert.Len(t, attrs, 11)

	// Core attributes
	assertAttributeValue(t, attrs, AttrNetworkID.String(), uuid.Nil.String())

	// Optional attributes
	assertAttributeValue(t, attrs, AttrKeyID.String(), "01H...")
	assertAttributeValue(t, attrs, AttrAPIKeyPrefix.String(), "talos")
	assertAttributeValue(t, attrs, AttrKeyType.String(), "issued")
	assertAttributeValue(t, attrs, AttrOperation.String(), "create_key")
	assertAttributeValue(t, attrs, AttrReason.String(), "user_requested")
	assertAttributeValue(t, attrs, AttrActorID.String(), "user-123")
	assertAttributeValue(t, attrs, AttrVisibility.String(), "public")
	assertAttributeValue(t, attrs, AttrExpiry.String(), "2026-06-15T12:00:00Z")

	// Metadata attributes
	assertAttributeValue(t, attrs, "metadata.algorithm", "jwt")
	assertAttributeValue(t, attrs, "metadata.ttl", "3600")
}

func TestEventToAttributes_NilEvent(t *testing.T) {
	t.Parallel()

	attrs := eventToAttributes(nil)
	assert.Nil(t, attrs)
}

func TestEventToAttributes_WithReason(t *testing.T) {
	t.Parallel()

	event := &AuditEvent{
		EventType: EventAPIKeyVerificationFailed,
		NetworkID: uuid.Nil,
		Reason:    "revoked",
	}

	attrs := eventToAttributes(event)

	assert.Len(t, attrs, 2) // network_id, reason
	assertAttributeValue(t, attrs, AttrNetworkID.String(), uuid.Nil.String())
	assertAttributeValue(t, attrs, AttrReason.String(), "revoked")
}

func TestEventToAttributes_WithMetadataOnly(t *testing.T) {
	t.Parallel()

	event := &AuditEvent{
		EventType: EventTokenDerived,
		NetworkID: uuid.Nil,

		Metadata: map[string]string{
			"algorithm": "jwt",
			"ttl":       "3600",
			"scopes":    "read,write",
		},
	}

	attrs := eventToAttributes(event)

	// 1 core + 3 metadata = 4
	assert.Len(t, attrs, 4)
	assertAttributeValue(t, attrs, "metadata.algorithm", "jwt")
	assertAttributeValue(t, attrs, "metadata.ttl", "3600")
	assertAttributeValue(t, attrs, "metadata.scopes", "read,write")
}

// Benchmark attribute conversion
func BenchmarkEventToAttributes_Minimal(b *testing.B) {
	event := &AuditEvent{
		EventType: EventAPIKeyCreated,
		NetworkID: uuid.Nil,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = eventToAttributes(event)
	}
}

func BenchmarkEventToAttributes_Full(b *testing.B) {
	event := &AuditEvent{
		EventType: EventAPIKeyCreated,
		NetworkID: uuid.Nil,

		KeyID:     "01HQZX9VYQKJB8XQZQXQZQXQXQ",
		Prefix:    "talos",
		KeyType:   "issued",
		Operation: "create_key",
		ActorID:   "user-123",
		Metadata: map[string]string{
			"algorithm": "jwt",
			"ttl":       "3600",
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = eventToAttributes(event)
	}
}

// Helper function to assert attribute value
func assertAttributeValue(t *testing.T, attrs []attribute.KeyValue, key, expectedValue string) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			assert.Equal(t, expectedValue, attr.Value.AsString(), "attribute %s", key)
			return
		}
	}
	t.Errorf("attribute %s not found in %v", key, attrs)
}

// reviewed - @aeneasr - 2026-03-27
