package events

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/ory/x/otelx/semconv"
)

// Attribute key constants following OpenTelemetry semantic conventions.
// All keys use PascalCase to match the convention used by Kratos, Hydra, Keto,
// and other services in this monorepo.
const (
	// AttrNetworkID uses the shared semconv NID key so the analytics pipeline can route by project.
	AttrNetworkID semconv.AttributeKey = semconv.AttributeKeyNID

	// Key identification attributes
	AttrKeyID        semconv.AttributeKey = "APIKeyID"
	AttrAPIKeyPrefix semconv.AttributeKey = "APIKeyPrefix"
	AttrKeyType      semconv.AttributeKey = "KeyType" // "issued" or "imported"

	// Operation context attributes
	AttrOperation semconv.AttributeKey = "Operation"
	AttrReason    semconv.AttributeKey = "Reason"

	// Actor attributes
	AttrActorID semconv.AttributeKey = "ActorID"

	// Key properties attributes
	AttrExpiry     semconv.AttributeKey = "Expiry"
	AttrVisibility semconv.AttributeKey = "Visibility"

	// AttrMetadataPrefix is a string (not AttributeKey) because it is concatenated
	// with user-defined keys rather than used as a standalone attribute key.
	AttrMetadataPrefix = "metadata."
)

// appendNotEmpty appends an attribute if the value is not empty.
func appendNotEmpty[T ~string](attrs []attribute.KeyValue, key semconv.AttributeKey, val T) []attribute.KeyValue {
	if val != "" {
		return append(attrs, attribute.String(key.String(), string(val)))
	}
	return attrs
}

// eventToAttributes converts an AuditEvent to OpenTelemetry attributes
func eventToAttributes(event *AuditEvent) []attribute.KeyValue {
	if event == nil {
		return nil
	}

	attrs := make([]attribute.KeyValue, 0, 10+len(event.Metadata))

	// Core fields (always present)
	attrs = append(
		attrs,
		attribute.String(AttrNetworkID.String(), event.NetworkID.String()),
	)

	// Optional fields
	attrs = appendNotEmpty(attrs, AttrKeyID, event.KeyID)
	attrs = appendNotEmpty(attrs, AttrAPIKeyPrefix, event.Prefix)
	attrs = appendNotEmpty(attrs, AttrKeyType, event.KeyType)
	attrs = appendNotEmpty(attrs, AttrOperation, event.Operation)
	attrs = appendNotEmpty(attrs, AttrReason, event.Reason)
	attrs = appendNotEmpty(attrs, AttrActorID, event.ActorID)
	attrs = appendNotEmpty(attrs, AttrVisibility, event.Visibility)
	if event.Expiry != nil {
		attrs = append(attrs, attribute.String(AttrExpiry.String(), event.Expiry.UTC().Format("2006-01-02T15:04:05Z")))
	}

	// Additional metadata (optional)
	for key, value := range event.Metadata {
		attrs = append(attrs, attribute.String(AttrMetadataPrefix+key, value))
	}

	return attrs
}

// reviewed - @aeneasr - 2026-03-27
