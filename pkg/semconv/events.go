// Package semconv provides exported semantic convention constants for Talos
// audit events. Other services (e.g. backoffice) import this package to
// reference Talos event types without hardcoding string literals.
package semconv

import orysemconv "github.com/ory/x/otelx/semconv"

const (
	// EventAPIKeyCreated is emitted when an API key is created (issued or imported).
	// Use the KeyType attribute to distinguish between the two origins.
	EventAPIKeyCreated orysemconv.Event = "APIKeyCreated"
	// EventAPIKeyUpdated is emitted when an API key's metadata is updated.
	EventAPIKeyUpdated orysemconv.Event = "APIKeyUpdated"
	// EventAPIKeyRevoked is emitted when an API key is revoked.
	EventAPIKeyRevoked orysemconv.Event = "APIKeyRevoked"
	// EventAPIKeyRotated is emitted when an API key is rotated.
	EventAPIKeyRotated orysemconv.Event = "APIKeyRotated"
	// EventAPIKeyVerified is emitted when an API key is successfully verified.
	EventAPIKeyVerified orysemconv.Event = "APIKeyVerified"
	// EventAPIKeyVerificationFailed is emitted when an API key verification fails.
	EventAPIKeyVerificationFailed orysemconv.Event = "APIKeyVerificationFailed"
	// EventAPIKeyImportFailed is emitted when an API key import fails.
	EventAPIKeyImportFailed orysemconv.Event = "APIKeyImportFailed"
	// EventTokenDerived is emitted when a session token is derived from an API key.
	EventTokenDerived orysemconv.Event = "TokenDerived"
	// EventAPIKeyDeleted is emitted when an issued API key is permanently deleted.
	EventAPIKeyDeleted orysemconv.Event = "APIKeyDeleted"
	// EventImportedAPIKeyDeleted is emitted when an imported API key is permanently deleted.
	EventImportedAPIKeyDeleted orysemconv.Event = "ImportedAPIKeyDeleted"
)
