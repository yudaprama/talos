// Package semconv provides exported semantic convention constants for Talos
// audit events. Other services (e.g. backoffice) import this package to
// reference Talos event types without hardcoding string literals.
package semconv

import orysemconv "github.com/ory/x/otelx/semconv"

// Event names are globally descriptive so they remain unique when emitted into
// a shared OTEL pipeline that aggregates events across services (e.g. the Ory
// Network project events stream). The API-key origin (issued vs. imported) is
// encoded in the create and delete event names so they do not collide with the
// backoffice console API-key events of the same kind.
const (
	// EventIssuedAPIKeyCreated is emitted when Talos issues a new API key.
	EventIssuedAPIKeyCreated orysemconv.Event = "IssuedAPIKeyCreated"
	// EventImportedAPIKeyCreated is emitted when an externally created API key is imported into Talos.
	EventImportedAPIKeyCreated orysemconv.Event = "ImportedAPIKeyCreated"
	// EventIssuedAPIKeyUpdated is emitted when an issued API key's metadata is updated.
	EventIssuedAPIKeyUpdated orysemconv.Event = "IssuedAPIKeyUpdated"
	// EventImportedAPIKeyUpdated is emitted when an imported API key's metadata is updated.
	EventImportedAPIKeyUpdated orysemconv.Event = "ImportedAPIKeyUpdated"
	// EventIssuedAPIKeyRevoked is emitted when an issued API key is revoked.
	EventIssuedAPIKeyRevoked orysemconv.Event = "IssuedAPIKeyRevoked"
	// EventImportedAPIKeyRevoked is emitted when an imported API key is revoked.
	EventImportedAPIKeyRevoked orysemconv.Event = "ImportedAPIKeyRevoked"
	// EventIssuedAPIKeyRotated is emitted when an issued API key is rotated.
	EventIssuedAPIKeyRotated orysemconv.Event = "IssuedAPIKeyRotated"
	// EventAPIKeyVerified is emitted when an API key is successfully verified.
	EventAPIKeyVerified orysemconv.Event = "APIKeyVerified"
	// EventAPIKeyVerificationFailed is emitted when an API key verification fails.
	EventAPIKeyVerificationFailed orysemconv.Event = "APIKeyVerificationFailed"
	// EventAPIKeyImportFailed is emitted when an API key import fails.
	EventAPIKeyImportFailed orysemconv.Event = "APIKeyImportFailed"
	// EventAPIKeyDerivedToken is emitted when a session token is derived from an API key.
	EventAPIKeyDerivedToken orysemconv.Event = "APIKeyDerivedToken"
	// EventImportedAPIKeyDeleted is emitted when an imported API key is permanently deleted.
	EventImportedAPIKeyDeleted orysemconv.Event = "ImportedAPIKeyDeleted"
)
