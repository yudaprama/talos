/*
Package events provides audit event emission for OpenTelemetry pipelines.

# Overview

The events package implements structured audit events for all significant
lifecycle operations in Talos. Events are emitted to downstream OTEL
pipelines and never persisted locally.

# Event Types

Admin Events:
  - IssuedAPIKeyCreated, ImportedAPIKeyCreated
  - APIKeyUpdated, APIKeyRevoked, APIKeyRotated, ImportedAPIKeyDeleted
  - APIKeyImportFailed
  - APIKeyVerified, APIKeyVerificationFailed
  - APIKeyTokenDerived

# Usage

Context-aware event building (recommended):

	eventcontext.NewFromContext(ctx, events.EventIssuedAPIKeyCreated).
	    WithKeyID(keyID).
	    WithPrefix(prefix).
	    WithActor(actorID).
	    Emit(ctx, emitter)

Failure scenarios:

	events.New(events.EventAPIKeyVerificationFailed).
	    WithNetworkID(networkID). // uuid.UUID
	    WithKeyID(keyID).
	    WithReason("revoked").
	    Emit(ctx, emitter)

# Emitter Implementations

OTELEmitter: Production implementation using span.AddEvent().
NoopEmitter: Discards all events; used when audit logging is disabled.

# Event Schema

Core attributes: NetworkID (always present).
Optional: APIKeyID, APIKeyPrefix, KeyType, Operation, Reason, ActorID, metadata.*.

# Performance

Event emission uses span.AddEvent() (O(1), buffered) with pre-allocated
attribute arrays. NoopEmitter has zero overhead.

# Integration

Services receive an Emitter via dependency injection:

	type Admin struct {
	    driver   persistence.Persister
	    provider ConfigProvider
	    emitter  events.Emitter
	}

# Security

Events do not contain sensitive data. Key IDs (UUIDs) are safe identifiers.
Full API key secrets are never emitted.

# Compliance

Events provide audit trails for GDPR, SOC2, etc.:
  - Who: ActorID
  - What: Operation, event name
  - When: timestamp (automatic via OTEL)
  - Where: NetworkID
  - Why: Reason
  - Result: encoded in event name (e.g., APIKeyVerified vs APIKeyVerificationFailed)
*/
package events
