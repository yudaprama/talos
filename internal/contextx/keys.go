// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package contextx defines context key types used to carry per-request values
// such as the network ID and config provider.
package contextx

type (
	// NIDKey is the context key for the current request's network ID.
	NIDKey struct{}
	// ConfigProviderKey is the context key for the per-tenant config provider.
	ConfigProviderKey struct{}
)

// reviewed - @aeneasr - 2026-03-25
