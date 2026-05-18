// Package spec exports the Talos configuration JSON schema for use by
// external packages (e.g. backoffice validation).
package spec

import _ "embed"

// ConfigSchema contains the Talos configuration JSON schema.
// Fields marked with 'x-license-required: true' require an Enterprise license.
//
//go:embed config.schema.json
var ConfigSchema []byte

// reviewed - @aeneasr - 2026-03-25
