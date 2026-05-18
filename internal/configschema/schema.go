// Package configschema provides configuration schema definitions.
package configschema

import "github.com/ory-corp/talos/spec"

// SchemaJSON contains the unified configuration schema with license markers.
// Fields marked with 'x-license-required: true' require an Enterprise license.
// Fields without this marker are available in the OSS Edition.
var SchemaJSON = spec.ConfigSchema

// reviewed - @aeneasr - 2026-03-25
