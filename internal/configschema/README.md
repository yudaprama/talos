# Unified Configuration Schema

This directory contains the unified configuration schema used by both OSS and Enterprise editions of
Ory Talos.

## Approach

Instead of maintaining separate OSS and Enterprise schemas, we use a **single unified schema** with
a simple license marker to indicate which features require an Enterprise license. This approach:

- **Simplifies maintenance**: One schema to update, not two
- **Improves documentation**: Users can see all features in one place
- **Enables validation**: Build systems can validate config files against the same schema
- **Clarifies licensing**: Simple boolean flag marks proprietary features

## Schema Structure

The schema (`config.schema.json`) contains all configuration properties for both editions, with a
custom property indicating feature availability:

### License Marker

#### `x-license-required: true`

Indicates that a feature requires an Enterprise license. Features without this marker are available
in the OSS Edition.

```json
{
  "cache": {
    "type": "object",
    "description": "Cache configuration. Requires Enterprise license.",
    "x-license-required": true,
    "properties": {
      "redis": {
        "type": "object",
        "description": "Redis cache configuration. Requires Enterprise license.",
        "x-license-required": true
      }
    }
  }
}
```

**Features without the marker** are available in OSS:

```json
{
  "http": {
    "type": "object",
    "description": "HTTP server configuration"
    // No x-license-required = available in OSS
  }
}
```

## Features by Edition

### OSS Features (Available to All)

- HTTP server configuration
- Database configuration (SQLite)
- Logging configuration
- TLS configuration
- API key defaults
- Token configuration

### Enterprise Features (License Required)

- `env`: Environment specification (development, staging, production)
- `cache`: Advanced caching with Redis support
- `cache.redis`: Redis-backed caching
- Advanced memory cache configuration
- PostgreSQL/MySQL/CockroachDB support (in driver implementation)
- `tracing`: OpenTelemetry tracing and OTLP exporter
- `serve.metrics`: Prometheus metrics HTTP server
- `rate_limit`: Rate limit enforcement
- `multitenancy`: Per-tenant configuration and routing

## Usage

### Go Code

Both editions import from the same package:

```go
import "github.com/ory-corp/talos/internal/configschema"

// Use the unified schema
schema := configschema.ConfigSchemaJSON

// Backward compatibility alias
ossSchema := configschema.OSSSchemaJSON // Same as ConfigSchemaJSON
```

### Configuration Files

Users can include Enterprise features in their config files. The behavior depends on the build:

**OSS Build**: Enterprise-only features are ignored or cause validation errors (depending on
implementation)

**Enterprise Build**: All features are available

Example config with both OSS and Enterprise features:

```yaml
# OSS features - available in all builds
http:
  addr: ":4420"
log:
  level: info
talos:
  hmac_secret: "base64-encoded-secret"

# Enterprise features - require license
env: production
cache:
  type: redis
  redis:
    addrs:
      - redis-primary:6379
    cluster: true
```

## Updating the Schema

### Adding New Features

1. **OSS Feature**: Add the property without `x-license-required`

   ```json
   {
     "new_feature": {
       "type": "object",
       "description": "New feature description",
       "properties": { ... }
     }
   }
   ```

2. **Enterprise Feature**: Add the property with `x-license-required: true`

   ```json
   {
     "new_feature": {
       "type": "object",
       "description": "New feature description. Requires Enterprise license.",
       "x-license-required": true,
       "properties": { ... }
     }
   }
   ```

3. Update descriptions to mention license requirement
4. Run tests to verify:
   ```bash
   go test ./internal/configschema/...
   go test -tags proprietary ./proprietary/cmd/...
   ```

### Modifying Existing Features

1. Edit `config.schema.json` directly
2. Update descriptions if license requirement changes
3. Add/remove `x-license-required` marker as needed
4. Run both OSS and Enterprise tests

### Migration from Multi-Marker Approach

The previous approach used multiple custom properties (`x-proprietary`, `x-requires-license`,
`x-oss-required`, `x-proprietary-note`, `x-license-note`). The unified approach simplifies this to a
single marker:

**Before** (multi-marker):

```json
{
  "cache": {
    "x-proprietary": true,
    "x-requires-license": "enterprise"
  }
}
```

**Now** (single marker):

```json
{
  "cache": {
    "x-license-required": true
  }
}
```

## Testing

### OSS Tests

```bash
go test ./internal/configschema/...
```

Verifies:

- Schema is valid JSON
- All expected OSS features are present
- License markers are correctly set
- OSS features don't have license markers

### Enterprise Tests

```bash
go test -tags proprietary ./proprietary/cmd/...
```

Verifies:

- Schema contains both OSS and Enterprise features
- Enterprise features have `x-license-required: true`
- No legacy markers are present

## Validation

The schema is used for:

1. **Documentation**: Auto-generating config documentation
2. **IDE Support**: Providing autocomplete and validation in editors
3. **Runtime Validation**: Validating config files on server startup
4. **CI/CD**: Ensuring example configs are valid

## Standards

The schema follows:

- [JSON Schema Draft 07](http://json-schema.org/draft-07/schema#)
- Custom extension properties (starting with `x-`) as per JSON Schema spec
- OpenAPI 3.x conventions for vendor extensions

## Design Principles

1. **Simplicity**: One marker (`x-license-required`) vs multiple markers
2. **Clarity**: Boolean true/false, not string values
3. **Defaults**: Absence of marker means "OSS Edition"
4. **Documentation**: Descriptions clearly state license requirements
