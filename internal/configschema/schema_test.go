package configschema_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/configschema"
)

func TestUnifiedSchemaIsValidJSON(t *testing.T) {
	t.Parallel()

	// Verify the schema is not empty
	require.NotEmpty(t, configschema.SchemaJSON, "SchemaJSON should not be empty")

	// Parse the schema to ensure it's valid JSON
	var schema map[string]any

	err := json.Unmarshal(configschema.SchemaJSON, &schema)
	require.NoError(t, err, "Schema should be valid JSON")

	// Verify basic structure
	assert.Equal(t, "object", schema["type"], "Schema type should be object")
	assert.Contains(t, schema, "properties", "Schema should have properties")
}

func TestUnifiedSchemaHasLicenseMarkers(t *testing.T) {
	t.Parallel()

	var schema map[string]any

	err := json.Unmarshal(configschema.SchemaJSON, &schema)
	require.NoError(t, err, "Schema should be valid JSON")

	// Verify description mentions license markers
	description, ok := schema["description"].(string)
	require.True(t, ok, "Schema should have a description")
	assert.Contains(t, description, "x-license-required", "Description should mention x-license-required marker")

	// Verify some properties have license markers
	properties, ok := schema["properties"].(map[string]any)
	require.True(t, ok, "Schema should have properties")

	// Check cache has license marker
	cache, hasCache := properties["cache"]
	require.True(t, hasCache, "Schema should have 'cache' property")
	cacheObj, ok := cache.(map[string]any)
	require.True(t, ok, "Cache should be an object")
	assert.Equal(t, true, cacheObj["x-license-required"], "Cache should be marked as license-required")
}

func TestUnifiedSchemaContainsAllFeatures(t *testing.T) {
	t.Parallel()

	var schema map[string]any

	err := json.Unmarshal(configschema.SchemaJSON, &schema)
	require.NoError(t, err, "Schema should be valid JSON")

	properties, ok := schema["properties"].(map[string]any)
	require.True(t, ok, "Schema should have properties")

	// All features should be present in unified schema
	expectedFeatures := []string{
		"serve", "db", "log", "credentials", "secrets", // OSS features
		"cache", "multitenancy", "tracing", // tracing is OSS in this fork; cache/multitenancy Enterprise
	}

	for _, feature := range expectedFeatures {
		assert.Contains(t, properties, feature, "Schema should contain feature: %s", feature)
	}
}

func TestOSSFeaturesNotMarkedAsLicenseRequired(t *testing.T) {
	t.Parallel()

	var schema map[string]any

	err := json.Unmarshal(configschema.SchemaJSON, &schema)
	require.NoError(t, err, "Schema should be valid JSON")

	properties, ok := schema["properties"].(map[string]any)
	require.True(t, ok, "Schema should have properties")

	// OSS features should not have x-license-required marker. tracing is OSS in
	// this fork (see internal/tracing/tracer_oss.go).
	ossFeatures := []string{"serve", "db", "log", "credentials", "secrets", "tracing"}
	for _, feature := range ossFeatures {
		prop, exists := properties[feature]
		require.True(t, exists, "Schema should contain OSS feature: %s", feature)

		propObj, ok := prop.(map[string]any)
		require.True(t, ok, "Property %s should be an object", feature)

		_, hasLicenseMarker := propObj["x-license-required"]
		assert.False(t, hasLicenseMarker, "OSS feature %s should not have x-license-required marker", feature)
	}

	// Commercial-only features (cache, multitenancy, rate_limit) must carry the
	// license marker so that documentation and tooling treat them as Enterprise-only.
	// NOTE: tracing and serve.metrics are OSS in this fork (see tracer_oss.go /
	// metrics_server_oss.go) and intentionally lack the marker.
	commercialFeatures := []string{"cache", "multitenancy", "rate_limit"}
	for _, feature := range commercialFeatures {
		prop, exists := properties[feature]
		require.True(t, exists, "Schema should contain commercial feature: %s", feature)

		propObj, ok := prop.(map[string]any)
		require.True(t, ok, "Property %s should be an object", feature)

		assert.Equal(t, true, propObj["x-license-required"],
			"commercial feature %s should have x-license-required: true", feature)
	}

	// serve.metrics lives under serve and is OSS in this fork (metrics scrape is
	// implemented by cmd/metrics_server_oss.go); verify it is NOT license-marked.
	serveProp, ok := properties["serve"].(map[string]any)
	require.True(t, ok)
	serveProps, ok := serveProp["properties"].(map[string]any)
	require.True(t, ok)
	metricsProp, ok := serveProps["metrics"].(map[string]any)
	require.True(t, ok, "serve.metrics must exist")
	_, hasMetricsLicenseMarker := metricsProp["x-license-required"]
	assert.False(t, hasMetricsLicenseMarker,
		"serve.metrics must NOT have x-license-required (OSS in this fork)")
}

func TestCacheRedisFieldsAreImmutable(t *testing.T) {
	t.Parallel()

	var schema map[string]any

	err := json.Unmarshal(configschema.SchemaJSON, &schema)
	require.NoError(t, err, "Schema should be valid JSON")

	properties, ok := schema["properties"].(map[string]any)
	require.True(t, ok, "Schema should have properties")

	cache, ok := properties["cache"].(map[string]any)
	require.True(t, ok, "Schema should have 'cache' property")
	cacheProps, ok := cache["properties"].(map[string]any)
	require.True(t, ok, "cache should have properties")
	redis, ok := cacheProps["redis"].(map[string]any)
	require.True(t, ok, "cache should have 'redis' property")
	redisProps, ok := redis["properties"].(map[string]any)
	require.True(t, ok, "cache.redis should have properties")

	// The Redis cache client is built exactly once via sync.Once (see
	// internal/registry/factory.go) and is never rebuilt on config reload.
	// Every cache.redis.* field is therefore immutable and must be marked so,
	// otherwise the generated docs and tooling advertise hot-reload behavior
	// the runtime cannot deliver.
	require.NotEmpty(t, redisProps, "cache.redis should have at least one field")
	for name, prop := range redisProps {
		propObj, ok := prop.(map[string]any)
		require.True(t, ok, "cache.redis.%s should be an object", name)
		assert.Equal(t, true, propObj["x-immutable"],
			"cache.redis.%s must have x-immutable: true (cache is sync.Once-built)", name)
	}
}

// reviewed - @aeneasr - 2026-03-25
