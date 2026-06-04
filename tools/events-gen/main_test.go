package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadConstStringValues_ResolvesNetworkIDKey guards the regression where the
// generated events reference showed a blank OTEL key for NetworkID.
//
// AttrNetworkID is defined as a cross-package constant reference
// (semconv.AttributeKeyNID), which AST literal extraction cannot resolve. The
// type-checked loader must yield the real emitted key, "ProjectID".
func TestLoadConstStringValues_ResolvesNetworkIDKey(t *testing.T) {
	t.Parallel()

	values, err := loadConstStringValues(eventsPackagePath)
	require.NoError(t, err)

	assert.Equal(t, "ProjectID", values["AttrNetworkID"],
		"AttrNetworkID must resolve to the shared semconv NID key")
}
