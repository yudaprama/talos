package sqliteshared

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory-corp/talos/internal/persistence/persistmodel"
)

func TestIsMemoryDSN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dsn  string
		want bool
	}{
		{name: "bare memory", dsn: ":memory:", want: true},
		{name: "file uri shared memory", dsn: "file::memory:?cache=shared", want: true},
		{name: "mode memory query param", dsn: "file:foo.db?mode=memory&cache=shared", want: true},
		{name: "rwc mode is not memory", dsn: "file:foo.db?mode=rwc", want: false},
		{name: "absolute file path", dsn: "/tmp/foo.db", want: false},
		{name: "empty string", dsn: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, IsMemoryDSN(tt.dsn))
		})
	}
}

func TestInt32ToNullable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input int32
		want  any
	}{
		{name: "zero is nil", input: 0, want: nil},
		{name: "positive returned as-is", input: 42, want: int32(42)},
		{name: "negative returned as-is", input: -1, want: int32(-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, Int32ToNullable(tt.input))
		})
	}
}

func TestBuildBatchInsertImportedKeysQuery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	nid := "00000000-0000-0000-0000-000000000000"

	t.Run("single key produces one row of placeholders", func(t *testing.T) {
		t.Parallel()

		keys := []persistmodel.BatchCreateImportedAPIKeyInput{
			{KeyID: "k1", ActorID: "a1", Name: "n1"},
		}

		query, args := BuildBatchInsertImportedKeysQuery(nid, keys, now)

		assert.Equal(t, 1, strings.Count(query, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
			"one row of placeholders per key")
		assert.Contains(t, query, "INSERT INTO imported_api_keys")
		assert.Contains(t, query, "ON CONFLICT (nid, key_id) DO NOTHING")
		assert.Contains(t, query, "RETURNING")
		assert.Len(t, args, 15, "15 bind parameters per key")
		assert.Equal(t, nid, args[0], "first arg is nid")
		assert.Equal(t, "k1", args[1], "second arg is key_id")
	})

	t.Run("multiple keys produce comma-separated rows with proportional args", func(t *testing.T) {
		t.Parallel()

		keys := []persistmodel.BatchCreateImportedAPIKeyInput{
			{KeyID: "k1", ActorID: "a1", Name: "n1"},
			{KeyID: "k2", ActorID: "a2", Name: "n2"},
			{KeyID: "k3", ActorID: "a3", Name: "n3"},
		}

		query, args := BuildBatchInsertImportedKeysQuery(nid, keys, now)

		assert.Equal(t, 3, strings.Count(query, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
			"one row of placeholders per key")
		assert.Equal(t, 2, strings.Count(query, "), ("),
			"comma-separated rows")
		assert.Len(t, args, 45, "15 bind parameters per key * 3 keys")
		assert.Equal(t, "k1", args[1])
		assert.Equal(t, "k2", args[16])
		assert.Equal(t, "k3", args[31])
	})

	t.Run("at MaxBatchKeys the args slice is exactly bounded", func(t *testing.T) {
		t.Parallel()

		keys := make([]persistmodel.BatchCreateImportedAPIKeyInput, MaxBatchKeys)
		for i := range keys {
			keys[i] = persistmodel.BatchCreateImportedAPIKeyInput{KeyID: "k", ActorID: "a", Name: "n"}
		}

		_, args := BuildBatchInsertImportedKeysQuery(nid, keys, now)

		require.Len(t, args, MaxBatchKeys*15)
	})
}
