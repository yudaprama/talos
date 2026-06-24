package metering

import (
	"context"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const meterSchema = `
CREATE TABLE networks (id VARCHAR(36) PRIMARY KEY, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL);
CREATE TABLE actor_balances (
    nid VARCHAR(36) NOT NULL, actor_id VARCHAR(255) NOT NULL,
    quota BIGINT NOT NULL DEFAULT 0, remaining BIGINT NOT NULL DEFAULT 0, updated_at DATETIME NOT NULL,
    PRIMARY KEY (nid, actor_id),
    FOREIGN KEY (nid) REFERENCES networks (id) ON DELETE CASCADE
);
CREATE TABLE api_key_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT, nid VARCHAR(36) NOT NULL, actor_id VARCHAR(255) NOT NULL,
    key_id VARCHAR(36), usage_type VARCHAR(32) NOT NULL, usage_amount BIGINT NOT NULL,
    cost_micros BIGINT NOT NULL DEFAULT 0, model VARCHAR(255) NOT NULL DEFAULT '',
    request_id VARCHAR(36), created_at DATETIME NOT NULL,
    FOREIGN KEY (nid) REFERENCES networks (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_api_key_usage_request ON api_key_usage (nid, request_id) WHERE request_id IS NOT NULL;
`

// setupMeterDB opens an in-memory SQLite DB with the metering schema. The OSS NID
// (uuid.Nil) row is inserted so the FK is satisfiable.
func setupMeterDB(t *testing.T) *sqlx.DB {
	t.Helper()
	dbx, err := sqlx.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = dbx.Close() })
	_, err = dbx.Exec(meterSchema)
	require.NoError(t, err)
	_, err = dbx.Exec("INSERT INTO networks (id, created_at, updated_at) VALUES ('00000000-0000-0000-0000-000000000000', datetime('now'), datetime('now'))")
	require.NoError(t, err)
	return dbx
}

func TestNoopMeter(t *testing.T) {
	ctx := context.Background()
	m := NoopMeter{}
	assert.False(t, m.Enabled())
	bal, err := m.Balance(ctx, "x")
	require.NoError(t, err)
	assert.True(t, bal.Unlimited()) // quota 0 => unlimited
	res, err := m.Ingest(ctx, IngestRequest{ActorID: "x", CostMicros: 5})
	require.NoError(t, err)
	assert.True(t, res.Accepted)
}

func TestDBMeter_IngestDebitIdempotencyBalance(t *testing.T) {
	ctx := context.Background()
	m := NewDBMeter(setupMeterDB(t), 1000) // quota 1000 micros
	assert.True(t, m.Enabled())

	// No row yet => unlimited.
	bal, err := m.Balance(ctx, "actor-1")
	require.NoError(t, err)
	assert.Equal(t, int64(0), bal.Quota)

	// First ingest: initialize remaining = quota - cost = 1000 - 300 = 700.
	res, err := m.Ingest(ctx, IngestRequest{ActorID: "actor-1", UsageType: "tokens", Amount: 300, CostMicros: 300, Model: "m1", RequestID: "r1"})
	require.NoError(t, err)
	assert.True(t, res.Accepted)
	assert.Equal(t, int64(1000), res.Quota)
	assert.Equal(t, int64(700), res.Remaining)

	// Second ingest: 700 - 200 = 500.
	res, err = m.Ingest(ctx, IngestRequest{ActorID: "actor-1", UsageType: "tokens", Amount: 200, CostMicros: 200, Model: "m1", RequestID: "r2"})
	require.NoError(t, err)
	assert.Equal(t, int64(500), res.Remaining)

	// Idempotency: replaying r1 is a no-op (Accepted=false, balance unchanged).
	replay, err := m.Ingest(ctx, IngestRequest{ActorID: "actor-1", UsageType: "tokens", Amount: 300, CostMicros: 300, Model: "m1", RequestID: "r1"})
	require.NoError(t, err)
	assert.False(t, replay.Accepted)
	assert.Equal(t, int64(500), replay.Remaining)

	// Balance read reflects current state.
	bal, err = m.Balance(ctx, "actor-1")
	require.NoError(t, err)
	assert.Equal(t, int64(500), bal.Remaining)
	assert.False(t, bal.Unlimited())
}

func TestDBMeter_ExhaustedReportsNegative(t *testing.T) {
	ctx := context.Background()
	m := NewDBMeter(setupMeterDB(t), 100)

	// Spend 150 against a 100 quota => remaining goes to -50 (caller applies the
	// deny gate when remaining <= 0).
	res, err := m.Ingest(ctx, IngestRequest{ActorID: "actor-2", CostMicros: 150, UsageType: "tokens", Amount: 150, Model: "m", RequestID: "r1"})
	require.NoError(t, err)
	assert.Equal(t, int64(-50), res.Remaining)
	assert.True(t, res.Remaining <= 0) // gate would deny
}
