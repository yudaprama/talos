package metering

import (
	"context"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/testutil"
)

// setupMeterDB provisions an isolated, migrated PostgreSQL schema (with the OSS
// NID row created by the driver's Initialize) and returns its connection. The
// metering SQL is exercised against the real production schema. Skips when
// TALOS_TEST_DATABASE_URL is unset.
func setupMeterDB(t *testing.T) *sqlx.DB {
	t.Helper()
	driver, err := testutil.InitDriver(t, "")
	require.NoError(t, err)
	return driver.Conn()
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
	sq, err := m.SetQuota(ctx, "x", 100)
	require.NoError(t, err)
	assert.True(t, sq.Unlimited()) // no-op meter never persists a quota
	tu, err := m.TopUp(ctx, "x", 100)
	require.NoError(t, err)
	assert.True(t, tu.Unlimited())
}

func TestDBMeter_SetQuota(t *testing.T) {
	ctx := context.Background()
	m := NewDBMeter(setupMeterDB(t), 0) // global default unlimited

	// Set a quota on an actor with no row yet → creates it as a fresh grant.
	bal, err := m.SetQuota(ctx, "actor-1", 1000)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), bal.Quota)
	assert.Equal(t, int64(1000), bal.Remaining)
	assert.False(t, bal.Unlimited())

	// Spend, then set a new quota → remaining resets to the new quota (fresh plan).
	_, err = m.Ingest(ctx, IngestRequest{ActorID: "actor-1", CostMicros: 400, UsageType: "tokens", Amount: 400, Model: "m", RequestID: "r1"})
	require.NoError(t, err)
	bal, err = m.Balance(ctx, "actor-1")
	require.NoError(t, err)
	assert.Equal(t, int64(600), bal.Remaining)

	bal, err = m.SetQuota(ctx, "actor-1", 5000)
	require.NoError(t, err)
	assert.Equal(t, int64(5000), bal.Quota)
	assert.Equal(t, int64(5000), bal.Remaining) // reset, not 600+...

	// Setting quota 0 makes the actor unlimited (gating off).
	bal, err = m.SetQuota(ctx, "actor-1", 0)
	require.NoError(t, err)
	assert.True(t, bal.Unlimited())
}

func TestDBMeter_TopUp(t *testing.T) {
	ctx := context.Background()
	m := NewDBMeter(setupMeterDB(t), 0)

	// Top up an actor with no row → created with quota = remaining = amount.
	bal, err := m.TopUp(ctx, "actor-1", 1000)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), bal.Quota)
	assert.Equal(t, int64(1000), bal.Remaining)

	// Spend to exhaustion, then top up → remaining increases, quota unchanged.
	_, err = m.Ingest(ctx, IngestRequest{ActorID: "actor-1", CostMicros: 1200, UsageType: "tokens", Amount: 1200, Model: "m", RequestID: "r1"})
	require.NoError(t, err)
	bal, err = m.Balance(ctx, "actor-1")
	require.NoError(t, err)
	assert.Equal(t, int64(-200), bal.Remaining) // exhausted

	bal, err = m.TopUp(ctx, "actor-1", 500)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), bal.Quota)     // quota untouched
	assert.Equal(t, int64(300), bal.Remaining)  // -200 + 500, back above zero
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
