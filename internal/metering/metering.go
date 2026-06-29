// Package metering defines the usage-metering interface and implementations for
// the metering fork (Talos OSS has no metering; the commercial edition does).
//
// It mirrors internal/ratelimit: a Meter interface with a no-op default plus a
// real DB-backed implementation. The DBMeter is backed by Talos's own
// PostgreSQL store, running hand-written SQL over the shared connection.
package metering

import (
	"context"
	"database/sql"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/jmoiron/sqlx"

	"github.com/ory/talos/internal/contextx"
)

// Balance is the per-actor balance snapshot used by the VerifyApiKey pre-check.
// All amounts are integer micros (cost x 1_000_000) to avoid float money math.
// Quota == 0 means unlimited (no enforcement).
type Balance struct {
	Quota     int64
	Remaining int64
}

// Unlimited reports whether the balance enforces no cap.
func (b *Balance) Unlimited() bool { return b == nil || b.Quota == 0 }

// Meter records usage and reports balance.
type Meter interface {
	// Balance returns the actor's current balance. A non-existent balance is
	// reported as unlimited (Quota 0). Used by the VerifyApiKey pre-check.
	Balance(ctx context.Context, actorID string) (*Balance, error)
	// Ingest records one usage event and atomically debits the actor's balance.
	// Idempotent on RequestID (returns the current balance with Accepted=false).
	Ingest(ctx context.Context, req IngestRequest) (*IngestResult, error)
	// SetQuota sets the actor's quota and resets remaining to the same value (a
	// fresh grant — assign/change a plan/tier). Creates the row if absent.
	// quotaMicros 0 = unlimited. Returns the resulting balance.
	SetQuota(ctx context.Context, actorID string, quotaMicros int64) (*Balance, error)
	// TopUp adds credits to the actor's remaining balance without changing its
	// quota. Creates the row if absent (quota and remaining set to amountMicros).
	// Returns the resulting balance.
	TopUp(ctx context.Context, actorID string, amountMicros int64) (*Balance, error)
	// Enabled reports whether metering is active (false for the no-op).
	Enabled() bool
}

// IngestRequest is a single usage event to record.
type IngestRequest struct {
	ActorID    string
	KeyID      string // optional
	UsageType  string // e.g. "tokens"
	Amount     int64  // e.g. prompt+completion token count
	CostMicros int64  // cost x 1_000_000 (this is what gets debited)
	Model      string
	RequestID  string // optional idempotency key (AIP-155)
}

// IngestResult is the outcome of an Ingest call.
type IngestResult struct {
	*Balance
	Accepted bool // false if a duplicate RequestID was ignored
}

// NoopMeter disables metering: balance is unlimited and Ingest records nothing.
type NoopMeter struct{}

// Balance returns an unlimited balance.
func (NoopMeter) Balance(context.Context, string) (*Balance, error) { return &Balance{}, nil }

// Ingest reports acceptance without recording.
func (NoopMeter) Ingest(context.Context, IngestRequest) (*IngestResult, error) {
	return &IngestResult{Balance: &Balance{}, Accepted: true}, nil
}

// SetQuota records nothing and returns an unlimited balance.
func (NoopMeter) SetQuota(context.Context, string, int64) (*Balance, error) {
	return &Balance{}, nil
}

// TopUp records nothing and returns an unlimited balance.
func (NoopMeter) TopUp(context.Context, string, int64) (*Balance, error) {
	return &Balance{}, nil
}

// Enabled reports false: the no-op meter performs no tracking.
func (NoopMeter) Enabled() bool { return false }

// DBMeter is the DB-backed meter. It runs hand-written PostgreSQL over the
// shared connection. DefaultQuotaMicros is the grant applied on an actor's first
// usage; 0 = unlimited (metering tracks usage but does not gate until a quota is
// configured).
//
// remaining is allowed to go negative: a negative balance is the accurate record
// of an overdraft that already occurred (async billing lags the verify-time
// pre-check), and is required so that a later TopUp/SetQuota nets correctly
// against the debt. Clamping to zero would silently grant free usage.
type DBMeter struct {
	conn               *sqlx.DB
	defaultQuotaMicros int64
}

// NewDBMeter constructs a DBMeter over an existing connection.
func NewDBMeter(conn *sqlx.DB, defaultQuotaMicros int64) *DBMeter {
	return &DBMeter{conn: conn, defaultQuotaMicros: defaultQuotaMicros}
}

// Enabled reports true.
func (m *DBMeter) Enabled() bool { return true }

// Balance returns the actor's cached balance (unlimited if no row exists).
func (m *DBMeter) Balance(ctx context.Context, actorID string) (*Balance, error) {
	nid := contextx.NetworkIDFromContext(ctx).String()
	var bal Balance
	err := m.conn.QueryRowContext(ctx,
		`SELECT quota, remaining FROM actor_balances WHERE nid = $1 AND actor_id = $2`,
		nid, actorID,
	).Scan(&bal.Quota, &bal.Remaining)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &Balance{Quota: 0, Remaining: 0}, nil // unlimited
		}
		return nil, err
	}
	return &bal, nil
}

// Ingest records one usage event and atomically debits the balance in a single
// transaction. Idempotent on RequestID. The debit is a single upsert
// (ON CONFLICT DO UPDATE) — Postgres has no SQLite arg-expansion limitation — so
// row-initialization and debit collapse into one statement with no TOCTOU gap.
func (m *DBMeter) Ingest(ctx context.Context, req IngestRequest) (*IngestResult, error) {
	nid := contextx.NetworkIDFromContext(ctx).String()
	now := time.Now().UTC()

	var reqID *string
	if req.RequestID != "" {
		rid := req.RequestID
		reqID = &rid
		// Idempotency: already recorded → no-op, return current balance.
		var one int
		err := m.conn.QueryRowContext(ctx,
			`SELECT 1 FROM api_key_usage WHERE nid = $1 AND request_id = $2 LIMIT 1`,
			nid, reqID,
		).Scan(&one)
		switch {
		case err == nil:
			bal, bErr := m.Balance(ctx, req.ActorID)
			if bErr != nil {
				return nil, bErr
			}
			return &IngestResult{Balance: bal, Accepted: false}, nil
		case !errors.Is(err, sql.ErrNoRows):
			return nil, err
		}
	}

	var keyID *string
	if req.KeyID != "" {
		k := req.KeyID
		keyID = &k
	}

	tx, err := m.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO api_key_usage (nid, actor_id, key_id, usage_type, usage_amount, cost_micros, model, request_id, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		nid, req.ActorID, keyID, req.UsageType, req.Amount, req.CostMicros, req.Model, reqID, now,
	); err != nil {
		return nil, err
	}

	// Atomic upsert debit: seed the row with the default grant on first use
	// (remaining = grant - cost), otherwise decrement the existing remaining.
	var bal Balance
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO actor_balances (nid, actor_id, quota, remaining, updated_at)
		 VALUES ($1, $2, $3, $3 - $4, $5)
		 ON CONFLICT (nid, actor_id) DO UPDATE
		 SET remaining = actor_balances.remaining - $4, updated_at = $5
		 RETURNING quota, remaining`,
		nid, req.ActorID, m.defaultQuotaMicros, req.CostMicros, now,
	).Scan(&bal.Quota, &bal.Remaining); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &IngestResult{Balance: &bal, Accepted: true}, nil
}

// SetQuota sets the actor's quota and resets remaining to the same value (a fresh
// grant) in one atomic upsert.
func (m *DBMeter) SetQuota(ctx context.Context, actorID string, quotaMicros int64) (*Balance, error) {
	nid := contextx.NetworkIDFromContext(ctx).String()
	now := time.Now().UTC()

	var bal Balance
	if err := m.conn.QueryRowContext(ctx,
		`INSERT INTO actor_balances (nid, actor_id, quota, remaining, updated_at)
		 VALUES ($1, $2, $3, $3, $4)
		 ON CONFLICT (nid, actor_id) DO UPDATE
		 SET quota = $3, remaining = $3, updated_at = $4
		 RETURNING quota, remaining`,
		nid, actorID, quotaMicros, now,
	).Scan(&bal.Quota, &bal.Remaining); err != nil {
		return nil, err
	}
	return &bal, nil
}

// TopUp adds credits to the actor's remaining balance without changing its quota
// in one atomic upsert. If the row is absent it is created with
// quota = remaining = amountMicros; if it exists, only remaining is incremented
// (quota unchanged), so an existing grant is never double-counted.
func (m *DBMeter) TopUp(ctx context.Context, actorID string, amountMicros int64) (*Balance, error) {
	nid := contextx.NetworkIDFromContext(ctx).String()
	now := time.Now().UTC()

	var bal Balance
	if err := m.conn.QueryRowContext(ctx,
		`INSERT INTO actor_balances (nid, actor_id, quota, remaining, updated_at)
		 VALUES ($1, $2, $3, $3, $4)
		 ON CONFLICT (nid, actor_id) DO UPDATE
		 SET remaining = actor_balances.remaining + $3, updated_at = $4
		 RETURNING quota, remaining`,
		nid, actorID, amountMicros, now,
	).Scan(&bal.Quota, &bal.Remaining); err != nil {
		return nil, err
	}
	return &bal, nil
}
