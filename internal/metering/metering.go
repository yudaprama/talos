// Package metering defines the usage-metering interface and implementations for
// the metering fork (Talos OSS has no metering; the commercial edition does).
//
// It mirrors internal/ratelimit: a Meter interface with a no-op default plus a
// real DB-backed implementation. Unlike rate limiting (no-op in OSS), the OSS
// DBMeter is a real implementation backed by Talos's own SQLite store — it owns
// its db.Queries over the SQLite connection.
package metering

import (
	"context"
	"database/sql"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/jmoiron/sqlx"

	"github.com/ory/talos/internal/contextx"
	db "github.com/ory/talos/internal/persistence/sqlc/generated"
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

// DBMeter is the OSS DB-backed meter. It owns its own db.Queries over the SQLite
// connection (OSS is single-backend SQLite). DefaultQuotaMicros is the grant
// applied on an actor's first usage; 0 = unlimited (metering tracks usage but
// does not gate until a quota is configured).
type DBMeter struct {
	conn               *sqlx.DB
	q                  *db.Queries
	defaultQuotaMicros int64
}

// NewDBMeter constructs a DBMeter over an existing SQLite connection.
func NewDBMeter(conn *sqlx.DB, defaultQuotaMicros int64) *DBMeter {
	return &DBMeter{conn: conn, q: db.New(conn.DB), defaultQuotaMicros: defaultQuotaMicros}
}

// Enabled reports true.
func (m *DBMeter) Enabled() bool { return true }

// Balance returns the actor's cached balance (unlimited if no row exists).
func (m *DBMeter) Balance(ctx context.Context, actorID string) (*Balance, error) {
	row, err := m.q.GetActorBalance(ctx, contextx.NetworkIDFromContext(ctx).String(), actorID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &Balance{Quota: 0, Remaining: 0}, nil // unlimited
		}
		return nil, err
	}
	return &Balance{Quota: row.Quota, Remaining: row.Remaining}, nil
}

// Ingest records one usage event and atomically debits the balance in a single
// transaction. Idempotent on RequestID.
func (m *DBMeter) Ingest(ctx context.Context, req IngestRequest) (*IngestResult, error) {
	nid := contextx.NetworkIDFromContext(ctx).String()
	now := time.Now().UTC()

	var reqID *string
	if req.RequestID != "" {
		rid := req.RequestID
		reqID = &rid
		// Idempotency: already recorded → no-op, return current balance.
		if _, err := m.q.GetUsageByRequestID(ctx, nid, reqID); err == nil {
			bal, bErr := m.Balance(ctx, req.ActorID)
			if bErr != nil {
				return nil, bErr
			}
			return &IngestResult{Balance: bal, Accepted: false}, nil
		} else if !errors.Is(err, sql.ErrNoRows) {
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
	qtx := m.q.WithTx(tx)

	if err := qtx.InsertUsage(ctx, db.InsertUsageParams{
		NID:         nid,
		ActorID:     req.ActorID,
		KeyID:       keyID,
		UsageType:   req.UsageType,
		UsageAmount: req.Amount,
		CostMicros:  req.CostMicros,
		Model:       req.Model,
		RequestID:   reqID,
		CreatedAt:   now,
	}); err != nil {
		return nil, err
	}

	// Initialize the actor's balance row on first use (no-op if it exists), then
	// debit. Split because sqlc's SQLite engine can't expand args inside
	// ON CONFLICT ... DO UPDATE SET, so init uses ON CONFLICT DO NOTHING + a plain
	// UPDATE debit.
	if _, err := qtx.GetActorBalance(ctx, nid, req.ActorID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err := qtx.InsertActorBalanceIfAbsent(ctx, db.InsertActorBalanceIfAbsentParams{
			NID:       nid,
			ActorID:   req.ActorID,
			Quota:     m.defaultQuotaMicros,
			UpdatedAt: now,
		}); err != nil {
			return nil, err
		}
	}

	row, err := qtx.DebitActorBalance(ctx, db.DebitActorBalanceParams{
		NID:       nid,
		ActorID:   req.ActorID,
		Amount:    req.CostMicros,
		UpdatedAt: now,
	})
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &IngestResult{
		Balance:  &Balance{Quota: row.Quota, Remaining: row.Remaining},
		Accepted: true,
	}, nil
}

// SetQuota sets the actor's quota and resets remaining to the same value in a
// single transaction. Initializes the row first (no-op if it exists), then
// overwrites quota + remaining — the same split-statement pattern as Ingest,
// because sqlc's SQLite engine cannot expand args inside ON CONFLICT DO UPDATE.
func (m *DBMeter) SetQuota(ctx context.Context, actorID string, quotaMicros int64) (*Balance, error) {
	nid := contextx.NetworkIDFromContext(ctx).String()
	now := time.Now().UTC()

	tx, err := m.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := m.q.WithTx(tx)

	if err := qtx.InsertActorBalanceIfAbsent(ctx, db.InsertActorBalanceIfAbsentParams{
		NID:       nid,
		ActorID:   actorID,
		Quota:     quotaMicros,
		UpdatedAt: now,
	}); err != nil {
		return nil, err
	}
	row, err := qtx.SetActorBalance(ctx, db.SetActorBalanceParams{
		NID:       nid,
		ActorID:   actorID,
		Quota:     quotaMicros,
		Remaining: quotaMicros,
		UpdatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Balance{Quota: row.Quota, Remaining: row.Remaining}, nil
}

// TopUp adds credits to the actor's remaining balance in a single transaction.
// If the row is absent it is created with quota = remaining = amountMicros; if it
// exists, only remaining is incremented (quota unchanged). The existence check
// guards against double-counting the initial grant (mirrors Ingest).
func (m *DBMeter) TopUp(ctx context.Context, actorID string, amountMicros int64) (*Balance, error) {
	nid := contextx.NetworkIDFromContext(ctx).String()
	now := time.Now().UTC()

	tx, err := m.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := m.q.WithTx(tx)

	if _, err := qtx.GetActorBalance(ctx, nid, actorID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		// Absent: seed with quota = remaining = amount, then commit (no add — the
		// seed already credits the full amount).
		if err := qtx.InsertActorBalanceIfAbsent(ctx, db.InsertActorBalanceIfAbsentParams{
			NID:       nid,
			ActorID:   actorID,
			Quota:     amountMicros,
			UpdatedAt: now,
		}); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &Balance{Quota: amountMicros, Remaining: amountMicros}, nil
	}

	row, err := qtx.TopUpActorBalance(ctx, db.TopUpActorBalanceParams{
		NID:       nid,
		ActorID:   actorID,
		Amount:    amountMicros,
		UpdatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Balance{Quota: row.Quota, Remaining: row.Remaining}, nil
}
