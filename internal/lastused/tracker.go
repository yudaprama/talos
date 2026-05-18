// Package lastused provides a batched queue for last_used_at timestamp updates.
// It collects Publish calls, deduplicates by (nid, imported, keyID), and flushes
// batched UPDATEs on size or time thresholds.
package lastused

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/gofrs/uuid"

	"github.com/ory-corp/talos/internal/contextx"
)

// flushTimeout bounds each batch DB write so a slow or unreachable database
// cannot stall a worker indefinitely.
const flushTimeout = 10 * time.Second

// Flusher is the narrow persistence interface for batch last-used updates.
// Implementations extract NID from the context, which the tracker injects
// per shard before each call.
type Flusher interface {
	BatchUpdateIssuedAPIKeyLastUsed(ctx context.Context, keyIDs []string) error
	BatchUpdateImportedAPIKeyLastUsed(ctx context.Context, keyIDs []string) error
}

// Config holds Tracker configuration. All fields are immutable after construction.
type Config struct {
	QueueSize     int
	FlushSize     int
	FlushInterval time.Duration
	NumWorkers    int
}

type entry struct {
	keyID    string
	nid      uuid.UUID
	imported bool
}

type shardKey struct {
	nid      uuid.UUID
	imported bool
}

// Tracker collects last-used update signals, deduplicates them,
// and flushes batched UPDATEs on size or time thresholds.
type Tracker struct {
	flusher   Flusher
	config    Config
	queue     chan entry
	workers   sync.WaitGroup
	closeOnce sync.Once
}

// New creates a Tracker and starts worker goroutines. The context controls
// the lifetime of interval flushes; cancelling it does not stop the tracker
// (call Close for that) but does cancel in-flight flushes.
// Panics if cfg contains invalid values (zero FlushInterval, QueueSize, or NumWorkers)
// because these would cause runtime failures (ticker panic, silent drops, no processing).
func New(ctx context.Context, flusher Flusher, cfg Config) *Tracker {
	if cfg.FlushInterval <= 0 {
		panic("lastused: FlushInterval must be positive")
	}
	if cfg.QueueSize <= 0 {
		panic("lastused: QueueSize must be positive")
	}
	if cfg.NumWorkers <= 0 {
		panic("lastused: NumWorkers must be positive")
	}

	t := &Tracker{
		flusher: flusher,
		config:  cfg,
		queue:   make(chan entry, cfg.QueueSize),
	}

	t.workers.Add(cfg.NumWorkers)
	for range cfg.NumWorkers {
		go t.worker(ctx)
	}

	return t
}

// Publish enqueues a last-used update. Non-blocking: drops on overflow.
func (t *Tracker) Publish(keyID string, nid uuid.UUID, imported bool) {
	select {
	case t.queue <- entry{keyID: keyID, nid: nid, imported: imported}:
	default:
		// Queue full — drop silently. ShouldUpdateLastUsed debounces to once/day per key.
	}
}

// Close gracefully shuts down workers and drains remaining entries.
// Safe to call multiple times.
func (t *Tracker) Close() {
	t.closeOnce.Do(func() {
		close(t.queue)
		t.workers.Wait()
	})
}

// worker reads from the shared queue, deduplicates entries per shard,
// and flushes when a shard reaches FlushSize or the flush interval fires.
// ctx scopes interval flushes; the final drain uses context.WithoutCancel so
// pending updates still land after a parent cancel.
func (t *Tracker) worker(ctx context.Context) {
	defer t.workers.Done()

	shards := make(map[shardKey]map[string]struct{})
	ticker := time.NewTicker(t.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case e, ok := <-t.queue:
			if !ok {
				// Channel closed — final flush. Detach from ctx so a cancelled
				// parent (typical during shutdown) does not abort the drain.
				drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), flushTimeout)
				t.flushAll(drainCtx, shards)
				cancel()
				return
			}
			sk := shardKey{nid: e.nid, imported: e.imported}
			if shards[sk] == nil {
				shards[sk] = make(map[string]struct{})
			}
			shards[sk][e.keyID] = struct{}{}

			if len(shards[sk]) >= t.config.FlushSize {
				t.flushShard(ctx, sk, shards[sk])
				delete(shards, sk)
			}

		case <-ticker.C:
			t.flushAll(ctx, shards)
			shards = make(map[shardKey]map[string]struct{})
		}
	}
}

// flushAll flushes all shards using ctx, bounded by flushTimeout per shard.
func (t *Tracker) flushAll(ctx context.Context, shards map[shardKey]map[string]struct{}) {
	for sk, keys := range shards {
		t.flushShard(ctx, sk, keys)
	}
}

// flushShard sends a batch update for a single shard under a flushTimeout deadline.
// It injects the shard NID into the context so the Flusher derives NID via the
// standard context-based path.
func (t *Tracker) flushShard(ctx context.Context, sk shardKey, keys map[string]struct{}) {
	if len(keys) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, flushTimeout)
	defer cancel()

	ctx = context.WithValue(ctx, contextx.NIDKey{}, sk.nid)
	keyIDs := slices.Collect(maps.Keys(keys))

	var err error
	if sk.imported {
		err = t.flusher.BatchUpdateImportedAPIKeyLastUsed(ctx, keyIDs)
	} else {
		err = t.flusher.BatchUpdateIssuedAPIKeyLastUsed(ctx, keyIDs)
	}
	if err != nil {
		slog.Error("batch update last_used_at",
			slog.String("nid", sk.nid.String()),
			slog.Bool("imported", sk.imported),
			slog.Int("batch_size", len(keyIDs)),
			slog.Any("error", err))
	}
}
