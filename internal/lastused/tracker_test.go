package lastused

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/talos/internal/contextx"
)

// recorder is a test Flusher that records all batch calls. It reads the NID the
// tracker injects into context via the best-effort accessor, which reflects the
// injected value in both editions (the strict accessor always resolves to
// uuid.Nil in OSS). This verifies the tracker's multi-tenant propagation
// contract.
type recorder struct {
	mu       sync.Mutex
	issued   map[string][]string // nid -> deduplicated key IDs across all flushes
	imported map[string][]string
	calls    atomic.Int64
}

func newRecorder() *recorder {
	return &recorder{
		issued:   make(map[string][]string),
		imported: make(map[string][]string),
	}
}

func (r *recorder) BatchUpdateIssuedAPIKeyLastUsed(ctx context.Context, keyIDs []string) error {
	nid := contextx.NetworkIDFromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls.Add(1)
	r.issued[nid.String()] = append(r.issued[nid.String()], keyIDs...)
	return nil
}

func (r *recorder) BatchUpdateImportedAPIKeyLastUsed(ctx context.Context, keyIDs []string) error {
	nid := contextx.NetworkIDFromContext(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls.Add(1)
	r.imported[nid.String()] = append(r.imported[nid.String()], keyIDs...)
	return nil
}

func (r *recorder) issuedKeys(nid uuid.UUID) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.issued[nid.String()]
}

func (r *recorder) importedKeys(nid uuid.UUID) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.imported[nid.String()]
}

func TestNew_PanicsOnInvalidConfig(t *testing.T) {
	t.Parallel()
	rec := newRecorder()

	t.Run("zero FlushInterval", func(t *testing.T) {
		t.Parallel()
		assert.PanicsWithValue(t, "lastused: FlushInterval must be positive", func() {
			New(t.Context(), rec, Config{QueueSize: 100, FlushSize: 10, FlushInterval: 0, NumWorkers: 1})
		})
	})
	t.Run("zero QueueSize", func(t *testing.T) {
		t.Parallel()
		assert.PanicsWithValue(t, "lastused: QueueSize must be positive", func() {
			New(t.Context(), rec, Config{QueueSize: 0, FlushSize: 10, FlushInterval: time.Second, NumWorkers: 1})
		})
	})
	t.Run("zero NumWorkers", func(t *testing.T) {
		t.Parallel()
		assert.PanicsWithValue(t, "lastused: NumWorkers must be positive", func() {
			New(t.Context(), rec, Config{QueueSize: 100, FlushSize: 10, FlushInterval: time.Second, NumWorkers: 0})
		})
	})
}

func TestTracker_FlushOnSize(t *testing.T) {
	t.Parallel()

	rec := newRecorder()
	tr := New(t.Context(), rec, Config{
		QueueSize:     1000,
		FlushSize:     3,
		FlushInterval: time.Hour, // won't fire during test
		NumWorkers:    1,
	})
	t.Cleanup(tr.Close)

	nid1 := uuid.Must(uuid.NewV4())

	// Publish 3 distinct keys to reach FlushSize=3
	tr.Publish("key-a", nid1, false)
	tr.Publish("key-b", nid1, false)
	tr.Publish("key-c", nid1, false)

	// Give worker time to process and flush
	require.Eventually(t, func() bool {
		return len(rec.issuedKeys(nid1)) >= 3
	}, 2*time.Second, 10*time.Millisecond)

	keys := rec.issuedKeys(nid1)
	assert.Len(t, keys, 3)
	assert.ElementsMatch(t, []string{"key-a", "key-b", "key-c"}, keys)
}

func TestTracker_FlushOnInterval(t *testing.T) {
	t.Parallel()

	rec := newRecorder()
	tr := New(t.Context(), rec, Config{
		QueueSize:     1000,
		FlushSize:     1000, // won't hit size threshold
		FlushInterval: 50 * time.Millisecond,
		NumWorkers:    1,
	})
	t.Cleanup(tr.Close)

	nid1 := uuid.Must(uuid.NewV4())
	tr.Publish("key-a", nid1, false)

	require.Eventually(t, func() bool {
		return len(rec.issuedKeys(nid1)) >= 1
	}, 2*time.Second, 10*time.Millisecond)
}

func TestTracker_Deduplication(t *testing.T) {
	t.Parallel()

	rec := newRecorder()
	tr := New(t.Context(), rec, Config{
		QueueSize:     1000,
		FlushSize:     1000, // won't hit size threshold
		FlushInterval: 50 * time.Millisecond,
		NumWorkers:    1,
	})
	t.Cleanup(tr.Close)

	nid1 := uuid.Must(uuid.NewV4())

	// Publish same key multiple times
	for range 10 {
		tr.Publish("key-dup", nid1, false)
	}

	require.Eventually(t, func() bool {
		return len(rec.issuedKeys(nid1)) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	// Should be deduplicated to 1
	assert.Equal(t, []string{"key-dup"}, rec.issuedKeys(nid1))
}

func TestTracker_MultiShard(t *testing.T) {
	t.Parallel()

	rec := newRecorder()
	tr := New(t.Context(), rec, Config{
		QueueSize:     1000,
		FlushSize:     1000,
		FlushInterval: 50 * time.Millisecond,
		NumWorkers:    1,
	})
	t.Cleanup(tr.Close)

	nidA := uuid.Must(uuid.NewV4())
	nidB := uuid.Must(uuid.NewV4())

	tr.Publish("key-1", nidA, false) // issued, nid-a
	tr.Publish("key-2", nidA, true)  // imported, nid-a
	tr.Publish("key-3", nidB, false) // issued, nid-b

	require.Eventually(t, func() bool {
		return len(rec.issuedKeys(nidA)) >= 1 &&
			len(rec.importedKeys(nidA)) >= 1 &&
			len(rec.issuedKeys(nidB)) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, []string{"key-1"}, rec.issuedKeys(nidA))
	assert.Equal(t, []string{"key-2"}, rec.importedKeys(nidA))
	assert.Equal(t, []string{"key-3"}, rec.issuedKeys(nidB))
}

func TestTracker_OverflowDrops(t *testing.T) {
	t.Parallel()

	rec := newRecorder()
	// Tiny queue that will overflow
	tr := New(t.Context(), rec, Config{
		QueueSize:     1,
		FlushSize:     1000,
		FlushInterval: time.Hour,
		NumWorkers:    1,
	})
	t.Cleanup(tr.Close)

	nid1 := uuid.Must(uuid.NewV4())

	// Flood the queue — should not block
	for i := range 100 {
		tr.Publish("key-"+string(rune('a'+i%26)), nid1, false)
	}
	// If we got here without blocking, the test passes (non-blocking)
}

func TestTracker_GracefulShutdown(t *testing.T) {
	t.Parallel()

	rec := newRecorder()
	tr := New(t.Context(), rec, Config{
		QueueSize:     1000,
		FlushSize:     1000,      // won't hit size threshold
		FlushInterval: time.Hour, // won't fire
		NumWorkers:    2,
	})

	nid1 := uuid.Must(uuid.NewV4())

	// Publish items then immediately close
	for i := range 5 {
		tr.Publish("key-"+string(rune('a'+i)), nid1, false)
	}

	// Close should drain pending items
	tr.Close()

	// All 5 unique keys should have been flushed during shutdown
	keys := rec.issuedKeys(nid1)
	assert.Len(t, keys, 5)
}

func TestTracker_CloseIdempotent(t *testing.T) {
	t.Parallel()

	rec := newRecorder()
	tr := New(t.Context(), rec, Config{
		QueueSize:     100,
		FlushSize:     100,
		FlushInterval: time.Hour,
		NumWorkers:    1,
	})

	tr.Close()
	tr.Close() // Should not panic
}

// TestTracker_FlushInjectsNIDIntoContext verifies the tracker injects the
// shard's NID into ctx before calling the Flusher. Drivers derive NID from
// context, so this property is the multi-tenant safety invariant.
func TestTracker_FlushInjectsNIDIntoContext(t *testing.T) {
	t.Parallel()

	var (
		mu             sync.Mutex
		seenNIDs       []uuid.UUID
		seenContextSet bool
	)
	stub := flusherFunc{
		issued: func(ctx context.Context, _ []string) error {
			mu.Lock()
			defer mu.Unlock()
			seenNIDs = append(seenNIDs, contextx.NetworkIDFromContext(ctx))
			seenContextSet = ctx != nil
			return nil
		},
		imported: func(ctx context.Context, _ []string) error {
			mu.Lock()
			defer mu.Unlock()
			seenNIDs = append(seenNIDs, contextx.NetworkIDFromContext(ctx))
			return nil
		},
	}

	tr := New(t.Context(), stub, Config{
		QueueSize: 100, FlushSize: 1, FlushInterval: time.Hour, NumWorkers: 1,
	})
	t.Cleanup(tr.Close)

	want := uuid.Must(uuid.NewV4())
	tr.Publish("key-1", want, false)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(seenNIDs) == 1
	}, 2*time.Second, 10*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, want, seenNIDs[0])
	assert.True(t, seenContextSet)
}

type flusherFunc struct {
	issued   func(ctx context.Context, keyIDs []string) error
	imported func(ctx context.Context, keyIDs []string) error
}

func (f flusherFunc) BatchUpdateIssuedAPIKeyLastUsed(ctx context.Context, keyIDs []string) error {
	return f.issued(ctx, keyIDs)
}

func (f flusherFunc) BatchUpdateImportedAPIKeyLastUsed(ctx context.Context, keyIDs []string) error {
	return f.imported(ctx, keyIDs)
}
