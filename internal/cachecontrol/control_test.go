package cachecontrol_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ory-corp/talos/internal/cachecontrol"
)

func TestCacheControl_ContextStorage(t *testing.T) {
	t.Parallel()

	t.Run("empty context returns zero value", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cc := cachecontrol.FromContext(ctx)
		assert.False(t, cc.NoCache)
		assert.False(t, cc.NoStore)
	})

	t.Run("stores and retrieves NoCache directive", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cc := cachecontrol.CacheControl{NoCache: true}
		ctx = cachecontrol.WithCacheControl(ctx, cc)

		retrieved := cachecontrol.FromContext(ctx)
		assert.True(t, retrieved.NoCache)
		assert.False(t, retrieved.NoStore)
	})

	t.Run("stores and retrieves NoStore directive", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cc := cachecontrol.CacheControl{NoStore: true}
		ctx = cachecontrol.WithCacheControl(ctx, cc)

		retrieved := cachecontrol.FromContext(ctx)
		assert.False(t, retrieved.NoCache)
		assert.True(t, retrieved.NoStore)
	})

	t.Run("stores and retrieves both directives", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cc := cachecontrol.CacheControl{NoCache: true, NoStore: true}
		ctx = cachecontrol.WithCacheControl(ctx, cc)

		retrieved := cachecontrol.FromContext(ctx)
		assert.True(t, retrieved.NoCache)
		assert.True(t, retrieved.NoStore)
	})
}

func TestShouldBypassCache(t *testing.T) {
	t.Parallel()

	t.Run("no directives - does not bypass", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		assert.False(t, cachecontrol.ShouldBypassCache(ctx))
	})

	t.Run("NoCache directive - bypasses cache", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cc := cachecontrol.CacheControl{NoCache: true}
		ctx = cachecontrol.WithCacheControl(ctx, cc)

		assert.True(t, cachecontrol.ShouldBypassCache(ctx))
	})

	t.Run("NoStore directive - bypasses cache", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cc := cachecontrol.CacheControl{NoStore: true}
		ctx = cachecontrol.WithCacheControl(ctx, cc)

		assert.True(t, cachecontrol.ShouldBypassCache(ctx))
	})

	t.Run("both directives - bypasses cache", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		cc := cachecontrol.CacheControl{NoCache: true, NoStore: true}
		ctx = cachecontrol.WithCacheControl(ctx, cc)

		assert.True(t, cachecontrol.ShouldBypassCache(ctx))
	})
}

func TestComputeCacheTTL(t *testing.T) {
	t.Parallel()

	const configTTL = 10 * time.Minute

	t.Run("nil expiry returns configTTL", func(t *testing.T) {
		t.Parallel()
		got, ok := cachecontrol.ComputeCacheTTL(configTTL, nil)
		assert.True(t, ok)
		assert.Equal(t, configTTL, got)
	})

	t.Run("expiry further than configTTL returns configTTL", func(t *testing.T) {
		t.Parallel()
		exp := time.Now().Add(30 * time.Minute)
		got, ok := cachecontrol.ComputeCacheTTL(configTTL, &exp)
		assert.True(t, ok)
		assert.Equal(t, configTTL, got)
	})

	t.Run("expiry less than configTTL returns time until expiry", func(t *testing.T) {
		t.Parallel()
		exp := time.Now().Add(5 * time.Minute)
		got, ok := cachecontrol.ComputeCacheTTL(configTTL, &exp)
		assert.True(t, ok)
		assert.InDelta(t, (5 * time.Minute).Seconds(), got.Seconds(), 1.0)
	})

	t.Run("already expired is not cacheable", func(t *testing.T) {
		t.Parallel()
		exp := time.Now().Add(-1 * time.Minute)
		got, ok := cachecontrol.ComputeCacheTTL(configTTL, &exp)
		assert.False(t, ok)
		assert.Equal(t, time.Duration(0), got)
	})

	t.Run("expiring within minCacheDuration is not cacheable", func(t *testing.T) {
		t.Parallel()
		exp := time.Now().Add(500 * time.Millisecond)
		got, ok := cachecontrol.ComputeCacheTTL(configTTL, &exp)
		assert.False(t, ok)
		assert.Equal(t, time.Duration(0), got)
	})
}

// reviewed - @aeneasr - 2026-03-25
