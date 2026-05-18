package cache

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/ory-corp/talos/internal/contextx"
)

// BuildFullKey constructs a cache key with namespace, network ID from context,
// and a SHA-256 hash of the key material.
// Format: namespace:nid:sha256(key)
//
// The key (typically a raw API credential) is hashed to prevent plaintext
// secret leakage through cache inspection, Redis MONITOR, or memory dumps.
// This provides automatic multi-tenant isolation by extracting the network ID
// from the context and including it in the cache key.
func BuildFullKey(ctx context.Context, namespace, key string) string {
	nid := contextx.NetworkIDFromContext(ctx).String()
	hash := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s:%s:%x", namespace, nid, hash)
}

// reviewed - @aeneasr - 2026-03-25
