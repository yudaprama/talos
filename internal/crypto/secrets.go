package crypto

import (
	"context"
	"slices"

	"github.com/cockroachdb/errors"

	talosconfig "github.com/ory-corp/talos/internal/config"
)

// ConfigProvider defines configuration methods used by crypto helpers.
type ConfigProvider interface {
	String(ctx context.Context, key talosconfig.Key) string
	Strings(ctx context.Context, key talosconfig.Key) []string
}

// HMACSecretsForVerification returns all HMAC secrets (current + retired) for verification.
// Returns an error if the project has no HMAC key configured.
// Returns: [current, ...retired] so that keys signed with a retired secret still verify.
func HMACSecretsForVerification(ctx context.Context, provider ConfigProvider) ([]string, error) {
	current := provider.String(ctx, talosconfig.KeySecretsHMACCurrent)
	if current == "" {
		return nil, errors.New("project has no HMAC key configured")
	}

	retired := provider.Strings(ctx, talosconfig.KeySecretsHMACRetired)
	return slices.Concat([]string{current}, retired), nil
}

// HMACSecretForSigning returns the current HMAC secret for signing new keys.
// Returns an error if the project has no HMAC key configured.
func HMACSecretForSigning(ctx context.Context, provider ConfigProvider) (string, error) {
	current := provider.String(ctx, talosconfig.KeySecretsHMACCurrent)
	if current == "" {
		return "", errors.New("project has no HMAC key configured")
	}
	return current, nil
}

// DefaultSecrets returns all default secrets (current + retired) for verification.
// Used by components that fall back to default secret (e.g., pagination).
func DefaultSecrets(ctx context.Context, provider ConfigProvider) []string {
	current := provider.String(ctx, talosconfig.KeySecretsDefaultCurrent)
	retired := provider.Strings(ctx, talosconfig.KeySecretsDefaultRetired)
	return slices.Concat([]string{current}, retired)
}

// reviewed - @aeneasr - 2026-03-26
