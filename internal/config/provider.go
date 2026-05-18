// Package config provides a context-aware configuration provider built on top of
// github.com/ory/x/configx. It enables hot reloading of configuration values.
//
// Configuration sources are loaded in the following priority order (lowest to highest):
//  1. Default values (defined in this package)
//  2. Configuration files (YAML)
//  3. Unprefixed environment variables (DB_DSN, HTTP_ADDR, etc.)
//  4. TALOS_ prefixed environment variables (TALOS_HTTP_ADDR, etc.)
//
// Environment variables with underscores are converted to dot notation:
//
//	DB_DSN → db.dsn
//	HTTP_ADDR → http.addr
//	TALOS_HTTP_ADDR → http.addr (highest priority)
package config

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/ory-corp/talos/internal/configschema"

	"github.com/ory/x/configx"
)

// ProviderInterface defines the interface for configuration providers.
// Both OSS and commercial implementations must implement this interface.
type ProviderInterface interface {
	String(ctx context.Context, key Key) string
	Strings(ctx context.Context, key Key) []string
	Bool(ctx context.Context, key Key) bool
	Int(ctx context.Context, key Key) int
	Float64(ctx context.Context, key Key) float64
	Duration(ctx context.Context, key Key) time.Duration
	Get(ctx context.Context, key Key) any
	Set(ctx context.Context, key Key, value any) error
	Unmarshal(ctx context.Context, key Key, value any) error
	UnderlyingProvider(ctx context.Context) *configx.Provider
}

// Provider wraps the ory/x/configx provider for configuration access with hot reloading.
// Network-specific configuration overrides are handled by the contextualizer at the
// middleware level, not within this provider.
//
// In OSS builds, this embeds configx.Provider directly, making all methods available.
// In commercial builds, a separate provider implementation extracts config from context.
type Provider struct {
	*configx.Provider
}

// NewProviderWithOptions creates a Provider with custom configx options.
// Used for creating network-specific config providers with overrides.
func NewProviderWithOptions(ctx context.Context, opts ...configx.OptionModifier) (*Provider, error) {
	p, err := configx.New(ctx, configschema.SchemaJSON, append(
		[]configx.OptionModifier{
			configx.WithContext(ctx),
			configx.WithImmutables("db.dsn", "tls.key", "redis.password"),
			configx.WithStderrValidationReporter(),
		},
		opts...,
	)...)
	if err != nil {
		return nil, errors.Wrap(err, "create config provider")
	}

	return &Provider{
		Provider: p,
	}, nil
}

// NewProvider creates a new config provider with hot reload support.
//
// Configuration sources are loaded in priority order:
//  1. Schema defaults (defined in config.schema.json)
//  2. Configuration file (if provided)
//  3. Unprefixed environment variables (DB_DSN, etc.)
//  4. TALOS_ prefixed environment variables (highest priority)
//
// The provider supports hot reloading when configuration files change.
//
// Note: Network-specific configuration overrides are handled by the contextualizer
// at the middleware level, not within this provider.
func NewProvider(ctx context.Context, configFile string) (*Provider, error) {
	opts := []configx.OptionModifier{
		configx.WithContext(ctx),
		configx.WithImmutables("db.dsn", "tls.key", "redis.password"),
		configx.WithStderrValidationReporter(),
	}

	if len(configFile) > 0 {
		opts = append(opts, configx.WithConfigFiles(configFile))
	}

	p, err := configx.New(ctx, configschema.SchemaJSON, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "create config provider")
	}

	return &Provider{
		Provider: p,
	}, nil
}

// String returns the string value for the given config key.
func (p *Provider) String(_ context.Context, key Key) string {
	return p.Provider.String(key.String())
}

// Strings returns the string slice value for the given config key.
func (p *Provider) Strings(_ context.Context, key Key) []string {
	return p.Provider.Strings(key.String())
}

// Bool returns the boolean value for the given config key.
func (p *Provider) Bool(_ context.Context, key Key) bool {
	return p.Provider.Bool(key.String())
}

// Int returns the integer value for the given config key.
func (p *Provider) Int(_ context.Context, key Key) int {
	return p.Provider.Int(key.String())
}

// Float64 returns the float64 value for the given config key.
func (p *Provider) Float64(_ context.Context, key Key) float64 {
	return p.Provider.Float64(key.String())
}

// Duration returns the duration value for the given config key.
func (p *Provider) Duration(_ context.Context, key Key) time.Duration {
	return p.Provider.Duration(key.String())
}

// Get returns the raw value for the given config key.
func (p *Provider) Get(_ context.Context, key Key) any {
	return p.Provider.Get(key.String())
}

// Set updates the value for the given config key.
func (p *Provider) Set(_ context.Context, key Key, value any) error {
	return p.Provider.Set(key.String(), value)
}

// Unmarshal decodes the config value into the provided struct.
func (p *Provider) Unmarshal(_ context.Context, key Key, value any) error {
	return p.Provider.Unmarshal(key.String(), value)
}

// UnderlyingProvider returns the wrapped configx.Provider for direct access.
func (p *Provider) UnderlyingProvider(_ context.Context) *configx.Provider {
	return p.Provider
}

// reviewed - @aeneasr - 2026-03-25
