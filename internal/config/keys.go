package config

// Key is a type-safe configuration key with compile-time safety.
// The unexported field prevents construction of arbitrary keys outside this package.
type Key struct {
	s string
}

func (k Key) String() string {
	return k.s
}

//nolint:gochecknoglobals // Intentional global constants for type-safe config keys
var (
	// KeyServeHTTPRequestLogExcludeHealthEndpoints excludes health endpoints from request logging.
	KeyServeHTTPRequestLogExcludeHealthEndpoints = Key{s: "serve.http.request_log.exclude_health_endpoints"}
	// KeyServeHTTPHost is the HTTP server listen host.
	KeyServeHTTPHost = Key{s: "serve.http.host"}
	// KeyServeHTTPPort is the HTTP server listen port.
	KeyServeHTTPPort = Key{s: "serve.http.port"}
	// KeyServeMetricsHost is the metrics server listen host.
	KeyServeMetricsHost = Key{s: "serve.metrics.host"}
	// KeyServeMetricsPort is the metrics server listen port.
	KeyServeMetricsPort = Key{s: "serve.metrics.port"}

	// KeyServeHTTPCORSEnabled enables CORS support.
	KeyServeHTTPCORSEnabled = Key{s: "serve.http.cors.enabled"}
	// KeyServeHTTPCORSAllowedOrigins lists allowed CORS origins.
	KeyServeHTTPCORSAllowedOrigins = Key{s: "serve.http.cors.allowed_origins"}
	// KeyServeHTTPCORSAllowedMethods lists allowed CORS methods.
	KeyServeHTTPCORSAllowedMethods = Key{s: "serve.http.cors.allowed_methods"}
	// KeyServeHTTPCORSAllowedHeaders lists allowed CORS headers.
	KeyServeHTTPCORSAllowedHeaders = Key{s: "serve.http.cors.allowed_headers"}
	// KeyServeHTTPCORSExposedHeaders lists exposed CORS response headers.
	KeyServeHTTPCORSExposedHeaders = Key{s: "serve.http.cors.exposed_headers"}
	// KeyServeHTTPCORSAllowCreds enables CORS credentials.
	KeyServeHTTPCORSAllowCreds = Key{s: "serve.http.cors.allow_credentials"}
	// KeyServeHTTPCORSMaxAge is the CORS preflight cache duration in seconds.
	KeyServeHTTPCORSMaxAge = Key{s: "serve.http.cors.max_age"}
	// KeyServeHTTPCORSDebug enables CORS debug logging.
	KeyServeHTTPCORSDebug = Key{s: "serve.http.cors.debug"}

	// KeyDBDSN is the database connection string. Scheme determines driver.
	KeyDBDSN = Key{s: "db.dsn"}

	// KeyLogLevel is the log verbosity level.
	KeyLogLevel = Key{s: "log.level"}
	// KeyLogFormat is the log output format.
	KeyLogFormat = Key{s: "log.format"}

	// KeyCredentialsAPIKeysDefaultTTL is the default API key time-to-live.
	KeyCredentialsAPIKeysDefaultTTL = Key{s: "credentials.api_keys.default_ttl"}
	// KeyCredentialsAPIKeysMaxTTL is the maximum allowed age for API keys with timestamps.
	KeyCredentialsAPIKeysMaxTTL = Key{s: "credentials.api_keys.max_ttl"}
	// KeyCredentialsAPIKeysPrefixCurrent is the current API key prefix.
	KeyCredentialsAPIKeysPrefixCurrent = Key{s: "credentials.api_keys.prefix.current"}
	// KeyCredentialsAPIKeysPrefixRetired is the retired API key prefix.
	KeyCredentialsAPIKeysPrefixRetired = Key{s: "credentials.api_keys.prefix.retired"}
	// KeyCredentialsAPIKeysPrefixPublicCurrent is the prefix for new public API keys.
	KeyCredentialsAPIKeysPrefixPublicCurrent = Key{s: "credentials.api_keys.prefix.public_current"}
	// KeyCredentialsAPIKeysPrefixPublicRetired lists retired public prefixes for verification.
	KeyCredentialsAPIKeysPrefixPublicRetired = Key{s: "credentials.api_keys.prefix.public_retired"}

	// KeyCredentialsDerivedTokensDefaultTTL is the default derived token time-to-live (applies to both JWT and macaroon tokens).
	KeyCredentialsDerivedTokensDefaultTTL = Key{s: "credentials.derived_tokens.default_ttl"}
	// KeyCredentialsDerivedTokensJWTSigningKeysURLs lists JWT signing key URLs.
	KeyCredentialsDerivedTokensJWTSigningKeysURLs = Key{s: "credentials.derived_tokens.jwt.signing_keys.urls"}
	// KeyCredentialsDerivedTokensJWTSigningKeyID is the optional JWK "kid" used to select the active signing key.
	// If set and no key with that kid exists, signing fails. If unset, the service prefers the first key
	// with use="sig", falling back to the first key in the set.
	KeyCredentialsDerivedTokensJWTSigningKeyID = Key{s: "credentials.derived_tokens.jwt.signing_key_id"}

	// KeyCredentialsDerivedTokensMacaroonPrefixCurrent is the current macaroon token prefix.
	KeyCredentialsDerivedTokensMacaroonPrefixCurrent = Key{s: "credentials.derived_tokens.macaroon.prefix.current"}
	// KeyCredentialsDerivedTokensMacaroonPrefixRetired lists retired macaroon prefixes for rotation.
	KeyCredentialsDerivedTokensMacaroonPrefixRetired = Key{s: "credentials.derived_tokens.macaroon.prefix.retired"}

	// KeyCredentialsIssuer is the token issuer claim for all derived tokens.
	KeyCredentialsIssuer = Key{s: "credentials.issuer"}
	// KeyCredentialsIssuerRetired lists retired issuer URLs accepted during token verification.
	KeyCredentialsIssuerRetired = Key{s: "credentials.issuer_retired"}
	// KeyCredentialsClockSkew is the maximum allowed clock skew for timestamp and token validation.
	KeyCredentialsClockSkew = Key{s: "credentials.clock_skew"}

	// KeyTracingEnabled enables OpenTelemetry tracing.
	KeyTracingEnabled = Key{s: "tracing.enabled"}
	// KeyTracingServiceName is the OTEL service name.
	KeyTracingServiceName = Key{s: "tracing.service_name"}
	// KeyTracingServiceVersion is the OTEL service version.
	KeyTracingServiceVersion = Key{s: "tracing.service_version"}
	// KeyTracingEnvironment is the OTEL deployment environment.
	KeyTracingEnvironment = Key{s: "tracing.environment"}
	// KeyTracingExporter is the OTEL exporter type.
	KeyTracingExporter = Key{s: "tracing.exporter"}
	// KeyTracingEndpoint is the OTEL collector endpoint.
	KeyTracingEndpoint = Key{s: "tracing.endpoint"}
	// KeyTracingSampleRate is the trace sampling rate.
	KeyTracingSampleRate = Key{s: "tracing.sample_rate"}

	// KeySecretsDefaultCurrent is the current default secret for generation.
	KeySecretsDefaultCurrent = Key{s: "secrets.default.current"}
	// KeySecretsDefaultRetired lists retired default secrets for verification during rotation.
	KeySecretsDefaultRetired = Key{s: "secrets.default.retired"}

	// KeySecretsPagination is the pagination token signing secret.
	KeySecretsPagination = Key{s: "secrets.pagination.current"}
	// KeySecretsPaginationRetired lists retired pagination secrets for rotation.
	KeySecretsPaginationRetired = Key{s: "secrets.pagination.retired"}

	// KeySecretsHMACCurrent is the current HMAC secret for new key generation.
	KeySecretsHMACCurrent = Key{s: "secrets.hmac.current"}
	// KeySecretsHMACRetired lists retired HMAC secrets for verification during rotation.
	KeySecretsHMACRetired = Key{s: "secrets.hmac.retired"}

	// KeyCacheType is the cache backend type (noop, memory, redis).
	KeyCacheType = Key{s: "cache.type"}
	// KeyCacheTTL is the default cache entry time-to-live.
	KeyCacheTTL = Key{s: "cache.ttl"}
	// KeyCacheMemoryMaxSize is the in-memory cache size limit in bytes.
	KeyCacheMemoryMaxSize = Key{s: "cache.memory.max_size"}
	// KeyCacheMemoryNumCounters is the number of frequency counters for admission.
	KeyCacheMemoryNumCounters = Key{s: "cache.memory.num_counters"}
	// KeyCacheRedisAddrs lists Redis server addresses.
	KeyCacheRedisAddrs = Key{s: "cache.redis.addrs"}
	// KeyCacheRedisPassword is the Redis authentication password.
	KeyCacheRedisPassword = Key{s: "cache.redis.password"}
	// KeyCacheRedisDB is the Redis database number.
	KeyCacheRedisDB = Key{s: "cache.redis.db"}
	// KeyCacheRedisPoolSize limits the Redis pool size.
	KeyCacheRedisPoolSize = Key{s: "cache.redis.pool_size"}
	// KeyCacheRedisTimeout configures Redis operation timeout.
	KeyCacheRedisTimeout = Key{s: "cache.redis.timeout"}
	// KeyCacheRedisMinIdleConns sets the minimum number of idle connections kept open.
	KeyCacheRedisMinIdleConns = Key{s: "cache.redis.min_idle_conns"}
	// KeyCacheRedisConnMaxIdleTime is the maximum duration a connection may be idle before being closed.
	KeyCacheRedisConnMaxIdleTime = Key{s: "cache.redis.conn_max_idle_time"}
	// KeyCacheRedisConnMaxLifetime is the maximum duration a connection may be reused.
	KeyCacheRedisConnMaxLifetime = Key{s: "cache.redis.conn_max_lifetime"}
	// KeyCacheRedisTLSEnabled enables TLS for the Redis connection using the system cert pool.
	KeyCacheRedisTLSEnabled = Key{s: "cache.redis.tls.enabled"}

	// KeyMultitenancyEnabled enables multi-tenancy (commercial only).
	KeyMultitenancyEnabled = Key{s: "multitenancy.enabled"}
	// KeyMultitenancyNetworks lists tenant network configurations.
	KeyMultitenancyNetworks = Key{s: "multitenancy.networks"}

	// KeyServeHTTPClientIPSource specifies how to resolve client IPs for IP restriction checks.
	// Hot-reloadable: read dynamically per request.
	KeyServeHTTPClientIPSource = Key{s: "serve.http.client_ip_source"}

	// KeyServeHTTPTrustForwardedHost controls whether the X-Forwarded-Host header is trusted
	// for tenant routing. Only enable when Talos runs behind a reverse proxy that strips or
	// overwrites this header from untrusted clients. Immutable: requires server restart.
	KeyServeHTTPTrustForwardedHost = Key{s: "serve.http.trust_forwarded_host"}

	// KeyRateLimitEnabled enables rate limit enforcement (commercial only). Hot-reloadable.
	KeyRateLimitEnabled = Key{s: "rate_limit.enabled"}
	// KeyRateLimitBackend is the rate limit counter backend type (memory, redis). Immutable.
	KeyRateLimitBackend = Key{s: "rate_limit.backend"}

	// KeyLastUsedQueueSize is the buffer size for the async last-used update queue.
	// Immutable: requires server restart to change.
	KeyLastUsedQueueSize = Key{s: "last_used.queue_size"}
	// KeyLastUsedFlushSize is the number of updates per shard that triggers a batch flush.
	// Immutable: requires server restart to change.
	KeyLastUsedFlushSize = Key{s: "last_used.flush_size"}
	// KeyLastUsedFlushInterval is the maximum time between batch flushes.
	// Immutable: requires server restart to change.
	KeyLastUsedFlushInterval = Key{s: "last_used.flush_interval"}
	// KeyLastUsedNumWorkers is the number of goroutines processing last-used batches.
	// Immutable: requires server restart to change.
	KeyLastUsedNumWorkers = Key{s: "last_used.num_workers"}
)

// reviewed - @aeneasr - 2026-03-25
