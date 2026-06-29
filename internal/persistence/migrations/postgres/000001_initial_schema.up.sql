-- Squashed schema for API Key Service (PostgreSQL).
-- Port of the SQLite squashed schema. nid / id stay VARCHAR(36) (UUID stored as
-- text, matching the gofrs/uuid Scanner/Valuer used by the sqlc models and the
-- string-typed metering models); JSON columns use JSONB; timestamps TIMESTAMPTZ.

-- Networks table - Multi-tenant support
CREATE TABLE IF NOT EXISTS networks
(
    id         VARCHAR(36) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- API Keys table (generated keys only - v1 format)
CREATE TABLE IF NOT EXISTS issued_api_keys
(
    nid               VARCHAR(36)  NOT NULL,
    key_id            VARCHAR(36)  NOT NULL, -- UUID v4 (36 chars with hyphens)
    name              VARCHAR(255) NOT NULL,
    token_prefix      VARCHAR(16)  NOT NULL, -- User-defined prefix (e.g., "prod", "dev")
    version           INTEGER      NOT NULL,
    actor_id          VARCHAR(255),
    scopes            JSONB        NOT NULL,
    status            INTEGER      NOT NULL, -- 0=unspecified, 1=active, 2=revoked, 3=expired
    metadata          JSONB        NOT NULL,
    last_used_at      TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL,
    updated_at        TIMESTAMPTZ  NOT NULL,
    rate_limit_quota       BIGINT DEFAULT NULL,   -- Per-key rate limit
    rate_limit_window      BIGINT DEFAULT NULL,   -- Window in seconds
    revocation_reason      INTEGER NOT NULL DEFAULT 0, -- 0=unspecified, 1=key_compromise, 2=affiliation_changed, 3=superseded, 4=privilege_withdrawn
    revocation_reason_text VARCHAR(500),
    allowed_cidrs          JSONB,                      -- Array of CIDR strings for IP restrictions; NULL means no restriction
    request_id             VARCHAR(36),                -- Client-controlled idempotency key (AIP-155, nullable)
    visibility             INTEGER NOT NULL DEFAULT 1, -- 1=secret, 2=public (matches KeyVisibility proto enum)
    PRIMARY KEY (nid, key_id),
    FOREIGN KEY (nid) REFERENCES networks (id) ON DELETE CASCADE
);

-- Imported Keys table (external/legacy keys)
CREATE TABLE IF NOT EXISTS imported_api_keys
(
    nid               VARCHAR(36)  NOT NULL,
    key_id            VARCHAR(64)  NOT NULL, -- SHA512/256 hash of the raw key
    name              VARCHAR(255) NOT NULL,
    actor_id          VARCHAR(255),
    scopes            JSONB        NOT NULL,
    status            INTEGER      NOT NULL, -- 0=unspecified, 1=active, 2=revoked, 3=expired
    metadata          JSONB        NOT NULL,
    last_used_at      TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL,
    updated_at        TIMESTAMPTZ  NOT NULL,
    rate_limit_quota       BIGINT DEFAULT NULL,   -- Per-key rate limit
    rate_limit_window      BIGINT DEFAULT NULL,   -- Window in seconds
    revocation_reason      INTEGER NOT NULL DEFAULT 0, -- 0=unspecified, 1=key_compromise, 2=affiliation_changed, 3=superseded, 4=privilege_withdrawn
    revocation_reason_text VARCHAR(500),
    allowed_cidrs          JSONB,                      -- Array of CIDR strings for IP restrictions; NULL means no restriction
    request_id             VARCHAR(36),                -- Client-controlled idempotency key (AIP-155, nullable)
    visibility             INTEGER NOT NULL DEFAULT 1, -- 1=secret, 2=public (matches KeyVisibility proto enum)
    PRIMARY KEY (nid, key_id),
    FOREIGN KEY (nid) REFERENCES networks (id) ON DELETE CASCADE
);

-- ====== Indexes ======
-- High-entropy columns first for better selectivity

-- API Keys indexes
CREATE INDEX IF NOT EXISTS idx_issued_api_keys_nid ON issued_api_keys (nid);
CREATE INDEX IF NOT EXISTS idx_issued_api_keys_actor_pagination
    ON issued_api_keys (actor_id, nid, status, created_at DESC, key_id DESC);
CREATE INDEX IF NOT EXISTS idx_issued_api_keys_expires
    ON issued_api_keys (expires_at, status, nid) WHERE expires_at IS NOT NULL;

-- Imported Keys indexes
CREATE INDEX IF NOT EXISTS idx_imported_api_keys_hash
    ON imported_api_keys (key_id, nid, status);
CREATE INDEX IF NOT EXISTS idx_imported_api_keys_nid ON imported_api_keys (nid);
CREATE INDEX IF NOT EXISTS idx_imported_api_keys_actor_pagination
    ON imported_api_keys (actor_id, nid, status, created_at DESC, key_id DESC);
CREATE INDEX IF NOT EXISTS idx_imported_api_keys_expires
    ON imported_api_keys (expires_at, status, nid) WHERE expires_at IS NOT NULL;

-- Idempotency key indexes (partial: NULL rows excluded, allowing unlimited non-idempotent creates)
CREATE UNIQUE INDEX IF NOT EXISTS idx_issued_api_keys_request_id
    ON issued_api_keys (nid, request_id) WHERE request_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_imported_api_keys_request_id
    ON imported_api_keys (nid, request_id) WHERE request_id IS NOT NULL;
