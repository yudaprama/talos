-- Metering (fork): per-actor balance cache + append-only usage ledger.
-- PostgreSQL port of the SQLite metering migration.
--
-- Balance is keyed by (nid, actor_id) — one balance shared across an actor's
-- keys. quota = 0 means unlimited (no enforcement). Cost is stored as integer
-- micros (cost x 1_000_000) to avoid floating-point money math.

-- Per-actor balance cache.
CREATE TABLE IF NOT EXISTS actor_balances
(
    nid        VARCHAR(36)  NOT NULL,
    actor_id   VARCHAR(255) NOT NULL,
    quota      BIGINT       NOT NULL DEFAULT 0, -- total credit grant (0 = unlimited)
    remaining  BIGINT       NOT NULL DEFAULT 0, -- current remaining balance (micros)
    updated_at TIMESTAMPTZ  NOT NULL,
    PRIMARY KEY (nid, actor_id),
    FOREIGN KEY (nid) REFERENCES networks (id) ON DELETE CASCADE
);

-- Append-only usage ledger (audit + reconciliation source of truth).
CREATE TABLE IF NOT EXISTS api_key_usage
(
    id           BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nid          VARCHAR(36)  NOT NULL,
    actor_id     VARCHAR(255) NOT NULL,
    key_id       VARCHAR(36),          -- nullable: derived/imported keys may not map 1:1
    usage_type   VARCHAR(32)  NOT NULL, -- e.g. "tokens"
    usage_amount BIGINT       NOT NULL, -- e.g. prompt+completion token count
    cost_micros  BIGINT       NOT NULL DEFAULT 0,
    model        VARCHAR(255) NOT NULL DEFAULT '',
    request_id   VARCHAR(36),          -- idempotency key (AIP-155); unique when set
    created_at   TIMESTAMPTZ  NOT NULL,
    FOREIGN KEY (nid) REFERENCES networks (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_key_usage_actor ON api_key_usage (nid, actor_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_key_usage_request
    ON api_key_usage (nid, request_id) WHERE request_id IS NOT NULL;
