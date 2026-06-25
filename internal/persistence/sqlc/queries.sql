-- API Key Queries

-- name: CreateIssuedAPIKey :one
-- Create a new API key (v1 format - simplified schema)
INSERT INTO issued_api_keys (
    nid, key_id, name,
    token_prefix, version,
    actor_id, scopes, status, metadata, last_used_at, expires_at,
    rate_limit_quota, rate_limit_window,
    allowed_cidrs, request_id, visibility,
    created_at, updated_at
) VALUES (
    sqlc.arg(nid), sqlc.arg(key_id), sqlc.arg(name),
    sqlc.arg(token_prefix), sqlc.arg(version),
    sqlc.arg(actor_id), sqlc.arg(scopes), sqlc.arg(status), sqlc.arg(metadata), sqlc.narg(last_used_at), sqlc.arg(expires_at),
    sqlc.narg(rate_limit_quota), sqlc.narg(rate_limit_window),
    sqlc.arg(allowed_cidrs), sqlc.narg(request_id), sqlc.arg(visibility),
    sqlc.arg(created_at), sqlc.arg(updated_at)
) RETURNING nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility;

-- name: GetIssuedAPIKey :one
-- Lookup API key by key_id and nid
-- Returns keys in any status (active, revoked, expired) - caller must check status
SELECT nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
FROM issued_api_keys
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id)
LIMIT 1;

-- name: GetActiveIssuedAPIKey :one
-- Lookup ACTIVE API key by key_id and nid (for verification hot path)
-- Only returns active keys (revoked/expired keys are filtered out)
SELECT nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
FROM issued_api_keys
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id) AND status = sqlc.arg(active_status)
LIMIT 1;

-- name: UpdateIssuedAPIKey :one
UPDATE issued_api_keys
SET
    name = COALESCE(sqlc.narg(update_name), name),
    scopes = COALESCE(sqlc.narg(update_scopes), scopes),
    metadata = COALESCE(sqlc.narg(update_metadata), metadata),
    rate_limit_quota = sqlc.narg(update_rate_limit_quota),
    rate_limit_window = sqlc.narg(update_rate_limit_window),
    allowed_cidrs = COALESCE(sqlc.narg(update_allowed_cidrs), allowed_cidrs),
    updated_at = sqlc.arg(updated_at)
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id)
RETURNING nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility;

-- name: UpdateIssuedAPIKeyLastUsed :exec
-- Application layer checks if update is needed before calling this
UPDATE issued_api_keys
SET last_used_at = sqlc.arg(last_used_at)
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id);

-- name: RevokeIssuedAPIKey :exec
-- Revoke an API key by setting status to revoked (integer status code)
-- SQLite version uses :exec (like MySQL) to ensure idempotent behavior
UPDATE issued_api_keys
SET status = sqlc.arg(revoked_status),
    updated_at = sqlc.arg(updated_at),
    expires_at = sqlc.arg(expires_at),
    revocation_reason = sqlc.arg(revocation_reason),
    revocation_reason_text = sqlc.arg(revocation_reason_text)
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id);

-- name: DeleteIssuedAPIKey :exec
DELETE FROM issued_api_keys
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id);

-- name: ListIssuedAPIKeysByNetwork :many
-- Cursor-based pagination using key_id (UUIDs provide stable ordering)
-- Pass NULL for cursor_key_id to start from the beginning
-- Optional actor_id filter (pass NULL to list all keys in network)
-- Optional status_filter (pass NULL to return all statuses, requires actor_id)
-- Uses idx_issued_api_keys_actor_pagination when actor_id is provided
SELECT nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
FROM issued_api_keys
WHERE nid = sqlc.arg(nid)
  AND (sqlc.narg(actor_id) IS NULL OR actor_id = sqlc.narg(actor_id))
  AND (sqlc.narg(status_filter) IS NULL OR status = sqlc.narg(status_filter))
  AND (sqlc.narg(cursor_key_id) IS NULL OR key_id < sqlc.narg(cursor_key_id))
ORDER BY key_id DESC
LIMIT sqlc.arg(page_limit);

-- name: GetExpiredIssuedAPIKeys :many
-- Batched selection for scalability (CockroachDB TTL-style)
-- Returns up to LIMIT expired keys for incremental processing within a network
SELECT nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
FROM issued_api_keys
WHERE nid = sqlc.arg(nid) AND status = sqlc.arg(active_status) AND expires_at < datetime('now')
LIMIT sqlc.arg(batch_limit);

-- name: ExpireIssuedAPIKeys :execresult
-- Batched expiration for scalability (CockroachDB TTL-style)
-- Expires up to LIMIT keys at a time within a network
-- Subquery required because SQLite lacks UPDATE ... LIMIT.
UPDATE issued_api_keys
SET status = sqlc.arg(expired_status), updated_at = sqlc.arg(updated_at)
WHERE ROWID IN (
    SELECT inner_keys.ROWID FROM issued_api_keys AS inner_keys
    WHERE inner_keys.nid = sqlc.arg(nid) AND inner_keys.status = sqlc.arg(active_status) AND inner_keys.expires_at < datetime('now')
    LIMIT sqlc.arg(batch_limit)
);

-- name: ListActiveIssuedKeyIDsBounded :many
-- Returns up to sqlc.arg(batch_limit) active issued API key IDs for the network.
-- Used for cap enforcement (quota.api_keys_max). The query is bounded;
-- callers count the returned rows. Never scans an unbounded set.
SELECT key_id FROM issued_api_keys
WHERE nid = sqlc.arg(nid) AND status = sqlc.arg(active_status)
ORDER BY key_id
LIMIT sqlc.arg(batch_limit);

-- name: ListActiveImportedKeyIDsBounded :many
-- Returns up to sqlc.arg(batch_limit) active imported API key IDs for the network.
-- Used for cap enforcement (quota.api_keys_max). The query is bounded;
-- callers count the returned rows. Never scans an unbounded set.
SELECT key_id FROM imported_api_keys
WHERE nid = sqlc.arg(nid) AND status = sqlc.arg(active_status)
ORDER BY key_id
LIMIT sqlc.arg(batch_limit);

-- Imported Key Queries

-- name: CreateImportedAPIKey :one
INSERT INTO imported_api_keys (
    nid, key_id,
    actor_id, name, scopes, metadata, status,
    expires_at, rate_limit_quota, rate_limit_window,
    allowed_cidrs, request_id, visibility,
    created_at, updated_at
) VALUES (
    sqlc.arg(nid), sqlc.arg(key_id),
    sqlc.arg(actor_id), sqlc.arg(name), sqlc.arg(scopes), sqlc.arg(metadata), sqlc.arg(status),
    sqlc.arg(expires_at), sqlc.narg(rate_limit_quota), sqlc.narg(rate_limit_window),
    sqlc.arg(allowed_cidrs), sqlc.narg(request_id), sqlc.arg(visibility),
    sqlc.arg(created_at), sqlc.arg(updated_at)
) RETURNING nid, key_id, name, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility;

-- name: GetImportedAPIKeyByHash :one
-- Lookup imported key by nid and key_id (SHA512/256 hash)
SELECT nid, key_id, name, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
FROM imported_api_keys
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id)
LIMIT 1;

-- name: ListImportedAPIKeys :many
-- Cursor-based pagination using primary key (key_id)
-- Pass NULL for cursor_key_id to start from the beginning
-- Note: Imported keys use hash IDs (not time-sortable), so order is deterministic but not chronological
SELECT nid, key_id, name, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
FROM imported_api_keys
WHERE nid = sqlc.arg(nid)
  AND (sqlc.narg(actor_id) IS NULL OR actor_id = sqlc.narg(actor_id))
  AND (sqlc.narg(status) IS NULL OR status = sqlc.narg(status))
  AND (sqlc.narg(cursor_key_id) IS NULL OR key_id < sqlc.narg(cursor_key_id))
ORDER BY key_id DESC
LIMIT sqlc.arg(page_limit);

-- name: RevokeImportedAPIKey :one
UPDATE imported_api_keys
SET status = sqlc.arg(revoked_status),
    updated_at = sqlc.arg(updated_at),
    expires_at = sqlc.arg(expires_at),
    revocation_reason = sqlc.arg(revocation_reason),
    revocation_reason_text = sqlc.arg(revocation_reason_text)
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id)
RETURNING nid, key_id, name, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility;

-- name: DeleteImportedAPIKey :exec
DELETE FROM imported_api_keys
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id);

-- name: UpdateImportedAPIKeyMetadata :one
UPDATE imported_api_keys
SET
    name = COALESCE(sqlc.narg(update_name), name),
    scopes = COALESCE(sqlc.narg(update_scopes), scopes),
    metadata = COALESCE(sqlc.narg(update_metadata), metadata),
    rate_limit_quota = sqlc.narg(update_rate_limit_quota),
    rate_limit_window = sqlc.narg(update_rate_limit_window),
    allowed_cidrs = COALESCE(sqlc.narg(update_allowed_cidrs), allowed_cidrs),
    updated_at = sqlc.arg(updated_at)
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id)
RETURNING nid, key_id, name, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility;

-- name: UpdateImportedAPIKeyLastUsed :exec
-- Application layer checks if update is needed before calling this
UPDATE imported_api_keys
SET last_used_at = sqlc.arg(last_used_at)
WHERE nid = sqlc.arg(nid) AND key_id = sqlc.arg(key_id);

-- name: GetIssuedAPIKeyByRequestID :one
-- Lookup issued API key by idempotency key (AIP-133)
SELECT nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
FROM issued_api_keys
WHERE nid = sqlc.arg(nid) AND request_id = sqlc.arg(request_id)
LIMIT 1;

-- name: GetImportedAPIKeyByRequestID :one
-- Lookup imported API key by idempotency key (AIP-133)
SELECT nid, key_id, name, actor_id, scopes, status, metadata, last_used_at, expires_at, created_at, updated_at, rate_limit_quota, rate_limit_window, revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
FROM imported_api_keys
WHERE nid = sqlc.arg(nid) AND request_id = sqlc.arg(request_id)
LIMIT 1;

-- reviewed - @aeneasr - 2026-03-26

-- ============================================================================
-- Metering (fork): per-actor balance cache + append-only usage ledger.
-- Backs the VerifyApiKey balance pre-check and AdminIngestUsage.
-- ============================================================================

-- name: GetActorBalance :one
-- Read an actor's cached balance for the verify pre-check. No row = unlimited.
SELECT nid, actor_id, quota, remaining, updated_at
FROM actor_balances
WHERE nid = sqlc.arg(nid) AND actor_id = sqlc.arg(actor_id)
LIMIT 1;

-- name: GetUsageByRequestID :one
-- Idempotency check: has this usage event already been recorded?
SELECT id, nid, actor_id, request_id, created_at
FROM api_key_usage
WHERE nid = sqlc.arg(nid) AND request_id = sqlc.arg(request_id)
LIMIT 1;

-- name: InsertUsage :exec
-- Append one usage event to the ledger. key_id and request_id are nullable.
INSERT INTO api_key_usage (
    nid, actor_id, key_id, usage_type, usage_amount, cost_micros, model, request_id, created_at
) VALUES (
    sqlc.arg(nid), sqlc.arg(actor_id), sqlc.narg(key_id), sqlc.arg(usage_type),
    sqlc.arg(usage_amount), sqlc.arg(cost_micros), sqlc.arg(model), sqlc.narg(request_id), sqlc.arg(created_at)
);

-- name: InsertActorBalanceIfAbsent :exec
-- Initialize an actor's balance row with the full quota. No-op if the row exists.
-- (sqlc's SQLite engine does not expand sqlc.arg() inside ON CONFLICT ... DO
-- UPDATE SET, so initialization and debit are split into two statements.)
INSERT INTO actor_balances (nid, actor_id, quota, remaining, updated_at)
VALUES (sqlc.arg(nid), sqlc.arg(actor_id), sqlc.arg(quota), sqlc.arg(quota), sqlc.arg(updated_at))
ON CONFLICT(nid, actor_id) DO NOTHING;

-- name: DebitActorBalance :one
-- Decrement the actor's remaining balance. The caller initializes the row first
-- (InsertActorBalanceIfAbsent) so the UPDATE always hits. Returns post-debit
-- quota/remaining.
UPDATE actor_balances
SET remaining = remaining - sqlc.arg(amount), updated_at = sqlc.arg(updated_at)
WHERE nid = sqlc.arg(nid) AND actor_id = sqlc.arg(actor_id)
RETURNING quota, remaining;

-- name: SetActorBalance :one
-- Set the actor's quota and remaining to explicit values (admin set-quota). The
-- caller initializes the row first (InsertActorBalanceIfAbsent) so the UPDATE
-- always hits. Returns the new quota/remaining.
UPDATE actor_balances
SET quota = sqlc.arg(quota), remaining = sqlc.arg(remaining), updated_at = sqlc.arg(updated_at)
WHERE nid = sqlc.arg(nid) AND actor_id = sqlc.arg(actor_id)
RETURNING quota, remaining;

-- name: TopUpActorBalance :one
-- Add credits to the actor's remaining balance without changing its quota (admin
-- top-up). The caller initializes the row first only when absent, so an existing
-- balance is not double-counted. Returns the post-top-up quota/remaining.
UPDATE actor_balances
SET remaining = remaining + sqlc.arg(amount), updated_at = sqlc.arg(updated_at)
WHERE nid = sqlc.arg(nid) AND actor_id = sqlc.arg(actor_id)
RETURNING quota, remaining;