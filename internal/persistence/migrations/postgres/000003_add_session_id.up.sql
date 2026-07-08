-- Per-session usage attribution: tag each usage-ledger row with the chat/session
-- id (propagated from the client via x-model-affinity → billing span). Nullable in
-- spirit; stored as NOT NULL DEFAULT '' so scans stay string-typed (mirrors model).
ALTER TABLE api_key_usage ADD COLUMN IF NOT EXISTS session_id VARCHAR(255) NOT NULL DEFAULT '';

-- Support per-session lookups.
CREATE INDEX IF NOT EXISTS idx_api_key_usage_session ON api_key_usage (nid, actor_id, session_id);
