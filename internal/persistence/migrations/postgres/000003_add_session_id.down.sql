DROP INDEX IF EXISTS idx_api_key_usage_session;
ALTER TABLE api_key_usage DROP COLUMN IF EXISTS session_id;
