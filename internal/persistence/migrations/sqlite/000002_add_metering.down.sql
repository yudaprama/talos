-- Reverse of 000002_add_metering.
DROP INDEX IF EXISTS idx_api_key_usage_request;
DROP INDEX IF EXISTS idx_api_key_usage_actor;
DROP TABLE IF EXISTS api_key_usage;
DROP TABLE IF EXISTS actor_balances;
