-- Rollback squashed schema
-- Drop tables in reverse dependency order

DROP INDEX IF EXISTS idx_imported_api_keys_request_id;
DROP INDEX IF EXISTS idx_issued_api_keys_request_id;
DROP INDEX IF EXISTS idx_imported_api_keys_expires;
DROP INDEX IF EXISTS idx_imported_api_keys_actor_pagination;
DROP INDEX IF EXISTS idx_imported_api_keys_nid;
DROP INDEX IF EXISTS idx_imported_api_keys_hash;
DROP INDEX IF EXISTS idx_issued_api_keys_expires;
DROP INDEX IF EXISTS idx_issued_api_keys_actor_pagination;
DROP INDEX IF EXISTS idx_issued_api_keys_nid;

DROP TABLE IF EXISTS imported_api_keys;
DROP TABLE IF EXISTS issued_api_keys;
DROP TABLE IF EXISTS networks;
