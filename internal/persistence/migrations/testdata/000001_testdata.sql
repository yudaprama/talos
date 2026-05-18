-- Migration v1 test fixtures (SQLite dialect)
-- {{.NID}} is replaced at test time with the actual network ID.
--
-- JSON columns (scopes, metadata, allowed_cidrs) are stored as BLOB by the sqlite.Driver
-- because json.RawMessage = []byte is passed to the driver as a []byte parameter.
-- Raw string literals would be stored as TEXT, causing scan failures when the driver
-- tries to read them back into *json.RawMessage. CAST(... AS BLOB) matches that storage.

-- INSERT OR IGNORE: the SQLite driver's Initialize() already inserts the default network.
INSERT OR IGNORE INTO networks (id, created_at, updated_at)
VALUES ('{{.NID}}', '2024-01-15 10:00:00', '2024-01-15 10:00:00');

-- Active key: all nullable fields populated
INSERT INTO issued_api_keys (
    nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata,
    last_used_at, expires_at, created_at, updated_at,
    rate_limit_quota, rate_limit_window,
    revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
) VALUES (
    '{{.NID}}', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'Active Key', 'phx', 1, 'user-1',
    CAST('["read","write"]' AS BLOB), 1, CAST('{"env":"prod"}' AS BLOB),
    '2024-01-15 11:00:00', NULL, '2024-01-15 10:00:00', '2024-01-15 10:00:00',
    1000, 60,
    0, NULL, CAST('["10.0.0.0/8"]' AS BLOB), 'req-aaaa-1111', 1
);

-- Revoked key: status=2, revocation reason and text set, no rate limits
INSERT INTO issued_api_keys (
    nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata,
    last_used_at, expires_at, created_at, updated_at,
    rate_limit_quota, rate_limit_window,
    revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
) VALUES (
    '{{.NID}}', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    'Revoked Key', 'phx', 1, 'user-1',
    CAST('["read"]' AS BLOB), 2, CAST('{}' AS BLOB),
    NULL, NULL, '2024-01-15 10:00:00', '2024-01-15 12:00:00',
    NULL, NULL,
    3, 'superseded by new key', CAST('[]' AS BLOB), NULL, 1
);

-- Expired key: status=3, no actor_id, past expires_at, public visibility
INSERT INTO issued_api_keys (
    nid, key_id, name, token_prefix, version, actor_id, scopes, status, metadata,
    last_used_at, expires_at, created_at, updated_at,
    rate_limit_quota, rate_limit_window,
    revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
) VALUES (
    '{{.NID}}', 'cccccccc-cccc-cccc-cccc-cccccccccccc',
    'Expired Key', 'dev', 1, NULL,
    CAST('["read"]' AS BLOB), 3, CAST('{}' AS BLOB),
    NULL, '2023-12-31 00:00:00', '2023-12-01 10:00:00', '2023-12-01 10:00:00',
    NULL, NULL,
    0, NULL, CAST('[]' AS BLOB), NULL, 2
);

-- Imported key: hash as key_id, rate limits, request_id
INSERT INTO imported_api_keys (
    nid, key_id, name, actor_id, scopes, status, metadata,
    last_used_at, expires_at, created_at, updated_at,
    rate_limit_quota, rate_limit_window,
    revocation_reason, revocation_reason_text, allowed_cidrs, request_id, visibility
) VALUES (
    '{{.NID}}',
    'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    'Imported Key', 'user-2',
    CAST('["admin"]' AS BLOB), 1, CAST('{"source":"legacy"}' AS BLOB),
    NULL, NULL, '2024-01-15 10:00:00', '2024-01-15 10:00:00',
    500, 30,
    0, NULL, CAST('[]' AS BLOB), 'req-bbbb-2222', 1
);
