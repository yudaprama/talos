#!/bin/sh
# Database initialization script for Ory Talos
# Runs migrations and seeds tenant data

set -e

echo "[init] Starting database initialization..."

# Run migrations
echo "[init] Running migrations..."
/talos migrate up --database "$DB_DSN"

echo "[init] Seeding tenant networks..."

# Seed networks (tenants)
# Note: Hostname-to-network mapping is done via config file (multitenancy.networks)
# The networks table just stores network IDs and metadata
psql -c "
INSERT INTO networks (id, created_at, updated_at)
VALUES
  ('00000000-0000-0000-0000-000000000000', NOW(), NOW()),
  ('00000000-0000-0000-0000-000000000001', NOW(), NOW()),
  ('00000000-0000-0000-0000-000000000002', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;
"

echo "[init] Database initialization complete!"
echo "[init] Configured networks (tenants):"
echo "[init]   - Default: 00000000-0000-0000-0000-000000000000"
echo "[init]   - Tenant1: 00000000-0000-0000-0000-000000000001"
echo "[init]   - Tenant2: 00000000-0000-0000-0000-000000000002"
echo "[init]"
echo "[init] Hostname-to-network mapping is configured in /etc/talos/config.yaml"
