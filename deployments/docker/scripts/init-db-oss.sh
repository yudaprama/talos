#!/bin/sh
# Database initialization script for Ory Talos OSS Edition
# Runs migrations on SQLite database

set -e

echo "[init] Starting OSS database initialization..."

# Ensure data directory exists with correct ownership
# The backend container runs as talos (UID 1000), so files must be writable by that user
mkdir -p /var/lib/talos
chown -R 1000:1000 /var/lib/talos

# Run migrations
echo "[init] Running migrations..."
/talos migrate up --database "$DB_DSN"

# Fix ownership after migration (migration runs as root and creates DB files)
chown -R 1000:1000 /var/lib/talos

echo "[init] OSS database initialization complete!"

