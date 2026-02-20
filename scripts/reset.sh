#!/bin/bash
# ShieldView SOC — Full Reset Script
#
# Use this ONLY when starting a fresh cohort or if the DB is corrupted.
# DO NOT reset between individual candidates — the app supports
# multiple simultaneous candidates by design. Each candidate gets
# their own auto-created user row.
#
# What this does:
#   1. Deletes the database (removes ALL candidate user rows)
#   2. Deletes the audit log
#   3. Re-creates the DB with seed data (3 seed users + 30 alerts)

set -e

DATA_DIR="${SHIELDVIEW_DATA_DIR:-./data}"
DB_PATH="$DATA_DIR/shieldview.db"
AUDIT_PATH="$DATA_DIR/audit.log"

echo "=== ShieldView Full Reset ==="
echo "WARNING: This will remove ALL candidate data!"
echo "Data directory: $DATA_DIR"
echo ""

if [ -f "$DB_PATH" ]; then
    echo "Removing database..."
    rm -f "$DB_PATH"
fi

if [ -f "$AUDIT_PATH" ]; then
    echo "Removing audit log..."
    rm -f "$AUDIT_PATH"
fi

echo "Re-seeding database..."
PYTHONPATH="$(cd "$(dirname "$0")/.." && pwd)" python -m app.seed

echo ""
echo "Reset complete. Fresh DB with 3 seed users + 30 alerts."
echo "========================================================="
