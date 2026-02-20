#!/bin/bash
# ShieldView SOC — First-time Setup Script

set -e

echo "=== ShieldView SOC Setup ==="

# Create data directory
DATA_DIR="${SHIELDVIEW_DATA_DIR:-./data}"
mkdir -p "$DATA_DIR"

# Create .env from example if not exists
if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
    echo "Created .env from .env.example — edit it with your webhook URL."
fi

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Seed database
echo "Initializing database..."
PYTHONPATH="$(pwd)" python -m app.seed

echo ""
echo "Setup complete! Run the app with:"
echo "  python -m app.app"
echo ""
echo "Or with Docker:"
echo "  docker-compose up --build"
echo ""
echo "==================================="
