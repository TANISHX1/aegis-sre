#!/bin/bash
set -e

echo "Registering Coral sources with runtime environment variables..."
python setup_sources.py

echo "Starting Reflex application..."
exec reflex run --env prod
