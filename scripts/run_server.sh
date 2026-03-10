#!/bin/bash
# Quick setup for running QASP Authority Server on a VPS with Docker.
#
# Usage:
#   chmod +x scripts/run_server.sh
#   ./scripts/run_server.sh
#
# Prerequisites:
#   - Docker (or Podman with docker alias)
#   - Port 8080 available

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "=== Building QASP dev image ==="
docker build --target dev -t qasp:dev .

echo "=== Starting QASP Authority Server on port 8080 ==="
docker run -d --name qasp-server \
  --restart unless-stopped \
  -p 8080:8080 \
  -v "$PROJECT_DIR/scripts:/app/scripts" \
  qasp:dev -c "pip install fastapi uvicorn httpx && python scripts/qasp_server.py --host 0.0.0.0 --port 8080"

echo ""
echo "Server running! Test with:"
echo "  curl http://localhost:8080/"
echo ""
echo "Stop with:"
echo "  docker stop qasp-server && docker rm qasp-server"
