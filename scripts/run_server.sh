#!/bin/bash
# Bring up the QASP Authority Server (plus optional MCP bridge sidecar) via docker compose -f docker-compose.yml.
#
# Usage:
#   ./scripts/run_server.sh            # authority only
#   ./scripts/run_server.sh --with-mcp # authority + MCP bridge sidecar
#   ./scripts/run_server.sh --down     # stop everything
#
# Prerequisites:
#   - Docker (with compose v2) or Podman with docker alias
#   - Port 8080 available (and 8888 if --with-mcp)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

SERVICES=(qasp-authority)
ACTION="up"

for arg in "$@"; do
  case "$arg" in
    --with-mcp) SERVICES+=(qasp-mcp-bridge) ;;
    --down)     ACTION="down" ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *) echo "Unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [[ "$ACTION" == "down" ]]; then
  echo "=== Stopping QASP stack ==="
  docker compose -f docker-compose.yml down
  exit 0
fi

echo "=== Building & starting: ${SERVICES[*]} ==="
docker compose -f docker-compose.yml up -d --build "${SERVICES[@]}"

echo ""
echo "Authority:        http://localhost:8080/"
echo "Metrics:          http://localhost:8080/metrics"
if printf '%s\n' "${SERVICES[@]}" | grep -q qasp-mcp-bridge; then
  echo "MCP bridge (SSE): http://localhost:8888/sse"
fi
echo ""
echo "Logs:  docker compose -f docker-compose.yml logs -f ${SERVICES[*]}"
echo "Stop:  ./scripts/run_server.sh --down"
