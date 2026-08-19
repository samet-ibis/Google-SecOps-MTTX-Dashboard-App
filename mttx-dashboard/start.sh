#!/bin/bash
# MTTX Dashboard — standalone launcher
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/backend"

# Chronicle (Google SecOps) service account — required for queries
[ -f sa.json ] && export GOOGLE_APPLICATION_CREDENTIALS="$SCRIPT_DIR/backend/sa.json"

# Auth: set MTTX_PASSWORD to enable login; leave it empty for open mode (dev)
#   export MTTX_PASSWORD="a-strong-password"
#   export MTTX_SECURE=1   # behind HTTPS: lock the cookie to TLS
export MTTX_PASSWORD MTTX_SECRET MTTX_SECURE MTTX_TTL_HOURS

PORT="${PORT:-8090}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  📊  MTTX Dashboard → http://localhost:$PORT"
[ -z "$MTTX_PASSWORD" ] && echo "  ⚠  MTTX_PASSWORD empty → OPEN MODE (no login). Set it in production."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
exec python3 -m uvicorn main:app --host 0.0.0.0 --port "$PORT" --reload
