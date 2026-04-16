#!/usr/bin/env bash
# Serve docs/ over HTTP so packet-compare.html can fetch() run files.
#
# file:// won't work because the HTML fetches runs/*.txt, and browsers block
# cross-origin fetches from local files.
#
# Usage:
#   scripts/serve-compare.sh [port]
#
# See docs/plans/20260416-local-compare-harness.md (Task 3).

set -euo pipefail

PORT="${1:-8000}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found on PATH" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCS_DIR="$REPO_ROOT/docs"

if [ ! -d "$DOCS_DIR" ]; then
    echo "error: docs directory not found at $DOCS_DIR" >&2
    exit 1
fi

echo "==> serving docs/ on http://localhost:${PORT}"
echo "==> open http://localhost:${PORT}/packet-compare.html"
cd "$DOCS_DIR"
exec python3 -m http.server "$PORT"
