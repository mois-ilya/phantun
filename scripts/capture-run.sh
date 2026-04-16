#!/usr/bin/env bash
# Capture one phantun run and record it in docs/runs/manifest.local.json.
#
# Spins up docker/compare/docker-compose.phantun.yml, lets the generator run
# to completion, copies the post-processed tcpdump text into
# docs/runs/phantun-<ts>-<sha>.txt, and appends a metadata entry to the
# gitignored manifest.local.json.
#
# Usage:
#   scripts/capture-run.sh [--notes "free-form text"]
#
# See docs/plans/20260416-local-compare-harness.md (Task 3).

set -euo pipefail

NOTES=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --notes)
            if [ "$#" -lt 2 ]; then
                echo "error: --notes requires a value" >&2
                exit 2
            fi
            NOTES="$2"
            shift 2
            ;;
        --notes=*)
            NOTES="${1#--notes=}"
            shift
            ;;
        -h|--help)
            sed -n '2,12p' "$0"
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            echo "usage: $0 [--notes \"...\"]" >&2
            exit 2
            ;;
    esac
done

for dep in docker python3 git; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo "error: required dependency '$dep' not found on PATH" >&2
        exit 1
    fi
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/compare/docker-compose.phantun.yml"
CAPTURES_DIR="$REPO_ROOT/docker/compare/captures"
RUNS_DIR="$REPO_ROOT/docs/runs"
MANIFEST="$RUNS_DIR/manifest.local.json"

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "error: compose file not found at $COMPOSE_FILE" >&2
    exit 1
fi

mkdir -p "$CAPTURES_DIR" "$RUNS_DIR"

# Drop any leftovers from a prior run: if the capturer container fails to
# start (image build broken, port collision, Docker daemon hiccup) the old
# files would otherwise survive on the host and be copied as "fresh" data.
rm -f "$CAPTURES_DIR"/phantun.pcap "$CAPTURES_DIR"/phantun.txt

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "==> starting phantun compare stack"
# --exit-code-from generator lets compose finish with the generator's exit
# status, which can be non-zero on packet loss. We only care whether the
# capturer produced valid output — but we still surface the compose exit
# code if the capture is missing, so the user can tell a broken stack from
# an empty capture.
set +e
docker compose -f "$COMPOSE_FILE" up --build \
    --abort-on-container-exit --exit-code-from generator
COMPOSE_RC=$?
set -e

CAPTURE_SRC="$CAPTURES_DIR/phantun.txt"
if [ ! -s "$CAPTURE_SRC" ]; then
    echo "error: capture file $CAPTURE_SRC missing or empty (docker compose exit code: $COMPOSE_RC)" >&2
    exit 1
fi

if ! grep -q 'IPv4' "$CAPTURE_SRC"; then
    echo "error: capture file $CAPTURE_SRC has no parsable 'IPv4' lines" >&2
    exit 1
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

BASE="phantun-${TS}-${SHA}"
DEST="$RUNS_DIR/${BASE}.txt"
SUFFIX=2
while [ -e "$DEST" ]; do
    DEST="$RUNS_DIR/${BASE}-${SUFFIX}.txt"
    SUFFIX=$((SUFFIX + 1))
done

cp "$CAPTURE_SRC" "$DEST"
DEST_NAME="$(basename "$DEST")"
echo "==> saved capture: docs/runs/$DEST_NAME"

python3 - "$MANIFEST" "$DEST_NAME" "$CREATED" "$SHA" "$BRANCH" "$NOTES" <<'PY'
import json
import os
import sys

manifest_path, file_name, created, sha, branch, notes = sys.argv[1:7]

if os.path.exists(manifest_path):
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
else:
    manifest = {}

runs = manifest.setdefault("runs", [])
runs.append({
    "file": file_name,
    "created": created,
    "git_sha": sha,
    "git_branch": branch,
    "notes": notes,
})

with open(manifest_path, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")
PY

echo "==> updated docs/runs/manifest.local.json"

rm -f "$CAPTURES_DIR"/phantun.pcap "$CAPTURES_DIR"/phantun.txt

echo "==> done"
