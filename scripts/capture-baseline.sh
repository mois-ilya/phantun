#!/usr/bin/env bash
# Capture the udp2raw baseline into docs/runs/baseline-udp2raw.txt and
# update docs/runs/manifest.json (the committed manifest) to point at it.
#
# The baseline is meant to be stable — only regenerate when the comparison
# design changes (which invalidates all phantun runs, too).
#
# Usage:
#   scripts/capture-baseline.sh [--force]
#
# See docs/plans/20260416-local-compare-harness.md (Task 3).

set -euo pipefail

FORCE=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --force)
            FORCE=1
            shift
            ;;
        -h|--help)
            sed -n '2,11p' "$0"
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            echo "usage: $0 [--force]" >&2
            exit 2
            ;;
    esac
done

for dep in docker python3; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo "error: required dependency '$dep' not found on PATH" >&2
        exit 1
    fi
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/compare/docker-compose.udp2raw.yml"
CAPTURES_DIR="$REPO_ROOT/docker/compare/captures"
RUNS_DIR="$REPO_ROOT/docs/runs"
BASELINE_FILE="$RUNS_DIR/baseline-udp2raw.txt"
MANIFEST="$RUNS_DIR/manifest.json"

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "error: compose file not found at $COMPOSE_FILE" >&2
    exit 1
fi

mkdir -p "$CAPTURES_DIR" "$RUNS_DIR"

if [ -e "$BASELINE_FILE" ] && [ "$FORCE" -ne 1 ]; then
    if [ ! -t 0 ]; then
        echo "error: $BASELINE_FILE already exists; rerun with --force to overwrite" >&2
        exit 1
    fi
    printf 'baseline already exists at docs/runs/baseline-udp2raw.txt; overwrite? (y/N) '
    read -r answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *)
            echo "aborted."
            exit 0
            ;;
    esac
fi

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "==> starting udp2raw baseline stack"
docker compose -f "$COMPOSE_FILE" up --build \
    --abort-on-container-exit --exit-code-from generator || true

CAPTURE_SRC="$CAPTURES_DIR/udp2raw.txt"
if [ ! -s "$CAPTURE_SRC" ]; then
    echo "error: capture file $CAPTURE_SRC missing or empty" >&2
    exit 1
fi

if ! grep -q 'IPv4' "$CAPTURE_SRC"; then
    echo "error: capture file $CAPTURE_SRC has no parsable 'IPv4' lines" >&2
    exit 1
fi

cp "$CAPTURE_SRC" "$BASELINE_FILE"
echo "==> saved baseline: docs/runs/$(basename "$BASELINE_FILE")"

CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PHANTUN_TCP_PORT="${PHANTUN_TCP_PORT:-4567}"

python3 - "$MANIFEST" "$(basename "$BASELINE_FILE")" "$CREATED" "$PHANTUN_TCP_PORT" <<'PY'
import json
import os
import sys

manifest_path, file_name, created, tcp_port = sys.argv[1:5]

if os.path.exists(manifest_path):
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
else:
    manifest = {}

manifest["baseline"] = {
    "file": file_name,
    "created": created,
    "tool_version": "udp2raw 20230206.0 (commit e5ecd33ec4c25d499a14213a5d1dbd5d21e0dd63)",
    "generator": "python3 UDP constant-rate 1Mbit/s 200B 30s (625 pps)",
    "capture_point": "udp2raw-client eth0 (bridge side)",
    "capture_filter": f"tcp and port {tcp_port}",
}

with open(manifest_path, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")
PY

echo "==> updated docs/runs/manifest.json"

rm -f "$CAPTURES_DIR"/udp2raw.pcap "$CAPTURES_DIR"/udp2raw.txt

echo "==> done"
