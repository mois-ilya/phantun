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
BASELINE_UDP_FILE="$RUNS_DIR/baseline-udp2raw-udp.txt"
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

# Drop any leftovers from a prior run: if the capturer container fails to
# start (image build broken, port collision, Docker daemon hiccup) the old
# files would otherwise survive on the host and be copied as "fresh" data.
rm -f "$CAPTURES_DIR"/udp2raw.pcap "$CAPTURES_DIR"/udp2raw.txt \
      "$CAPTURES_DIR"/udp2raw-udp.pcap "$CAPTURES_DIR"/udp2raw-udp.txt

cleanup() {
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "==> starting udp2raw baseline stack"
# --exit-code-from generator lets compose finish with the generator's exit
# status. We check the capture file separately; if it's missing we surface
# the compose exit code so the user can tell a broken stack from an empty
# capture.
set +e
docker compose -f "$COMPOSE_FILE" up --build \
    --abort-on-container-exit --exit-code-from generator
COMPOSE_RC=$?
set -e

CAPTURE_SRC="$CAPTURES_DIR/udp2raw.txt"
CAPTURE_SRC_UDP="$CAPTURES_DIR/udp2raw-udp.txt"
for src in "$CAPTURE_SRC" "$CAPTURE_SRC_UDP"; do
    if [ ! -s "$src" ]; then
        echo "error: capture file $src missing or empty (docker compose exit code: $COMPOSE_RC)" >&2
        exit 1
    fi
    if ! grep -q 'IPv4' "$src"; then
        echo "error: capture file $src has no parsable 'IPv4' lines" >&2
        exit 1
    fi
done

cp "$CAPTURE_SRC" "$BASELINE_FILE"
cp "$CAPTURE_SRC_UDP" "$BASELINE_UDP_FILE"
echo "==> saved baseline: docs/runs/$(basename "$BASELINE_FILE")"
echo "==> saved baseline: docs/runs/$(basename "$BASELINE_UDP_FILE")"

CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PHANTUN_TCP_PORT="${PHANTUN_TCP_PORT:-4567}"
PHANTUN_LOCAL_UDP="${PHANTUN_LOCAL_UDP:-4500}"

python3 - "$MANIFEST" "$(basename "$BASELINE_FILE")" "$(basename "$BASELINE_UDP_FILE")" "$CREATED" "$PHANTUN_TCP_PORT" "$PHANTUN_LOCAL_UDP" <<'PY'
import json
import os
import sys

manifest_path, file_name, udp_file_name, created, tcp_port, udp_port = sys.argv[1:7]

if os.path.exists(manifest_path):
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
else:
    manifest = {}

manifest["baseline"] = {
    "file": file_name,
    "udp_file": udp_file_name,
    "created": created,
    "tool_version": "udp2raw 20230206.0 (commit e5ecd33ec4c25d499a14213a5d1dbd5d21e0dd63)",
    "generator": "UDP replay of docker/compare/awg-replay.jsonl (AmneziaWG client, 600 pkts / ~1.36s)",
    "capture_point": "udp2raw-client eth0 (bridge side)",
    "capture_filter": f"tcp and port {tcp_port}",
    "capture_filter_udp": f"udp and port {udp_port}",
}

with open(manifest_path, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")
PY

echo "==> updated docs/runs/manifest.json"

rm -f "$CAPTURES_DIR"/udp2raw.pcap "$CAPTURES_DIR"/udp2raw.txt \
      "$CAPTURES_DIR"/udp2raw-udp.pcap "$CAPTURES_DIR"/udp2raw-udp.txt

echo "==> done"
