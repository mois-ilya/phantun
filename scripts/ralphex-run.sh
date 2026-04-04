#!/bin/sh
# Run ralphex in Docker with phantun-specific settings.
# Usage: ./scripts/ralphex-run.sh docs/plans/20260404-stealth-performance.md
set -e

export RALPHEX_IMAGE=ralphex-phantun
export RALPHEX_DOCKER_PRIVILEGED=1

# Build the custom image if it doesn't exist
if ! docker image inspect "$RALPHEX_IMAGE" >/dev/null 2>&1; then
    echo "Building $RALPHEX_IMAGE image..."
    docker build -f .ralphex/Dockerfile -t "$RALPHEX_IMAGE" .
fi

# caffeinate prevents macOS sleep during long runs
exec caffeinate -i ralphex-dk "$@"
