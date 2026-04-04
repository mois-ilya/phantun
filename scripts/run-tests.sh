#!/bin/sh
set -e

# Run full test suite.
# Inside Docker: cargo test directly (Linux, namespaces available).
# Outside Docker: build and run Dockerfile.test.

if [ -f /.dockerenv ]; then
    echo "Running tests directly (inside Docker)..."
    cargo test -p fake-tcp --features integration-tests
else
    echo "Running tests via Docker..."
    docker build -f Dockerfile.test -t phantun-test .
    docker run --privileged --rm phantun-test
fi
