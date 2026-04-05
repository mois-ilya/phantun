#!/bin/sh
set -e

# Run full test suite.
# Inside Docker as root: cargo test directly.
# Inside Docker as non-root: sudo cargo test (needs sudoers entry + caps).
# Outside Docker: build and run Dockerfile.test.

if [ -f /.dockerenv ]; then
    if [ "$(id -u)" = "0" ]; then
        echo "Running tests directly (inside Docker, root)..."
        cargo test -p fake-tcp --features integration-tests
    else
        echo "Building tests (unprivileged)..."
        cargo test -p fake-tcp --features integration-tests --no-run
        echo "Running tests via sudo (inside Docker, non-root)..."
        sudo /usr/local/cargo/bin/cargo test -p fake-tcp --features integration-tests
        # Fix ownership of cargo cache after root-privileged test run
        sudo chown -R "$(id -u):$(id -g)" /usr/local/cargo/registry /usr/local/cargo/git 2>/dev/null || true
    fi
else
    echo "Running tests via Docker..."
    docker build -f Dockerfile.test -t phantun-test .
    docker run --privileged --rm phantun-test
fi

echo ""
echo "=== ALL TESTS PASSED ==="
