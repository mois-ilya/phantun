#!/bin/sh
set -e

# Run benchmarks.
# Inside Docker: run both micro-benchmarks and throughput benchmarks.
# Outside Docker + Docker available: build and run via Docker with --privileged.
# Outside Docker + no Docker: run only micro-benchmarks (throughput needs Linux/Docker).

run_micro() {
    echo "Running micro-benchmarks (packet construction)..."
    cargo bench -p fake-tcp --bench packet_construction
}

run_throughput() {
    echo "Running throughput benchmarks..."
    cargo bench -p fake-tcp --bench throughput --features integration-tests
}

if [ -f /.dockerenv ]; then
    if [ "$(id -u)" = "0" ]; then
        echo "Running benchmarks directly (inside Docker, root)..."
        run_micro
        run_throughput
    else
        echo "Running benchmarks (inside Docker, non-root)..."
        CARGO_BIN="$(which cargo)"
        echo "Running micro-benchmarks (unprivileged)..."
        "$CARGO_BIN" bench -p fake-tcp --bench packet_construction
        echo "Building throughput benchmarks (unprivileged)..."
        "$CARGO_BIN" bench -p fake-tcp --bench throughput --features integration-tests --no-run
        echo "Running throughput benchmarks (via sudo)..."
        sudo "$CARGO_BIN" bench -p fake-tcp --bench throughput --features integration-tests
        sudo chown -R "$(id -u):$(id -g)" /usr/local/cargo/registry /usr/local/cargo/git 2>/dev/null || true
    fi
else
    if command -v docker >/dev/null 2>&1; then
        echo "Running benchmarks via Docker..."
        docker build -f Dockerfile.test -t phantun-test .
        echo "Running all benchmarks in Docker..."
        docker run --privileged --rm \
            -v "$(pwd)/target/criterion:/workspace/target/criterion" \
            phantun-test sh -c \
            'cargo bench -p fake-tcp --bench packet_construction && cargo bench -p fake-tcp --bench throughput --features integration-tests'
    elif [ "$(uname -s)" = "Linux" ]; then
        echo "Docker not available. Running micro-benchmarks only (throughput needs Docker/privileged)."
        run_micro
        echo ""
        echo "Skipping throughput benchmarks (require Docker with --privileged for TUN/netns)."
    else
        echo "Docker not available."
        echo "fake-tcp depends on tokio-tun (Linux-only) and cannot compile on this platform."
        echo "To run benchmarks: install Docker and re-run this script."
        exit 1
    fi
fi

echo ""
echo "=== BENCHMARKS COMPLETE ==="
