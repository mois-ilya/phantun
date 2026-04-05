# Custom ralphex image with Rust toolchain for phantun project
FROM ghcr.io/umputun/ralphex:latest

# Install Rust system-wide (available to any user)
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH="/usr/local/cargo/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable \
    && chmod -R a+rX /usr/local/rustup /usr/local/cargo \
    && mkdir -p /usr/local/cargo/registry /usr/local/cargo/git \
    && chown -R app:app /usr/local/cargo/registry /usr/local/cargo/git

# Verify installation
RUN rustc --version && cargo --version

# Install iproute2 + iptables for integration tests (TUN/network namespaces + DNAT)
# sudo: integration tests need root for setns() syscall and ip netns commands
# SECURITY NOTE: sudo rules are restricted to exact commands needed by run-tests.sh
# and run-benchmarks.sh rather than blanket cargo access. Scripts build as `app`
# first (--no-run), so build.rs / proc-macro code executes unprivileged. Only the
# test/bench execution runs as root (needed for network namespace operations).
RUN apk add --no-cache iproute2 iptables sudo \
    && printf 'Defaults:app secure_path="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\nDefaults:app env_keep += "RUSTUP_HOME CARGO_HOME"\napp ALL=(root) NOPASSWD: /usr/local/cargo/bin/cargo test -p fake-tcp --features integration-tests\napp ALL=(root) NOPASSWD: /usr/local/cargo/bin/cargo bench -p fake-tcp --bench throughput --features integration-tests\n' > /etc/sudoers.d/cargo-test \
    && mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun

# Git hooks: always run full test suite on commit
ENV RUN_TESTS=1
RUN git config --global core.hooksPath .githooks
