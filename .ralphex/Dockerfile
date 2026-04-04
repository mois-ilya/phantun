# Custom ralphex image with Rust toolchain for phantun project
FROM ghcr.io/umputun/ralphex:latest

# Install Rust system-wide (available to any user)
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH="/usr/local/cargo/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable \
    && chmod -R a+rX /usr/local/rustup /usr/local/cargo

# Verify installation
RUN rustc --version && cargo --version

# Install iproute2 + iptables for integration tests (TUN/network namespaces + DNAT)
RUN apk add --no-cache iproute2 iptables

# Git hooks: always run full test suite on commit
ENV RUN_TESTS=1
RUN git config --global core.hooksPath .githooks
