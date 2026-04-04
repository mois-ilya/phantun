# Custom ralphex image with Rust toolchain for phantun project
FROM ghcr.io/umputun/ralphex:latest

# Install Rust system-wide (available to any user)
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH="/usr/local/cargo/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable \
    && chmod -R a+rwX /usr/local/rustup /usr/local/cargo

# Verify installation
RUN rustc --version && cargo --version

# Install iproute2 + iptables for integration tests (TUN/network namespaces + DNAT)
# sudo: integration tests need root for setns() syscall and ip netns commands
RUN apk add --no-cache iproute2 iptables sudo \
    && echo 'app ALL=(root) NOPASSWD: SETENV: /usr/local/cargo/bin/cargo' > /etc/sudoers.d/cargo-test \
    && mkdir -p /dev/net && mknod /dev/net/tun c 10 200 && chmod 666 /dev/net/tun

# Git hooks: always run full test suite on commit
ENV RUN_TESTS=1
RUN git config --global core.hooksPath .githooks
