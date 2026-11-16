# Multi-stage build pinned to the workspace toolchain (rust-toolchain.toml
# = 1.97.1 — the builder image must match, or edition/lint drift silently
# changes what compiles). Builder and runtime must also agree on glibc:
# the builder is trixie (2.41), so the runtime is trixie-slim.

FROM rust:1.97.1 AS builder
WORKDIR /build

# Dependency layer first: manifests only, so cargo caches the workspace
# crates across source edits (builds stay fast without a persistent cache).
COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml .cargo/config.toml .cargo/
COPY crates/qcore-transport-api crates/qcore-transport-api
COPY crates/qcore-core crates/qcore-core
COPY crates/qcore crates/qcore
COPY crates/qcore-cli crates/qcore-cli
COPY crates/qcore-ffi crates/qcore-ffi
COPY crates/qcore-transports crates/qcore-transports
COPY examples examples
COPY xtask xtask
COPY tests tests
COPY profiles profiles

# Release build of the CLI (links every builtin transport, tor included —
# see crates/qcore-cli/Cargo.toml). xtask is not built here: the image
# ships the proxy binary, not the release pipeline.
RUN cargo build --release -p qcore-cli

FROM debian:trixie-slim
# CA certificates: WARP/MASQUE/Psiphon registration and Tor bootstrap
# negotiate TLS; a ca-certificates-less container fails those handshakes.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/qcore /usr/local/bin/qcore

# Never root: the proxy binds ports >1024 (default 1080), so no
# CAP_NET_BIND_SERVICE is needed and a non-root user costs nothing.
# `--no-create-home` keeps the image minimal, so the runtime creates a
# writable home for the qcore user (state/identity/session files live in
# $HOME/.qcore by default and the lock must be creatable there).
RUN useradd --system --no-create-home qcore \
    && mkdir -p /home/qcore \
    && chown qcore:qcore /home/qcore
USER qcore

# Default SOCKS5 listener (loopback INSIDE the container — publish the port
# to reach it: docker run -p 1080:1080; see README Docker section).
EXPOSE 1080

# HEALTHCHECK is deliberately omitted: a health probe would need to speak
# the token-authenticated control protocol (a bare TCP connect would lie),
# and wiring that is a release-matrix decision — do not add a stub.

ENTRYPOINT ["qcore"]
