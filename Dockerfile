FROM rust:1.92.0-slim-bookworm AS base

RUN cargo install cargo-chef --version 0.1.73

FROM base AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM base AS builder
RUN apt-get update && apt-get install -y clang autoconf automake libtool m4 make golang-go
COPY --from=planner /recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY coraza-dynamic-module ./coraza-dynamic-module
COPY coraza-rs ./coraza-rs
COPY coraza-sys ./coraza-sys
COPY go.work ./go.work
COPY go.work.sum ./go.work.sum

RUN cargo build --release --package coraza-dynamic-module

FROM debian:bookworm-slim AS runtime-base

FROM runtime-base AS envoy
RUN apt-get update && apt-get install -y wget ca-certificates gpg
RUN wget -O- https://apt.envoyproxy.io/signing.key | gpg --dearmor -o /etc/apt/keyrings/envoy-keyring.gpg
RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/envoy-keyring.gpg] https://apt.envoyproxy.io bookworm main" | tee /etc/apt/sources.list.d/envoy.list
RUN apt-get update && apt-get install -y envoy

FROM runtime-base AS runtime
ENV LD_LIBRARY_PATH=/usr/local/lib
COPY --from=builder /target/release/libcoraza_dynamic_module.so /usr/local/lib/libcoraza_dynamic_module.so
COPY --from=envoy /usr/bin/envoy /usr/bin/envoy
ENTRYPOINT ["/usr/bin/envoy"]

