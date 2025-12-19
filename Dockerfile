FROM rust:1.92.0-slim-bookworm AS base

RUN cargo install cargo-chef --version 0.1.73

FROM base AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM base AS builder
RUN apt-get update && apt-get install -y clang autoconf automake libtool m4 make golang-go
RUN go install golang.org/dl/go1.25.5@latest && \
    /root/go/bin/go1.25.5 download
ENV GO=/root/go/bin/go1.25.5
COPY --from=planner /recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Hack to allow building without copying over the e2e tests.
RUN mkdir -p e2e && cd e2e && go mod init github.com/wtzhang23/coraza-rs/e2e && go mod tidy
COPY Cargo.toml Cargo.lock ./
COPY coraza-dynamic-module ./coraza-dynamic-module
COPY coraza-rs ./coraza-rs
COPY coraza-sys ./coraza-sys
COPY go.work ./go.work
COPY go.work.sum ./go.work.sum

RUN cargo build --release --package coraza-dynamic-module

FROM envoyproxy/envoy:v1.36.4 AS runtime-base
ENV ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib
COPY --from=builder /target/release/libcoraza_dynamic_module.so /usr/local/lib/libcoraza_dynamic_module.so
ENTRYPOINT ["envoy"]

