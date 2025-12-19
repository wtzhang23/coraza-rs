# coraza-rs

Rust bindings and Envoy dynamic module for [libcoraza](https://github.com/corazawaf/libcoraza).

## Crates

- **coraza-sys:** Raw bindings to [libcoraza](https://github.com/corazawaf/libcoraza) generated with [bindgen](https://github.com/rust-lang/rust-bindgen)
- **coraza-rs:** An idiomatic, safe API built on top of `coraza-sys`
- **coraza-dynamic-module:** A [dynamic module](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/dynamic_modules) loadable by Envoy

## Building

1. Install dependencies (Rust, Golang, and autotools). See the [Dockerfile](./Dockerfile) for details.
2. Clone the repository with submodules:
   ```bash
   git clone --recursive <repository-url>
   ```
3. Build the release version:
   ```bash
   cargo build --release
   ```
   The dynamic module will be created in the Cargo [build cache](https://doc.rust-lang.org/cargo/reference/build-cache.html#build-cache).

## Examples

See the [examples](./examples) directory for a minimal working example with test script.

## Testing

### End-to-End Tests

1. Build the Docker image:
   ```bash
   docker build -t envoy-with-coraza-module:latest .
   ```
2. Run the end-to-end tests:
   ```bash
   cd e2e && go test ./...
   ```

### FTW Tests

[FTW (Framework for Testing WAFs)](https://github.com/coreruleset/go-ftw) tests validate WAF rule behavior using the OWASP CRS regression test suite.

1. Build the Docker image:
   ```bash
   docker build -t envoy-with-coraza-module:latest .
   ```
2. Run FTW tests:
   ```bash
   cd ftw
   docker compose build --pull
   docker compose run --rm ftw
   ```

The CRS rules are embedded in Coraza via rootfs, so no manual rule setup is required.