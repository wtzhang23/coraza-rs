# coraza-rs
This repository introduces the following crates:
* **coraza-sys:**: Raw bindings to [libcoraza](https://github.com/corazawaf/libcoraza) generated with [bindgen](https://github.com/rust-lang/rust-bindgen)
* **coraza-rs**: An idiomatic, safe API built on top of *coraza-sys*
* **coraza-dynamic-module**: A [dynamic module](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/dynamic_modules) loadable by Envoy 

## Build
1. Install all dependencies including Rust, Golang, and autotools. Refer to the [Dockerfile](./Dockerfile) for more details.
2. Clone the repo. Make sure to pull all submodules as well.
3. Run `cargo build --release`. This will create the dynamic module within the Cargo [build cache](https://doc.rust-lang.org/cargo/reference/build-cache.html#build-cache).

## Test
1. Build the [Dockerfile](./Dockerfile) by running `docker build -t envoy-with-coraza-module:latest .`
2. Run `cd e2e && go test ./...`