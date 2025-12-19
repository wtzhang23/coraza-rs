# FTW Tests for coraza-rs

[FTW (Framework for Testing WAFs)](https://github.com/coreruleset/go-ftw) tests for the coraza-rs dynamic module using the OWASP CRS regression test suite.

## Attribution

The FTW test infrastructure is adapted from [coraza-proxy-wasm](https://github.com/corazawaf/coraza-proxy-wasm), which is:
- Copyright 2022 The OWASP Coraza contributors
- Licensed under the Apache License, Version 2.0

Adapted to use Envoy dynamic modules instead of WASM filters.

## Running Tests

1. Build the Docker image (from the repository root):
   ```bash
   docker build -t envoy-with-coraza-module:latest .
   ```

2. Run FTW tests:
   ```bash
   cd ftw
   docker compose build --pull
   docker compose run --rm ftw
   ```

## Configuration

- `ftw.yml`: FTW configuration with test overrides and ignores
- `envoy-config.yaml`: Envoy configuration with coraza-rs dynamic module
- `ftw-config.conf`: FTW-specific Coraza configuration rules
- `docker-compose.yml`: Orchestration of services (albedo backend, Envoy, log processing, FTW runner)

The CRS rules are embedded in Coraza via rootfs and referenced using `@owasp_crs/` paths.

## Environment Variables

- `ENVOY_IMAGE`: Envoy image to use (default: `envoy-with-coraza-module:latest`)
- `ENVOY_CONFIG`: Envoy configuration file path (default: `/conf/envoy-config.yaml`)
- `FTW_CLOUDMODE`: Enable cloud mode for FTW tests (default: `false`)
- `FTW_INCLUDE`: Include specific test patterns (e.g., `-i 941100`)

Example:
```bash
FTW_INCLUDE="-i 941100" docker compose run --rm ftw
```
