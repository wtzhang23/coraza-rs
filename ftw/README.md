# FTW Tests for coraza-rs

This directory contains [FTW (Framework for Testing WAFs)](https://github.com/coreruleset/ftw) tests for the coraza-rs dynamic module.

## Attribution

The FTW test infrastructure in this directory is adapted from [coraza-proxy-wasm](https://github.com/corazawaf/coraza-proxy-wasm), which is:
- Copyright 2022 The OWASP Coraza contributors
- Licensed under the Apache License, Version 2.0

The adaptations include modifications to use Envoy dynamic modules instead of WASM filters, and adjustments to log filtering and configuration for the coraza-rs implementation.

## Prerequisites

- Docker and Docker Compose
- Built `envoy-with-coraza-module` Docker image (see main README)

## Setup

### Build the Envoy Docker Image

Build the Docker image with the coraza-rs dynamic module:

```bash
# From the coraza-rs root directory
docker build -t envoy-with-coraza-module:latest .
```

This image includes the dynamic module at `/usr/local/lib/libcoraza_dynamic_module.so`.

## Running Tests

### Using Docker Compose

1. Build the FTW test runner image:
   ```bash
   cd ftw
   docker compose build --pull
   ```

2. Start all services and run tests:
   ```bash
   docker compose up --abort-on-container-exit
   ```

   Or run just the FTW tests (assuming other services are already running):
   ```bash
   docker compose run --rm ftw
   ```

3. To run tests in the background and check logs:
   ```bash
   docker compose up -d
   docker compose logs -f ftw
   ```

### Environment Variables

- `ENVOY_IMAGE`: Envoy image to use (default: `envoyproxy/envoy:v1.36.4`)
- `ENVOY_CONFIG`: Envoy config file (default: `/conf/envoy-config.yaml`)
- `FTW_CLOUDMODE`: Enable FTW cloud mode (default: `false`)
- `FTW_INCLUDE`: Include specific test patterns (e.g., `-i 941100`)

Example:

```bash
FTW_INCLUDE="-i 941100" docker compose run --rm ftw
```

## Test Structure

The FTW tests use the official OWASP CRS regression test suite, which is automatically downloaded in the FTW Docker image. The CRS rules themselves are embedded in Coraza via rootfs and referenced using `@owasp_crs/` paths. The tests are configured via:

- `ftw.yml`: FTW configuration with test overrides and ignores
- `envoy-config.yaml`: Envoy configuration with coraza-rs dynamic module
- `ftw-config.conf`: FTW-specific Coraza configuration rules
- `docker-compose.yml`: Orchestration of services (albedo backend, Envoy, log processing, FTW runner)

## CI/CD Integration

FTW tests can be integrated into CI/CD pipelines. See `.github/workflows/test-build.yml` for an example.

## Differences from coraza-proxy-wasm

- Uses dynamic modules instead of WASM
- Log filtering looks for coraza log patterns instead of `[critical][wasm]`
- Build directory contains `.so` file instead of `.wasm`
- Uses Envoy v1.36.4 (compatible with dynamic modules)

## Advanced

### Using a Different Envoy Image

You can override the Envoy image using the `ENVOY_IMAGE` environment variable:

```bash
ENVOY_IMAGE=your-custom-envoy-image:tag docker compose up
```

## Troubleshooting

### Tests fail with "Timeout waiting for response"

Ensure Envoy is starting correctly. Check logs:

```bash
docker compose logs envoy
```

### WAF initialization errors

If Envoy fails to start with "Failed to initialize dynamic module", check:

1. Verify the Docker image was built correctly:
   ```bash
   docker build -t envoy-with-coraza-module:latest .
   ```

2. Check Envoy logs for specific error messages:
   ```bash
   docker compose logs envoy | grep -i "error\|failed"
   ```

3. Verify the configuration files are correct:
   - `envoy-config.yaml` should reference `@coraza.conf-recommended`, `@crs-setup.conf.example`, and `@owasp_crs/*.conf`
   - `ftw-config.conf` should exist and contain valid Coraza rules

### Log file not found

The log processing container may fail if Envoy hasn't started. Check:

```bash
docker compose logs coraza-logs
```
