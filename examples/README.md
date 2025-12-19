# Coraza WAF Examples

A minimal example demonstrating how to use the Coraza WAF with Envoy using the coraza-rs dynamic module.

## Quick Start

1. Build the Docker image (from the repository root):
   ```bash
   docker build -t envoy-with-coraza-module:latest .
   ```

2. Run the test script:
   ```bash
   cd examples
   ./test.sh
   ```

The script will start Envoy with the Coraza module and test valid and invalid requests, displaying results in a table format.

## Files

- **`coraza.conf`** - Minimal Coraza WAF configuration with example security rules
- **`envoy.yaml`** - Envoy proxy configuration that loads the Coraza dynamic module
- **`docker-compose.yml`** - Docker Compose setup for Envoy and httpbin backend
- **`test.sh`** - Test script that demonstrates valid and invalid requests

## Configuration

### coraza.conf

Example WAF rules:
- **Rule 1001**: Blocks SQL injection attempts (`UNION SELECT`, `INSERT INTO`)
- **Rule 1002**: Blocks XSS attempts (detects `<script>` tags)
- **Rule 1003**: Blocks requests with suspicious user agents containing "evil"
- **Rule 1004**: Blocks access to `/admin` paths

### envoy.yaml

Envoy configuration that:
- Listens on port 8080
- Loads the Coraza dynamic module as an HTTP filter
- Routes to httpbin backend on port 8081
- Points to `/examples/coraza.conf` for WAF rules

### test.sh

The test script displays requests, expected responses, and actual responses in a simple table. Each test is written inline with explicit curl commands for clarity.
