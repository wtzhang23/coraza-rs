#!/bin/bash
# Example test script for coraza-rs Envoy dynamic module
# This script demonstrates how to test WAF rules by sending valid and invalid requests

set -euo pipefail

ENVOY_IMAGE="${ENVOY_IMAGE:-envoy-with-coraza-module:latest}"

cleanup() {
    echo ""
    echo "Cleaning up..."
    docker compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Starting Envoy..."

# Check if Docker image exists
if ! docker image inspect "$ENVOY_IMAGE" >/dev/null 2>&1; then
    echo "Error: Docker image '$ENVOY_IMAGE' not found."
    echo "Please build the image first: docker build -t $ENVOY_IMAGE ."
    exit 1
fi

# Start services with docker-compose
docker compose up -d

# Wait for Envoy to be ready
for i in {1..30}; do
    if curl -s http://localhost:8080/ >/dev/null 2>&1; then
        break
    fi
    if [ $i -eq 30 ]; then
        echo "Error: Envoy failed to start"
        docker compose logs
        exit 1
    fi
    sleep 1
done

echo "Envoy is ready"
echo ""

# Test results
FAILED=0

# Valid request: Normal path
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/")
if [ "$response" = "200" ]; then
    echo "PASS: / - expected 200, got $response"
else
    echo "FAIL: / - expected 200, got $response"
    FAILED=1
fi

# Valid request: Normal path (httpbin /get endpoint)
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/get")
if [ "$response" = "200" ]; then
    echo "PASS: /get - expected 200, got $response"
else
    echo "FAIL: /get - expected 200, got $response"
    FAILED=1
fi

# Invalid request: Admin path (blocked by rule 1004)
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/admin/test")
if [ "$response" = "403" ]; then
    echo "PASS: /admin/test - expected 403, got $response"
else
    echo "FAIL: /admin/test - expected 403, got $response"
    FAILED=1
fi

# Invalid request: SQL injection (blocked by rule 1001)
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/?id=1%20UNION%20SELECT%20*%20FROM%20users")
if [ "$response" = "403" ]; then
    echo "PASS: /?id=1 UNION SELECT... - expected 403, got $response"
else
    echo "FAIL: /?id=1 UNION SELECT... - expected 403, got $response"
    FAILED=1
fi

# Invalid request: XSS attempt (blocked by rule 1002)
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E")
if [ "$response" = "403" ]; then
    echo "PASS: /?q=<script>... - expected 403, got $response"
else
    echo "FAIL: /?q=<script>... - expected 403, got $response"
    FAILED=1
fi

# Invalid request: Suspicious user agent (blocked by rule 1003)
response=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: evil-bot" "http://localhost:8080/")
if [ "$response" = "403" ]; then
    echo "PASS: / (evil-bot UA) - expected 403, got $response"
else
    echo "FAIL: / (evil-bot UA) - expected 403, got $response"
    FAILED=1
fi

echo ""

if [ $FAILED -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed!"
    exit 1
fi
