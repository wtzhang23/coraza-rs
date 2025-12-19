#!/bin/bash
# Example test script for coraza-rs Envoy dynamic module
# This script demonstrates how to test WAF rules by sending valid and invalid requests

set -euo pipefail

ENVOY_IMAGE="${ENVOY_IMAGE:-envoy-with-coraza-module:latest}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    docker compose down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo -e "${YELLOW}Starting Envoy...${NC}"

# Check if Docker image exists
if ! docker image inspect "$ENVOY_IMAGE" >/dev/null 2>&1; then
    echo -e "${RED}Error: Docker image '$ENVOY_IMAGE' not found.${NC}"
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
        echo -e "${RED}Error: Envoy failed to start${NC}"
        docker compose logs
        exit 1
    fi
    sleep 1
done

echo -e "${GREEN}Envoy is ready\n${NC}"

# Test results
FAILED=0

echo "Request                          Expected  Actual  Result"
echo "────────────────────────────────────────────────────────────"

# Valid request: Normal path
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/")
if [ "$response" = "200" ]; then
    printf "%-30s %-8s %-6s ${GREEN}✓ PASS${NC}\n" "/" "200" "$response"
else
    printf "%-30s %-8s %-6s ${RED}✗ FAIL${NC}\n" "/" "200" "$response"
    FAILED=1
fi

# Valid request: Normal path (httpbin /get endpoint)
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/get")
if [ "$response" = "200" ]; then
    printf "%-30s %-8s %-6s ${GREEN}✓ PASS${NC}\n" "/get" "200" "$response"
else
    printf "%-30s %-8s %-6s ${RED}✗ FAIL${NC}\n" "/get" "200" "$response"
    FAILED=1
fi

# Invalid request: Admin path (blocked by rule 1004)
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/admin/test")
if [ "$response" = "403" ]; then
    printf "%-30s %-8s %-6s ${GREEN}✓ PASS${NC}\n" "/admin/test" "403" "$response"
else
    printf "%-30s %-8s %-6s ${RED}✗ FAIL${NC}\n" "/admin/test" "403" "$response"
    FAILED=1
fi

# Invalid request: SQL injection (blocked by rule 1001)
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/?id=1%20UNION%20SELECT%20*%20FROM%20users")
if [ "$response" = "403" ]; then
    printf "%-30s %-8s %-6s ${GREEN}✓ PASS${NC}\n" "/?id=1 UNION SELECT..." "403" "$response"
else
    printf "%-30s %-8s %-6s ${RED}✗ FAIL${NC}\n" "/?id=1 UNION SELECT..." "403" "$response"
    FAILED=1
fi

# Invalid request: XSS attempt (blocked by rule 1002)
response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E")
if [ "$response" = "403" ]; then
    printf "%-30s %-8s %-6s ${GREEN}✓ PASS${NC}\n" "/?q=<script>..." "403" "$response"
else
    printf "%-30s %-8s %-6s ${RED}✗ FAIL${NC}\n" "/?q=<script>..." "403" "$response"
    FAILED=1
fi

# Invalid request: Suspicious user agent (blocked by rule 1003)
response=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: evil-bot" "http://localhost:8080/")
if [ "$response" = "403" ]; then
    printf "%-30s %-8s %-6s ${GREEN}✓ PASS${NC}\n" "/ (evil-bot UA)" "403" "$response"
else
    printf "%-30s %-8s %-6s ${RED}✗ FAIL${NC}\n" "/ (evil-bot UA)" "403" "$response"
    FAILED=1
fi

echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✓${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed! ✗${NC}"
    exit 1
fi
