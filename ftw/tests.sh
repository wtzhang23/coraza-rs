#!/bin/sh
# This file is adapted from coraza-proxy-wasm/ftw/tests.sh
# Original work: Copyright 2022 The OWASP Coraza contributors
# Adapted for coraza-rs dynamic module implementation

cd /workspace

# Copied from https://github.com/jcchavezs/modsecurity-wasm-filter-e2e/blob/master/tests.sh

step=1
total_steps=1
max_retries=15 #seconds for the server reachability timeout
host=${1:-envoy}
health_url="http://${host}:80"

# Testing if the server is up
echo "[$step/$total_steps] Testing application reachability"
status_code="000"
while [[ "$status_code" -eq "000" ]]; do
  status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null $health_url)
  sleep 1
  echo -ne "[Wait] Waiting for response from $health_url. Timeout: ${max_retries}s   \r"
  let "max_retries--"
  if [[ "$max_retries" -eq 0 ]] ; then
    echo "[Fail] Timeout waiting for response from $health_url, make sure the server is running."
    echo "Envoy Logs:" && cat /home/envoy/logs/envoy.log
    exit 1
  fi
done
if [[ "$status_code" -ne "200" ]]; then
  echo -e "\n[Fail] Unexpected status code $status_code, expected 200. Exiting."
  exit 1
fi
echo -e "\n[Ok] Got status code $status_code, expected 200. Ready to start."


# Allow users to pass FTW flags via FTW_ARGS environment variable
# Example: FTW_ARGS="--output github --show-failures-only --cloud false -i 941100"
FTW_ARGS=${FTW_ARGS:-""}

# Run FTW tests with configured flags
# Note: $FTW_ARGS is intentionally unquoted to allow word splitting
# Use stdbuf to ensure unbuffered output for GitHub Actions annotations
if command -v stdbuf >/dev/null 2>&1; then
  stdbuf -oL -eL /ftw run -d coreruleset/tests/regression/tests --config ftw.yml --read-timeout=30s ${FTW_ARGS}
else
  # If stdbuf is not available, run directly (alpine images may not have it)
  /ftw run -d coreruleset/tests/regression/tests --config ftw.yml --read-timeout=30s ${FTW_ARGS}
fi
