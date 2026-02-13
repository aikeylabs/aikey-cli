#!/bin/bash
# Test script to verify environment variables are injected by ak run

echo "=== Environment Variables Test ==="
echo "TEST_VAR: ${TEST_VAR:-NOT_SET}"
echo "ANOTHER_VAR: ${ANOTHER_VAR:-NOT_SET}"
echo "==================================="
