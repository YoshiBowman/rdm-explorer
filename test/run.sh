#!/bin/bash
# test/run.sh — Headless test runner for RDM Explorer
# Usage: bash test/run.sh
# Logs are written to logs/test_<timestamp>.log

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG="logs/test_$TIMESTAMP.log"
mkdir -p logs

echo "=== RDM Explorer Test Run: $TIMESTAMP ===" | tee "$LOG"
echo "" | tee -a "$LOG"

# macOS (BSD) ships without GNU timeout; fall back gracefully.
# Timeout must be long enough for Test 7 (35s gateway poll) + Test 8 (60s scan) + headroom.
if command -v timeout &>/dev/null; then
  TIMEOUT_CMD="timeout 120"
elif command -v gtimeout &>/dev/null; then   # brew install coreutils
  TIMEOUT_CMD="gtimeout 120"
else
  TIMEOUT_CMD=""
fi

$TIMEOUT_CMD node test/test-broker.js 2>&1 | tee -a "$LOG"
# PIPESTATUS[0] captures node's exit code, not tee's
EXIT=${PIPESTATUS[0]}

echo "" | tee -a "$LOG"
echo "=== EXIT: $EXIT | STATUS: $([ $EXIT -eq 0 ] && echo PASS || echo FAIL) ===" | tee -a "$LOG"
exit $EXIT
