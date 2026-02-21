#!/usr/bin/env bash
# Orchestration script: run Ghidra headless decompilation for all CFA tests.
#
# Usage: bash scripts/ghidra_decompile_tests.sh
#
# Prerequisites:
#   - Ghidra 12.1 DEV with GhidraXenon extension
#   - pyghidra (pip install pyghidra)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$HOME/code/milohax/vmx128-research/ghidra-test/ghidra_12.1_DEV}"

if [ ! -d "$GHIDRA_INSTALL_DIR/Ghidra" ]; then
    echo "ERROR: Ghidra not found at $GHIDRA_INSTALL_DIR"
    echo "Set GHIDRA_INSTALL_DIR to your Ghidra installation directory."
    exit 1
fi

OUTPUT="${PROJECT_DIR}/docs/cfa_tests_ghidra_decomp.c"

echo "=== Ghidra CFA Test Decompilation ==="
echo "Ghidra: $GHIDRA_INSTALL_DIR"
echo "Output: $OUTPUT"
echo ""

python3 "${SCRIPT_DIR}/ghidra_decompile_cfa.py" "$OUTPUT"

echo ""
TEST_COUNT=$(grep -c "^// Test" "$OUTPUT" 2>/dev/null || echo "0")
echo "Verification: $TEST_COUNT tests in output file"
