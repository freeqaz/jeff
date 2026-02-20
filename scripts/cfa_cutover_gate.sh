#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PARITY_SCRIPT="$REPO_ROOT/scripts/dc3_cfa_parity_smoke.sh"

BUILD_BIN=1
RUN_ID_PREFIX="cutover-$(date +%Y%m%d-%H%M%S)"

usage() {
    cat <<'EOF'
Usage: scripts/cfa_cutover_gate.sh [options]

Options:
  --no-build           Skip `cargo build --bin dtk` prior to checks
  --run-id-prefix <id> Prefix for parity run IDs (default: cutover-<timestamp>)
  -h, --help           Show this help

This script runs a consolidated cutover gate:
  1) cargo test cfa_tests
  2) cfa_tests under pipeline shadow gate
  3) cfa_tests under VM2 native shadow gate
  4) DC3 parity smoke (default)
  5) DC3 parity smoke (strict candidate flags)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)
            BUILD_BIN=0
            shift
            ;;
        --run-id-prefix)
            RUN_ID_PREFIX="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -x "$PARITY_SCRIPT" ]]; then
    echo "Parity script missing or not executable: $PARITY_SCRIPT" >&2
    exit 2
fi

cd "$REPO_ROOT"

if [[ $BUILD_BIN -eq 1 ]]; then
    echo "[cutover-gate] Building debug dtk..."
    cargo build --bin dtk >/tmp/jeff-cutover-build-"$RUN_ID_PREFIX".log 2>&1
fi

echo "[cutover-gate] Running baseline cfa_tests..."
cargo test cfa_tests -- --nocapture

echo "[cutover-gate] Running shadow-gated cfa_tests..."
DTK_CFA_ENABLE_PIPELINE_SHADOW=1 \
DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 \
cargo test cfa_tests -- --nocapture

echo "[cutover-gate] Running native-VM2-gated cfa_tests..."
DTK_CFA_ENABLE_VM2_SHADOW=1 \
DTK_CFA_VM_SHADOW_NATIVE_VM2=1 \
DTK_CFA_MAX_VM_SHADOW_DELTAS=0 \
DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=4 \
DTK_CFA_VM_SHADOW_MAX_STEPS=64 \
cargo test cfa_tests -- --nocapture

echo "[cutover-gate] Running DC3 parity smoke (default)..."
"$PARITY_SCRIPT" --no-build --run-id "${RUN_ID_PREFIX}-default"

echo "[cutover-gate] Running DC3 parity smoke (strict)..."
"$PARITY_SCRIPT" \
    --no-build \
    --strict-code-seeds \
    --strict-symbol-size \
    --run-id "${RUN_ID_PREFIX}-strict"

echo "[cutover-gate] PASS"
