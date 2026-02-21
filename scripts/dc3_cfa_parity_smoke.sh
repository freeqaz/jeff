#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

DC3_ROOT="/home/free/code/milohax/dc3-decomp"
DTK_BIN="$REPO_ROOT/target/debug/dtk"
CFG_REL="config/373307D9/config.yml"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
BUILD_BIN=1
STRICT_CODE_SEEDS=0
STRICT_SYMBOL_SIZE=0

usage() {
    cat <<'EOF'
Usage: scripts/dc3_cfa_parity_smoke.sh [options]

Options:
  --dc3-root <path>   Path to dc3-decomp repo (default: /home/free/code/milohax/dc3-decomp)
  --dtk <path>        Path to dtk binary (default: ./target/debug/dtk from this repo)
  --run-id <id>       Override run-id suffix for /tmp output folders
  --no-build          Skip `cargo build --bin dtk`
  --strict-code-seeds Enable `DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1` for shadow/candidate runs
  --strict-symbol-size
                     Enable `DTK_CFA_CANDIDATE_STRICT_SYMBOL_SIZE_SEEDS=1` for shadow/candidate runs
  -h, --help          Show this help

The script runs:
  1) legacy split
  2) shadow split
  3) candidate split

It exits non-zero if:
  - any split exits non-zero, or
  - baseline vs shadow/candidate has non-trivial diffs
    (only `config.json` and `dep` are ignored).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dc3-root)
            DC3_ROOT="$2"
            shift 2
            ;;
        --dtk)
            DTK_BIN="$2"
            shift 2
            ;;
        --run-id)
            RUN_ID="$2"
            shift 2
            ;;
        --no-build)
            BUILD_BIN=0
            shift
            ;;
        --strict-code-seeds)
            STRICT_CODE_SEEDS=1
            shift
            ;;
        --strict-symbol-size)
            STRICT_SYMBOL_SIZE=1
            shift
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

if [[ ! -d "$DC3_ROOT" ]]; then
    echo "dc3 root not found: $DC3_ROOT" >&2
    exit 2
fi

if [[ $BUILD_BIN -eq 1 ]]; then
    echo "[dc3-parity] Building debug dtk binary..."
    (cd "$REPO_ROOT" && cargo build --bin dtk >/tmp/jeff-dc3-parity-build-"$RUN_ID".log 2>&1)
fi

if [[ ! -x "$DTK_BIN" ]]; then
    echo "dtk binary not found/executable: $DTK_BIN" >&2
    exit 2
fi

BASE_DIR="/tmp/jeff-parity-dc3-baseline-$RUN_ID"
SHADOW_DIR="/tmp/jeff-parity-dc3-shadow-$RUN_ID"
CAND_DIR="/tmp/jeff-parity-dc3-candidate-$RUN_ID"

BASE_LOG="/tmp/jeff-dc3-baseline-$RUN_ID.log"
SHADOW_LOG="/tmp/jeff-dc3-shadow-$RUN_ID.log"
CAND_LOG="/tmp/jeff-dc3-candidate-$RUN_ID.log"

DIFF_BASE_SHADOW="/tmp/jeff-diff-base-shadow-$RUN_ID.txt"
DIFF_BASE_CAND="/tmp/jeff-diff-base-cand-$RUN_ID.txt"

split_cmd() {
    local out_dir="$1"
    shift
    (
        cd "$DC3_ROOT"
        env "$@" "$DTK_BIN" xex split "$CFG_REL" "$out_dir"
    )
}

SHARED_STRICT_ENV=()
if [[ $STRICT_CODE_SEEDS -eq 1 ]]; then
    SHARED_STRICT_ENV+=(DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1)
fi
if [[ $STRICT_SYMBOL_SIZE -eq 1 ]]; then
    SHARED_STRICT_ENV+=(DTK_CFA_CANDIDATE_STRICT_SYMBOL_SIZE_SEEDS=1)
fi

echo "[dc3-parity] Running baseline split..."
BASE_RC=0
split_cmd "$BASE_DIR" DTK_CFA_PIPELINE_MODE=legacy >"$BASE_LOG" 2>&1 || BASE_RC=$?

echo "[dc3-parity] Running shadow split..."
SHADOW_RC=0
split_cmd \
    "$SHADOW_DIR" \
    DTK_CFA_PIPELINE_MODE=shadow \
    DTK_CFA_ENABLE_PIPELINE_SHADOW=1 \
    DTK_CFA_ENABLE_VM2_SHADOW=1 \
    DTK_CFA_VM_SHADOW_NATIVE_VM2=1 \
    DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 \
    DTK_CFA_MAX_VM_SHADOW_DELTAS=0 \
    DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 \
    DTK_CFA_VM_SHADOW_MAX_STEPS=64 \
    "${SHARED_STRICT_ENV[@]}" \
    >"$SHADOW_LOG" 2>&1 || SHADOW_RC=$?

echo "[dc3-parity] Running candidate split..."
CAND_RC=0
split_cmd \
    "$CAND_DIR" \
    DTK_CFA_PIPELINE_MODE=candidate \
    DTK_CFA_ENABLE_PIPELINE_SHADOW=1 \
    DTK_CFA_ENABLE_VM2_SHADOW=1 \
    DTK_CFA_VM_SHADOW_NATIVE_VM2=1 \
    DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 \
    DTK_CFA_MAX_VM_SHADOW_DELTAS=0 \
    DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 \
    DTK_CFA_VM_SHADOW_MAX_STEPS=64 \
    "${SHARED_STRICT_ENV[@]}" \
    >"$CAND_LOG" 2>&1 || CAND_RC=$?

BASE_FILES="$(find "$BASE_DIR" -type f | wc -l | tr -d ' ')"
SHADOW_FILES="$(find "$SHADOW_DIR" -type f | wc -l | tr -d ' ')"
CAND_FILES="$(find "$CAND_DIR" -type f | wc -l | tr -d ' ')"

BASE_OBJS="$(find "$BASE_DIR/obj" -name '*.obj' | wc -l | tr -d ' ')"
SHADOW_OBJS="$(find "$SHADOW_DIR/obj" -name '*.obj' | wc -l | tr -d ' ')"
CAND_OBJS="$(find "$CAND_DIR/obj" -name '*.obj' | wc -l | tr -d ' ')"

diff -qr "$BASE_DIR" "$SHADOW_DIR" >"$DIFF_BASE_SHADOW" || true
diff -qr "$BASE_DIR" "$CAND_DIR" >"$DIFF_BASE_CAND" || true

DIFF_TOTAL_BASE_SHADOW="$(wc -l <"$DIFF_BASE_SHADOW" | tr -d ' ')"
DIFF_TOTAL_BASE_CAND="$(wc -l <"$DIFF_BASE_CAND" | tr -d ' ')"

DIFF_NONTRIV_BASE_SHADOW="$(
    awk '
        !/config\.json/ && $0 !~ /^Files .*\/dep and .*\/dep differ$/ && NF { count++ }
        END { print count + 0 }
    ' "$DIFF_BASE_SHADOW"
)"
DIFF_NONTRIV_BASE_CAND="$(
    awk '
        !/config\.json/ && $0 !~ /^Files .*\/dep and .*\/dep differ$/ && NF { count++ }
        END { print count + 0 }
    ' "$DIFF_BASE_CAND"
)"

echo "[dc3-parity] Summary"
echo "  run_id: $RUN_ID"
echo "  baseline_mode: legacy"
echo "  strict_code_seeds: $STRICT_CODE_SEEDS"
echo "  strict_symbol_size: $STRICT_SYMBOL_SIZE"
echo "  baseline_rc: $BASE_RC"
echo "  shadow_rc: $SHADOW_RC"
echo "  candidate_rc: $CAND_RC"
echo "  files: baseline=$BASE_FILES shadow=$SHADOW_FILES candidate=$CAND_FILES"
echo "  objs: baseline=$BASE_OBJS shadow=$SHADOW_OBJS candidate=$CAND_OBJS"
echo "  diff_total: base_vs_shadow=$DIFF_TOTAL_BASE_SHADOW base_vs_candidate=$DIFF_TOTAL_BASE_CAND"
echo "  diff_nontrivial: base_vs_shadow=$DIFF_NONTRIV_BASE_SHADOW base_vs_candidate=$DIFF_NONTRIV_BASE_CAND"
echo "  outputs:"
echo "    baseline: $BASE_DIR"
echo "    shadow:   $SHADOW_DIR"
echo "    candidate:$CAND_DIR"
echo "  logs:"
echo "    baseline: $BASE_LOG"
echo "    shadow:   $SHADOW_LOG"
echo "    candidate:$CAND_LOG"

if [[ $BASE_RC -ne 0 || $SHADOW_RC -ne 0 || $CAND_RC -ne 0 ]]; then
    echo "[dc3-parity] FAIL: non-zero split exit status detected." >&2
    exit 1
fi

if [[ "$DIFF_NONTRIV_BASE_SHADOW" -ne 0 || "$DIFF_NONTRIV_BASE_CAND" -ne 0 ]]; then
    echo "[dc3-parity] FAIL: non-trivial parity diffs detected." >&2
    exit 1
fi

echo "[dc3-parity] PASS"
