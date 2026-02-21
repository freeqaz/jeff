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
MAX_SHADOW_VM_DIFFS=""
MAX_SHADOW_BRIDGED_STEPS=""
TMP_MIN_FREE_GB=8
CLEANUP_OLD_ARTIFACTS=0
CLEANUP_RUN_ARTIFACTS=0
VM_SHADOW_MAX_FUNCTIONS=8
VM_SHADOW_MAX_STEPS=64

usage() {
    cat <<'EOF'
Usage: scripts/dc3_cfa_parity_smoke.sh [options]

Options:
  --dc3-root <path>   Path to dc3-decomp repo (default: /home/free/code/milohax/dc3-decomp)
  --config-rel <path> Config path relative to repo root (default: config/373307D9/config.yml)
  --dtk <path>        Path to dtk binary (default: ./target/debug/dtk from this repo)
  --run-id <id>       Override run-id suffix for /tmp output folders
  --no-build          Skip `cargo build --bin dtk`
  --strict-code-seeds Enable `DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1` for shadow/candidate runs
  --strict-symbol-size
                     Enable `DTK_CFA_CANDIDATE_STRICT_SYMBOL_SIZE_SEEDS=1` for shadow/candidate runs
  --max-shadow-vm-diffs <n>
                     Require shadow run VM telemetry `total_diffs` <= n (reads shadow log)
  --max-shadow-bridged-steps <n>
                     Require shadow run VM telemetry `bridged_steps` <= n (reads shadow log)
  --vm-shadow-max-functions <n>
                     Set `DTK_CFA_VM_SHADOW_MAX_FUNCTIONS` for shadow/candidate runs (default: 8)
  --vm-shadow-max-steps <n>
                     Set `DTK_CFA_VM_SHADOW_MAX_STEPS` for shadow/candidate runs (default: 64)
  --tmp-min-free-gb <n>
                     Require at least <n> GiB available on /tmp before each split (default: 8)
  --cleanup-old-artifacts
                     Remove prior /tmp jeff parity artifacts before running
  --cleanup-run-artifacts
                     Remove this run's /tmp parity artifacts on exit
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
        --config-rel)
            CFG_REL="$2"
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
        --max-shadow-vm-diffs)
            MAX_SHADOW_VM_DIFFS="$2"
            shift 2
            ;;
        --max-shadow-bridged-steps)
            MAX_SHADOW_BRIDGED_STEPS="$2"
            shift 2
            ;;
        --vm-shadow-max-functions)
            VM_SHADOW_MAX_FUNCTIONS="$2"
            shift 2
            ;;
        --vm-shadow-max-steps)
            VM_SHADOW_MAX_STEPS="$2"
            shift 2
            ;;
        --tmp-min-free-gb)
            TMP_MIN_FREE_GB="$2"
            shift 2
            ;;
        --cleanup-old-artifacts)
            CLEANUP_OLD_ARTIFACTS=1
            shift
            ;;
        --cleanup-run-artifacts)
            CLEANUP_RUN_ARTIFACTS=1
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

if [[ ! -f "$DC3_ROOT/$CFG_REL" ]]; then
    echo "config not found: $DC3_ROOT/$CFG_REL" >&2
    exit 2
fi

if ! [[ "$TMP_MIN_FREE_GB" =~ ^[0-9]+$ ]]; then
    echo "--tmp-min-free-gb must be a non-negative integer" >&2
    exit 2
fi

if ! [[ "$VM_SHADOW_MAX_FUNCTIONS" =~ ^[0-9]+$ ]] || [[ "$VM_SHADOW_MAX_FUNCTIONS" -lt 1 ]]; then
    echo "--vm-shadow-max-functions must be a positive integer" >&2
    exit 2
fi

if ! [[ "$VM_SHADOW_MAX_STEPS" =~ ^[0-9]+$ ]] || [[ "$VM_SHADOW_MAX_STEPS" -lt 1 ]]; then
    echo "--vm-shadow-max-steps must be a positive integer" >&2
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

cleanup_old_artifacts() {
    find /tmp -maxdepth 1 -name 'jeff-parity-dc3-*' -exec rm -rf {} + 2>/dev/null || true
    find /tmp -maxdepth 1 -name 'jeff-dc3-*' -exec rm -rf {} + 2>/dev/null || true
    find /tmp -maxdepth 1 -name 'jeff-diff-base-*' -exec rm -rf {} + 2>/dev/null || true
}

cleanup_current_artifacts() {
    rm -rf "$BASE_DIR" "$SHADOW_DIR" "$CAND_DIR" \
        "$BASE_LOG" "$SHADOW_LOG" "$CAND_LOG" \
        "$DIFF_BASE_SHADOW" "$DIFF_BASE_CAND"
}

require_tmp_free_space() {
    local min_gb="$1"
    local avail_kb
    avail_kb="$(df -Pk /tmp | awk 'NR==2 {print $4}')"
    local min_kb=$((min_gb * 1024 * 1024))
    if [[ "$avail_kb" -lt "$min_kb" ]]; then
        local avail_gb
        avail_gb="$(awk "BEGIN {printf \"%.2f\", $avail_kb / 1024 / 1024}")"
        echo "[dc3-parity] FAIL: /tmp free space ${avail_gb}GiB is below required ${min_gb}GiB" >&2
        echo "[dc3-parity] Hint: rerun with --cleanup-old-artifacts and/or --cleanup-run-artifacts" >&2
        exit 1
    fi
}

if [[ $CLEANUP_OLD_ARTIFACTS -eq 1 ]]; then
    echo "[dc3-parity] Cleaning prior parity artifacts from /tmp..."
    cleanup_old_artifacts
fi

if [[ $CLEANUP_RUN_ARTIFACTS -eq 1 ]]; then
    trap cleanup_current_artifacts EXIT
fi

split_cmd() {
    local out_dir="$1"
    shift
    (
        cd "$DC3_ROOT"
        env "$@" "$DTK_BIN" xex split "$CFG_REL" "$out_dir"
    )
}

count_files_under() {
    local path="$1"
    if [[ -d "$path" ]]; then
        find "$path" -type f | wc -l | tr -d ' '
    else
        echo 0
    fi
}

count_obj_files() {
    local path="$1"
    if [[ -d "$path/obj" ]]; then
        find "$path/obj" -name '*.obj' | wc -l | tr -d ' '
    else
        echo 0
    fi
}

SHARED_STRICT_ENV=()
if [[ $STRICT_CODE_SEEDS -eq 1 ]]; then
    SHARED_STRICT_ENV+=(DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1)
fi
if [[ $STRICT_SYMBOL_SIZE -eq 1 ]]; then
    SHARED_STRICT_ENV+=(DTK_CFA_CANDIDATE_STRICT_SYMBOL_SIZE_SEEDS=1)
fi

SHADOW_LOG_ENV=()
if [[ -n "$MAX_SHADOW_VM_DIFFS" || -n "$MAX_SHADOW_BRIDGED_STEPS" ]]; then
    SHADOW_LOG_ENV+=(RUST_LOG="${RUST_LOG:-debug}")
fi

require_tmp_free_space "$TMP_MIN_FREE_GB"
echo "[dc3-parity] Running baseline split..."
BASE_RC=0
split_cmd "$BASE_DIR" DTK_CFA_PIPELINE_MODE=legacy >"$BASE_LOG" 2>&1 || BASE_RC=$?

require_tmp_free_space "$TMP_MIN_FREE_GB"
echo "[dc3-parity] Running shadow split..."
SHADOW_RC=0
split_cmd \
    "$SHADOW_DIR" \
    "${SHADOW_LOG_ENV[@]}" \
    DTK_CFA_PIPELINE_MODE=shadow \
    DTK_CFA_ENABLE_PIPELINE_SHADOW=1 \
    DTK_CFA_ENABLE_VM2_SHADOW=1 \
    DTK_CFA_VM_SHADOW_NATIVE_VM2=1 \
    DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 \
    DTK_CFA_MAX_VM_SHADOW_DELTAS=0 \
    DTK_CFA_VM_SHADOW_MAX_FUNCTIONS="$VM_SHADOW_MAX_FUNCTIONS" \
    DTK_CFA_VM_SHADOW_MAX_STEPS="$VM_SHADOW_MAX_STEPS" \
    "${SHARED_STRICT_ENV[@]}" \
    >"$SHADOW_LOG" 2>&1 || SHADOW_RC=$?

require_tmp_free_space "$TMP_MIN_FREE_GB"
echo "[dc3-parity] Running candidate split..."
CAND_RC=0
split_cmd \
    "$CAND_DIR" \
    "${SHADOW_LOG_ENV[@]}" \
    DTK_CFA_PIPELINE_MODE=candidate \
    DTK_CFA_ENABLE_PIPELINE_SHADOW=1 \
    DTK_CFA_ENABLE_VM2_SHADOW=1 \
    DTK_CFA_VM_SHADOW_NATIVE_VM2=1 \
    DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 \
    DTK_CFA_MAX_VM_SHADOW_DELTAS=0 \
    DTK_CFA_VM_SHADOW_MAX_FUNCTIONS="$VM_SHADOW_MAX_FUNCTIONS" \
    DTK_CFA_VM_SHADOW_MAX_STEPS="$VM_SHADOW_MAX_STEPS" \
    "${SHARED_STRICT_ENV[@]}" \
    >"$CAND_LOG" 2>&1 || CAND_RC=$?

BASE_FILES="$(count_files_under "$BASE_DIR")"
SHADOW_FILES="$(count_files_under "$SHADOW_DIR")"
CAND_FILES="$(count_files_under "$CAND_DIR")"

BASE_OBJS="$(count_obj_files "$BASE_DIR")"
SHADOW_OBJS="$(count_obj_files "$SHADOW_DIR")"
CAND_OBJS="$(count_obj_files "$CAND_DIR")"

if [[ -d "$BASE_DIR" && -d "$SHADOW_DIR" ]]; then
    diff -qr "$BASE_DIR" "$SHADOW_DIR" >"$DIFF_BASE_SHADOW" || true
else
    : >"$DIFF_BASE_SHADOW"
fi
if [[ -d "$BASE_DIR" && -d "$CAND_DIR" ]]; then
    diff -qr "$BASE_DIR" "$CAND_DIR" >"$DIFF_BASE_CAND" || true
else
    : >"$DIFF_BASE_CAND"
fi

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
echo "  vm_shadow_max_functions: $VM_SHADOW_MAX_FUNCTIONS"
echo "  vm_shadow_max_steps: $VM_SHADOW_MAX_STEPS"
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

SHADOW_VM_TOTAL_DIFFS=""
SHADOW_VM_BRIDGED_STEPS=""
if [[ -n "$MAX_SHADOW_VM_DIFFS" || -n "$MAX_SHADOW_BRIDGED_STEPS" ]]; then
    SHADOW_VM_LINE="$(grep -m1 "VM shadow report:" "$SHADOW_LOG" || true)"
    if [[ -z "$SHADOW_VM_LINE" ]]; then
        echo "[dc3-parity] FAIL: requested VM telemetry thresholds but no VM shadow report line was found in $SHADOW_LOG" >&2
        exit 1
    fi
    SHADOW_VM_TOTAL_DIFFS="$(echo "$SHADOW_VM_LINE" | sed -n 's/.*total_diffs=\([0-9][0-9]*\).*/\1/p')"
    SHADOW_VM_BRIDGED_STEPS="$(echo "$SHADOW_VM_LINE" | sed -n 's/.*bridged_steps=\([0-9][0-9]*\).*/\1/p')"
    echo "  shadow_vm: total_diffs=$SHADOW_VM_TOTAL_DIFFS bridged_steps=$SHADOW_VM_BRIDGED_STEPS"
fi

if [[ $BASE_RC -ne 0 || $SHADOW_RC -ne 0 || $CAND_RC -ne 0 ]]; then
    echo "[dc3-parity] FAIL: non-zero split exit status detected." >&2
    exit 1
fi

if [[ "$DIFF_NONTRIV_BASE_SHADOW" -ne 0 || "$DIFF_NONTRIV_BASE_CAND" -ne 0 ]]; then
    echo "[dc3-parity] FAIL: non-trivial parity diffs detected." >&2
    exit 1
fi

if [[ -n "$MAX_SHADOW_VM_DIFFS" ]] && [[ "$SHADOW_VM_TOTAL_DIFFS" -gt "$MAX_SHADOW_VM_DIFFS" ]]; then
    echo "[dc3-parity] FAIL: shadow VM total_diffs=$SHADOW_VM_TOTAL_DIFFS exceeds limit $MAX_SHADOW_VM_DIFFS" >&2
    exit 1
fi

if [[ -n "$MAX_SHADOW_BRIDGED_STEPS" ]] && [[ "$SHADOW_VM_BRIDGED_STEPS" -gt "$MAX_SHADOW_BRIDGED_STEPS" ]]; then
    echo "[dc3-parity] FAIL: shadow VM bridged_steps=$SHADOW_VM_BRIDGED_STEPS exceeds limit $MAX_SHADOW_BRIDGED_STEPS" >&2
    exit 1
fi

echo "[dc3-parity] PASS"
