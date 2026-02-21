#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PARITY_SCRIPT="$REPO_ROOT/scripts/dc3_cfa_parity_smoke.sh"

DTK_BIN="$REPO_ROOT/target/debug/dtk"
DC3_ROOT="/home/free/code/milohax/dc3-decomp"
CFG_REL="config/373307D9/config.yml"
ITERATIONS=3
RUN_ID_PREFIX="candidate-soak-$(date +%Y%m%d-%H%M%S)"
BUILD_BIN=1
TMP_MIN_FREE_GB=8
MAX_SHADOW_VM_DIFFS=0
MAX_SHADOW_BRIDGED_STEPS=0
CLEANUP_OLD_ARTIFACTS=0
CLEANUP_RUN_ARTIFACTS=0
VM_SHADOW_MAX_FUNCTIONS=8
VM_SHADOW_MAX_STEPS=64

usage() {
    cat <<'EOF'
Usage: scripts/cfa_candidate_strict_soak.sh [options]

Options:
  --dtk <path>            Path to dtk binary (default: ./target/debug/dtk)
  --dc3-root <path>       Repo root used for split config lookup
  --config-rel <path>     Config path relative to repo root
  --iterations <n>        Number of strict parity repetitions (default: 3)
  --run-id-prefix <id>    Prefix for run IDs (default: candidate-soak-<timestamp>)
  --tmp-min-free-gb <n>   Forwarded to parity smoke (default: 8)
  --max-shadow-vm-diffs <n>
                          VM telemetry threshold (default: 0)
  --max-shadow-bridged-steps <n>
                          VM telemetry threshold (default: 0)
  --vm-shadow-max-functions <n>
                          VM runtime sampling bound (default: 8)
  --vm-shadow-max-steps <n>
                          VM runtime sampling bound (default: 64)
  --cleanup-old-artifacts Remove prior parity artifacts before first iteration
  --cleanup-run-artifacts Remove each iteration artifacts on exit
  --no-build              Skip `cargo build --bin dtk`
  -h, --help              Show this help

Each iteration runs strict candidate gates:
  scripts/dc3_cfa_parity_smoke.sh --strict-code-seeds --strict-symbol-size
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dtk)
            DTK_BIN="$2"
            shift 2
            ;;
        --dc3-root)
            DC3_ROOT="$2"
            shift 2
            ;;
        --config-rel)
            CFG_REL="$2"
            shift 2
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --run-id-prefix)
            RUN_ID_PREFIX="$2"
            shift 2
            ;;
        --tmp-min-free-gb)
            TMP_MIN_FREE_GB="$2"
            shift 2
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
        --cleanup-old-artifacts)
            CLEANUP_OLD_ARTIFACTS=1
            shift
            ;;
        --cleanup-run-artifacts)
            CLEANUP_RUN_ARTIFACTS=1
            shift
            ;;
        --no-build)
            BUILD_BIN=0
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

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [[ "$ITERATIONS" -lt 1 ]]; then
    echo "--iterations must be a positive integer" >&2
    exit 2
fi

if ! [[ "$TMP_MIN_FREE_GB" =~ ^[0-9]+$ ]]; then
    echo "--tmp-min-free-gb must be a non-negative integer" >&2
    exit 2
fi

if ! [[ "$MAX_SHADOW_VM_DIFFS" =~ ^[0-9]+$ ]]; then
    echo "--max-shadow-vm-diffs must be a non-negative integer" >&2
    exit 2
fi

if ! [[ "$MAX_SHADOW_BRIDGED_STEPS" =~ ^[0-9]+$ ]]; then
    echo "--max-shadow-bridged-steps must be a non-negative integer" >&2
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

if [[ ! -x "$PARITY_SCRIPT" ]]; then
    echo "Parity script missing or not executable: $PARITY_SCRIPT" >&2
    exit 2
fi

if [[ ! -d "$DC3_ROOT" ]]; then
    echo "repo root not found: $DC3_ROOT" >&2
    exit 2
fi

if [[ ! -f "$DC3_ROOT/$CFG_REL" ]]; then
    echo "config not found: $DC3_ROOT/$CFG_REL" >&2
    exit 2
fi

if [[ $BUILD_BIN -eq 1 ]]; then
    echo "[candidate-soak] Building debug dtk..."
    (cd "$REPO_ROOT" && cargo build --bin dtk >/tmp/jeff-candidate-soak-build-"$RUN_ID_PREFIX".log 2>&1)
fi

if [[ ! -x "$DTK_BIN" ]]; then
    echo "dtk binary not found/executable: $DTK_BIN" >&2
    exit 2
fi

PASS=0
for ((i = 1; i <= ITERATIONS; i++)); do
    run_id="${RUN_ID_PREFIX}-${i}"
    args=(
        "$PARITY_SCRIPT"
        --no-build
        --dtk "$DTK_BIN"
        --dc3-root "$DC3_ROOT"
        --config-rel "$CFG_REL"
        --run-id "$run_id"
        --strict-code-seeds
        --strict-symbol-size
        --tmp-min-free-gb "$TMP_MIN_FREE_GB"
        --max-shadow-vm-diffs "$MAX_SHADOW_VM_DIFFS"
        --max-shadow-bridged-steps "$MAX_SHADOW_BRIDGED_STEPS"
        --vm-shadow-max-functions "$VM_SHADOW_MAX_FUNCTIONS"
        --vm-shadow-max-steps "$VM_SHADOW_MAX_STEPS"
    )

    if [[ $CLEANUP_OLD_ARTIFACTS -eq 1 && $i -eq 1 ]]; then
        args+=(--cleanup-old-artifacts)
    fi

    if [[ $CLEANUP_RUN_ARTIFACTS -eq 1 ]]; then
        args+=(--cleanup-run-artifacts)
    fi

    echo "[candidate-soak] iteration=$i/$ITERATIONS run_id=$run_id"
    if "${args[@]}"; then
        PASS=$((PASS + 1))
    else
        echo "[candidate-soak] FAIL iteration=$i run_id=$run_id" >&2
        exit 1
    fi
done

echo "[candidate-soak] Summary: pass=$PASS total=$ITERATIONS vm_max_functions=$VM_SHADOW_MAX_FUNCTIONS vm_max_steps=$VM_SHADOW_MAX_STEPS"
echo "[candidate-soak] PASS"
