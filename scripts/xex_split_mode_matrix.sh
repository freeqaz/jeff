#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PARITY_SCRIPT="$REPO_ROOT/scripts/dc3_cfa_parity_smoke.sh"

DTK_BIN="$REPO_ROOT/target/debug/dtk"
BUILD_BIN=1
REQUIRE_ALL=0
STRICT_MODE=0
RUN_ID_PREFIX="split-matrix-$(date +%Y%m%d-%H%M%S)"
TMP_MIN_FREE_GB=8
MAX_SHADOW_VM_DIFFS=0
MAX_SHADOW_BRIDGED_STEPS=0
CLEANUP_OLD_ARTIFACTS=0
CLEANUP_RUN_ARTIFACTS=0
VM_SHADOW_MAX_FUNCTIONS=8
VM_SHADOW_MAX_STEPS=64

TARGETS=(
    "dc3|/home/free/code/milohax/dc3-decomp|config/373307D9/config.yml"
    "rb3-szbe69|/home/free/code/milohax/rb3|config/SZBE69/config.yml"
    "rb3-szbe69-b8|/home/free/code/milohax/rb3|config/SZBE69_B8/config.yml"
)

usage() {
    cat <<'EOF'
Usage: scripts/xex_split_mode_matrix.sh [options]

Options:
  --dtk <path>            Path to dtk binary (default: ./target/debug/dtk)
  --target <spec>         Add target as label|repo_root|config_rel (repeatable)
  --require-all           Fail when any configured target is missing
  --strict                Enable strict candidate seed flags for all runs
  --run-id-prefix <id>    Prefix for run IDs (default: split-matrix-<timestamp>)
  --tmp-min-free-gb <n>   Forwarded to parity smoke (default: 8)
  --max-shadow-vm-diffs <n>
                          VM telemetry threshold (default: 0)
  --max-shadow-bridged-steps <n>
                          VM telemetry threshold (default: 0)
  --vm-shadow-max-functions <n>
                          VM runtime sampling bound (default: 8)
  --vm-shadow-max-steps <n>
                          VM runtime sampling bound (default: 64)
  --cleanup-old-artifacts Remove prior parity artifacts before first run
  --cleanup-run-artifacts Remove each run's parity artifacts on exit
  --no-build              Skip `cargo build --bin dtk`
  -h, --help              Show this help

Default targets:
  dc3|/home/free/code/milohax/dc3-decomp|config/373307D9/config.yml
  rb3-szbe69|/home/free/code/milohax/rb3|config/SZBE69/config.yml
  rb3-szbe69-b8|/home/free/code/milohax/rb3|config/SZBE69_B8/config.yml
EOF
}

CUSTOM_TARGETS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dtk)
            DTK_BIN="$2"
            shift 2
            ;;
        --target)
            if [[ $CUSTOM_TARGETS -eq 0 ]]; then
                TARGETS=()
                CUSTOM_TARGETS=1
            fi
            TARGETS+=("$2")
            shift 2
            ;;
        --require-all)
            REQUIRE_ALL=1
            shift
            ;;
        --strict)
            STRICT_MODE=1
            shift
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

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "No split targets configured." >&2
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

if [[ $BUILD_BIN -eq 1 ]]; then
    echo "[split-matrix] Building debug dtk..."
    (cd "$REPO_ROOT" && cargo build --bin dtk >/tmp/jeff-split-matrix-build-"$RUN_ID_PREFIX".log 2>&1)
fi

if [[ ! -x "$DTK_BIN" ]]; then
    echo "dtk binary not found/executable: $DTK_BIN" >&2
    exit 2
fi

slugify() {
    echo "$1" | tr -c 'A-Za-z0-9_.-' '-'
}

resolve_config_xex_path() {
    local repo_root="$1"
    local cfg_rel="$2"
    local cfg_path="$repo_root/$cfg_rel"
    local xex_rel
    xex_rel="$(
        awk -F': *' '
            /^[[:space:]]*xex:[[:space:]]*/ {print $2; exit}
            /^[[:space:]]*object:[[:space:]]*/ {print $2; exit}
        ' "$cfg_path" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//'
    )"
    if [[ -z "$xex_rel" ]]; then
        return 1
    fi
    if [[ "$xex_rel" == /* ]]; then
        echo "$xex_rel"
    else
        echo "$repo_root/$xex_rel"
    fi
}

MISSING_TARGETS=()
EXISTING_TARGETS=()
for target in "${TARGETS[@]}"; do
    IFS='|' read -r label repo_root cfg_rel <<<"$target"
    if [[ -z "${label:-}" || -z "${repo_root:-}" || -z "${cfg_rel:-}" ]]; then
        echo "[split-matrix] Invalid target (expected label|repo_root|config_rel): $target" >&2
        exit 2
    fi
    if [[ -d "$repo_root" && -f "$repo_root/$cfg_rel" ]]; then
        if xex_path="$(resolve_config_xex_path "$repo_root" "$cfg_rel")" && [[ -f "$xex_path" ]]; then
            EXISTING_TARGETS+=("$target")
        else
            MISSING_TARGETS+=("$target|missing-xex")
        fi
    else
        MISSING_TARGETS+=("$target|missing-config")
    fi
done

if [[ ${#MISSING_TARGETS[@]} -gt 0 ]]; then
    for missing in "${MISSING_TARGETS[@]}"; do
        echo "[split-matrix] Skipping target: $missing" >&2
    done
    if [[ $REQUIRE_ALL -eq 1 ]]; then
        exit 1
    fi
fi

if [[ ${#EXISTING_TARGETS[@]} -eq 0 ]]; then
    echo "[split-matrix] No existing targets to run." >&2
    exit 1
fi

TOTAL=0
PASS=0
FIRST_RUN=1
for target in "${EXISTING_TARGETS[@]}"; do
    IFS='|' read -r label repo_root cfg_rel <<<"$target"
    TOTAL=$((TOTAL + 1))

    run_id="${RUN_ID_PREFIX}-$(slugify "$label")"
    args=(
        "$PARITY_SCRIPT"
        --no-build
        --dtk "$DTK_BIN"
        --dc3-root "$repo_root"
        --config-rel "$cfg_rel"
        --run-id "$run_id"
        --tmp-min-free-gb "$TMP_MIN_FREE_GB"
        --max-shadow-vm-diffs "$MAX_SHADOW_VM_DIFFS"
        --max-shadow-bridged-steps "$MAX_SHADOW_BRIDGED_STEPS"
        --vm-shadow-max-functions "$VM_SHADOW_MAX_FUNCTIONS"
        --vm-shadow-max-steps "$VM_SHADOW_MAX_STEPS"
    )

    if [[ $STRICT_MODE -eq 1 ]]; then
        args+=(--strict-code-seeds --strict-symbol-size)
    fi

    if [[ $CLEANUP_OLD_ARTIFACTS -eq 1 && $FIRST_RUN -eq 1 ]]; then
        args+=(--cleanup-old-artifacts)
    fi

    if [[ $CLEANUP_RUN_ARTIFACTS -eq 1 ]]; then
        args+=(--cleanup-run-artifacts)
    fi

    echo "[split-matrix] target=$label repo=$repo_root cfg=$cfg_rel run_id=$run_id"
    if "${args[@]}"; then
        PASS=$((PASS + 1))
    else
        echo "[split-matrix] FAIL target=$label run_id=$run_id" >&2
        exit 1
    fi

    FIRST_RUN=0
done

echo "[split-matrix] Summary: pass=$PASS total=$TOTAL missing=${#MISSING_TARGETS[@]} strict=$STRICT_MODE vm_max_functions=$VM_SHADOW_MAX_FUNCTIONS vm_max_steps=$VM_SHADOW_MAX_STEPS"
echo "[split-matrix] PASS"
