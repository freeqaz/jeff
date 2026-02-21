#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

DTK_BIN="$REPO_ROOT/target/debug/dtk"
BUILD_BIN=1
REQUIRE_ALL=0
MODES=("legacy" "shadow" "candidate")
XEX_PATHS=(
    "/home/free/code/milohax/dc3-decomp/orig/373307D9/default.xex"
    "/home/free/code/milohax/milo-executable-library/dc3/9.16.12 (Final Debug)/ham_xbox_r.xex"
    "/home/free/code/milohax/milo-executable-library/dc1/TU0/default.xex"
    "/home/free/code/milohax/milo-executable-library/gh2/360 TU0 Strum Limit Fix/default.xex"
)

usage() {
    cat <<'EOF'
Usage: scripts/xex_info_mode_matrix.sh [options]

Options:
  --dtk <path>      Path to dtk binary (default: ./target/debug/dtk from this repo)
  --mode <value>    Add a pipeline mode to test (repeatable; default: legacy, shadow, candidate)
  --xex <path>      Add an XEX path to test (repeatable; defaults to local milohax corpus paths)
  --require-all     Fail when any requested XEX path is missing (default: skip missing paths)
  --no-build        Skip `cargo build --bin dtk`
  -h, --help        Show this help

For each existing XEX and mode pair, runs:
  DTK_CFA_PIPELINE_MODE=<mode> dtk xex info <xex>
EOF
}

CUSTOM_MODES=0
CUSTOM_XEXS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dtk)
            DTK_BIN="$2"
            shift 2
            ;;
        --mode)
            if [[ $CUSTOM_MODES -eq 0 ]]; then
                MODES=()
                CUSTOM_MODES=1
            fi
            MODES+=("$2")
            shift 2
            ;;
        --xex)
            if [[ $CUSTOM_XEXS -eq 0 ]]; then
                XEX_PATHS=()
                CUSTOM_XEXS=1
            fi
            XEX_PATHS+=("$2")
            shift 2
            ;;
        --require-all)
            REQUIRE_ALL=1
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

if [[ ${#MODES[@]} -eq 0 ]]; then
    echo "No modes specified." >&2
    exit 2
fi
if [[ ${#XEX_PATHS[@]} -eq 0 ]]; then
    echo "No XEX paths specified." >&2
    exit 2
fi

if [[ $BUILD_BIN -eq 1 ]]; then
    echo "[xex-matrix] Building debug dtk..."
    (cd "$REPO_ROOT" && cargo build --bin dtk >/tmp/jeff-xex-matrix-build.log 2>&1)
fi

if [[ ! -x "$DTK_BIN" ]]; then
    echo "dtk binary not found/executable: $DTK_BIN" >&2
    exit 2
fi

EXISTING_XEXS=()
MISSING_XEXS=()
for xex in "${XEX_PATHS[@]}"; do
    if [[ -f "$xex" ]]; then
        EXISTING_XEXS+=("$xex")
    else
        MISSING_XEXS+=("$xex")
    fi
done

if [[ ${#MISSING_XEXS[@]} -gt 0 ]]; then
    for missing in "${MISSING_XEXS[@]}"; do
        echo "[xex-matrix] Missing XEX: $missing" >&2
    done
    if [[ $REQUIRE_ALL -eq 1 ]]; then
        exit 1
    fi
fi

if [[ ${#EXISTING_XEXS[@]} -eq 0 ]]; then
    echo "[xex-matrix] No existing XEX paths to test." >&2
    exit 1
fi

TOTAL=0
PASS=0
for mode in "${MODES[@]}"; do
    for xex in "${EXISTING_XEXS[@]}"; do
        TOTAL=$((TOTAL + 1))
        echo "[xex-matrix] mode=$mode xex=$xex"
        if DTK_CFA_PIPELINE_MODE="$mode" "$DTK_BIN" xex info "$xex" >/tmp/jeff-xex-info-${mode}-${TOTAL}.log 2>&1; then
            PASS=$((PASS + 1))
        else
            echo "[xex-matrix] FAIL mode=$mode xex=$xex (log: /tmp/jeff-xex-info-${mode}-${TOTAL}.log)" >&2
            exit 1
        fi
    done
done

echo "[xex-matrix] Summary: pass=$PASS total=$TOTAL missing=${#MISSING_XEXS[@]}"
echo "[xex-matrix] PASS"
