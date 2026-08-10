#!/usr/bin/env bash
#
# A/B a change to jeff against a real project's split output.
#
# jeff's split output is version-sensitive and the fork is shared by
# cea-decomp, dc3-decomp, rb3-xenon and ChimpsAtSea_Reach, so "did this change
# move any emitted byte?" is a question that needs measuring rather than
# reasoning about. This runs `xex split` with two dtk binaries and reports the
# per-object delta.
#
# Three hazards it exists to avoid:
#
#   1. Never overwrite a shared dtk binary that other work is using. Build the
#      candidate elsewhere (`cargo build --release --target-dir /tmp/jeff-fix`)
#      and pass both paths in.
#   2. Never run a split against a project's own config in place. If the config
#      has a `symbols:` key, dtk REWRITES that file, which dirties the project
#      tree. This copies the config (and its symbols/splits files) into a temp
#      directory and rewrites the relative paths to absolute, so the project is
#      only ever read.
#   3. Never assume the raw `xex split` output is what the project actually
#      scores. `rule split` in a project's build.ninja may set environment
#      variables and may be followed by steps that REWRITE the split objects,
#      and if you skip them your staged objects are not the objects objdiff
#      compares. rb3-xenon does both:
#
#        JEFF_MERGE_PROTECT=scripts/target_symbol_map.json dtk xex split ...
#        python3 scripts/obj_target_symbol_renamer.py --batch --apply
#
#      That renamer rewrites 85,015 fn_<addr> symbols across 1,822 of 3,085
#      objects. Measured 2026-08-10 without it, an A/B of the 1.11.0 sled
#      naming reported "0 of 9,266 functions changed" for rb3 -- every target
#      function was still fn_<addr>, so objdiff never compared the relocation
#      names the change was about. With it, the same A/B reports 61 functions
#      improved and 3 reaching 100%. A silent false NEGATIVE, which is the
#      expensive direction: it reads as "this change is a no-op, ship it".
#
#      So: read the project's `rule split` before trusting a result, pass its
#      env with --env, replay its post-split steps with --post-split, and prove
#      the staging is faithful with --verify-against. --verify-against is the
#      backstop for all of this -- it is how the omission above was caught.
#
# Usage:
#   scripts/xex_split_ab_compare.sh --old <dtk> --new <dtk> \
#       --project <repo_root> --config <config_rel_path> [--keep] \
#       [--env KEY=VALUE]... [--post-split <cmd>] [--verify-against <obj_dir>]
#
# --env             Repeatable. Set for both splits. Relative paths work: the
#                   split runs with cwd = --project, as the real build does.
# --post-split      Shell command run after each split, cwd = --project, with
#                   $SPLIT_OUT set to that side's output directory. Replays the
#                   project's own post-split object rewriting.
# --verify-against  Directory of the project's live target objects (e.g.
#                   build/<version>/obj). Every file there is compared against
#                   the NEW side. A mismatch means the staging does not
#                   reproduce the project, so any delta below is measured
#                   against something the project does not use.
#
# Example (Halo CEA -- no split env, no post-split steps):
#   scripts/xex_split_ab_compare.sh \
#       --old /home/free/code/milohax/jeff/target/release/dtk \
#       --new /tmp/jeff-fix/release/dtk \
#       --project /home/free/code/milohax/cea-decomp \
#       --config config/2011-07-28/config.yml
#
# Example (rb3-xenon -- both, and verified):
#   scripts/xex_split_ab_compare.sh \
#       --old /tmp/jeff-presled/release/dtk \
#       --new /home/free/code/milohax/jeff/target/release/dtk \
#       --project /home/free/code/milohax/rb3-xenon \
#       --config config/45410914/config.yml \
#       --env JEFF_MERGE_PROTECT=scripts/target_symbol_map.json \
#       --post-split 'python3 scripts/obj_target_symbol_renamer.py --batch --apply --obj-dir "$SPLIT_OUT/obj"' \
#       --verify-against build/45410914/obj
#
set -euo pipefail

OLD_DTK=""
NEW_DTK=""
PROJECT=""
CONFIG_REL=""
KEEP=0
POST_SPLIT=""
VERIFY_AGAINST=""
declare -a SPLIT_ENV=()
WORK_ROOT="${TMPDIR:-/tmp}/jeff-split-ab-$$"

usage() {
    sed -n '3,74p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --old) OLD_DTK="$2"; shift 2 ;;
        --new) NEW_DTK="$2"; shift 2 ;;
        --project) PROJECT="$2"; shift 2 ;;
        --config) CONFIG_REL="$2"; shift 2 ;;
        --work-dir) WORK_ROOT="$2"; shift 2 ;;
        --env) SPLIT_ENV+=("$2"); shift 2 ;;
        --post-split) POST_SPLIT="$2"; shift 2 ;;
        --verify-against) VERIFY_AGAINST="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for req in OLD_DTK NEW_DTK PROJECT CONFIG_REL; do
    if [[ -z "${!req}" ]]; then
        echo "Missing --${req,,} (see --help)" >&2
        exit 2
    fi
done
[[ -x "$OLD_DTK" ]] || { echo "not executable: $OLD_DTK" >&2; exit 2; }
[[ -x "$NEW_DTK" ]] || { echo "not executable: $NEW_DTK" >&2; exit 2; }
[[ -f "$PROJECT/$CONFIG_REL" ]] || { echo "no config: $PROJECT/$CONFIG_REL" >&2; exit 2; }

if [[ "$(readlink -f "$OLD_DTK")" == "$(readlink -f "$NEW_DTK")" ]]; then
    echo "--old and --new are the same file; nothing to compare" >&2
    exit 2
fi

echo "[split-ab] old: $OLD_DTK ($("$OLD_DTK" --version 2>/dev/null | head -1))"
echo "[split-ab] new: $NEW_DTK ($("$NEW_DTK" --version 2>/dev/null | head -1))"
echo "[split-ab] project: $PROJECT ($CONFIG_REL)"
echo "[split-ab] work dir: $WORK_ROOT"
if [[ ${#SPLIT_ENV[@]} -gt 0 ]]; then
    echo "[split-ab] split env: ${SPLIT_ENV[*]}"
fi
[[ -n "$POST_SPLIT" ]] && echo "[split-ab] post-split: $POST_SPLIT"
[[ -n "$VERIFY_AGAINST" ]] && echo "[split-ab] verify against: $VERIFY_AGAINST"

CONFIG_DIR_REL="$(dirname "$CONFIG_REL")"

# Stage an isolated copy of the config directory per side, with every relative
# path in the config made absolute. Two copies, not one, so that a rewritten
# symbols file from the first run cannot become an input to the second.
stage() {
    local side="$1"
    local cfg_dir="$WORK_ROOT/$side/config"
    mkdir -p "$cfg_dir"
    cp -r "$PROJECT/$CONFIG_DIR_REL/." "$cfg_dir/"
    python3 - "$PROJECT" "$cfg_dir" "$(basename "$CONFIG_REL")" <<'PY'
import os, re, sys
project, cfg_dir, cfg_name = sys.argv[1], sys.argv[2], sys.argv[3]
path = os.path.join(cfg_dir, cfg_name)
out = []
for line in open(path):
    m = re.match(r'^(\s*)(object|symbols|splits|pdb|map):\s*(\S.*?)\s*$', line)
    if m and not os.path.isabs(m.group(3)):
        indent, key, value = m.groups()
        # inputs stay in the project; anything dtk rewrites moves to the copy
        if key in ('symbols',):
            value = os.path.join(cfg_dir, os.path.basename(value))
        else:
            candidate = os.path.join(cfg_dir, os.path.basename(value))
            value = candidate if os.path.exists(candidate) else os.path.join(project, value)
        line = f'{indent}{key}: {value}\n'
    out.append(line)
open(path, 'w').writelines(out)
PY
    echo "$cfg_dir/$(basename "$CONFIG_REL")"
}

run() {
    local side="$1" dtk="$2" cfg="$3"
    local out="$WORK_ROOT/$side/out"
    mkdir -p "$out"
    echo "[split-ab] splitting ($side)..." >&2
    # cwd = the project, so a relative path in --env resolves the way it does in
    # the project's own `rule split`. Nothing relative is written: the staged
    # config and the output directory are both absolute.
    if ! (cd "$PROJECT" && env ${SPLIT_ENV[@]+"${SPLIT_ENV[@]}"} \
            "$dtk" xex split "$cfg" "$out") >"$WORK_ROOT/$side/split.log" 2>&1; then
        echo "[split-ab] FAIL: $side split failed, see $WORK_ROOT/$side/split.log" >&2
        exit 1
    fi
    if [[ -n "$POST_SPLIT" ]]; then
        echo "[split-ab] post-split ($side)..." >&2
        if ! (cd "$PROJECT" && SPLIT_OUT="$out" eval "$POST_SPLIT") \
                >>"$WORK_ROOT/$side/split.log" 2>&1; then
            echo "[split-ab] FAIL: $side --post-split failed, see $WORK_ROOT/$side/split.log" >&2
            exit 1
        fi
    fi
    echo "$out"
}

# Prove the staged NEW side reproduces the objects the project actually scores.
# Without this the whole comparison can be measured against objects no build
# ever produces, and the failure is silent -- see hazard 3 in the header.
verify_against() {
    local new_out="$1" ref="$2"
    [[ "$ref" = /* ]] || ref="$PROJECT/$ref"
    if [[ ! -d "$ref" ]]; then
        echo "[split-ab] FAIL: --verify-against is not a directory: $ref" >&2
        exit 2
    fi
    python3 - "$new_out" "$ref" <<'PY'
import hashlib, os, sys
new_out, ref = sys.argv[1], sys.argv[2]
def h(p):
    with open(p, 'rb') as f: return hashlib.sha256(f.read()).hexdigest()
same = diff = missing = 0
examples = []
for dirpath, _, files in os.walk(ref):
    for f in files:
        rp = os.path.join(dirpath, f)
        rel = os.path.relpath(rp, ref)
        # the reference is the project's object directory; the split writes it
        # under obj/, so try both shapes rather than guessing.
        for cand in (os.path.join(new_out, rel), os.path.join(new_out, 'obj', rel)):
            if os.path.exists(cand): break
        else:
            missing += 1
            if len(examples) < 5: examples.append(('missing', rel))
            continue
        if h(rp) == h(cand): same += 1
        else:
            diff += 1
            if len(examples) < 5: examples.append(('differs', rel))
print('[split-ab] verify vs %s: identical %d, different %d, missing %d' % (ref, same, diff, missing))
for kind, rel in examples:
    print('[split-ab]     %s: %s' % (kind, rel))
if diff or missing:
    print('[split-ab] STAGING IS NOT FAITHFUL. The delta below is measured against objects')
    print('[split-ab] the project does not use. Check `rule split` in build.ninja for env')
    print('[split-ab] vars (--env) and for post-split object rewriting (--post-split).')
    raise SystemExit(1)
print('[split-ab] staging is faithful: the new side reproduces the project byte-for-byte.')
PY
}

OLD_CFG="$(stage old)"
NEW_CFG="$(stage new)"
OLD_OUT="$(run old "$OLD_DTK" "$OLD_CFG")"
NEW_OUT="$(run new "$NEW_DTK" "$NEW_CFG")"

if [[ -n "$VERIFY_AGAINST" ]]; then
    verify_against "$NEW_OUT" "$VERIFY_AGAINST"
else
    echo "[split-ab] NOTE: no --verify-against, so nothing proves this staging matches the"
    echo "[split-ab] project's real objects. If its \`rule split\` sets env vars or rewrites"
    echo "[split-ab] objects afterwards, a no-op result here may be a false negative."
fi

python3 - "$OLD_OUT" "$NEW_OUT" <<'PY'
import hashlib, os, sys

def snap(root):
    out = {}
    for dirpath, _, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            with open(p, 'rb') as fh:
                out[os.path.relpath(p, root)] = hashlib.sha256(fh.read()).hexdigest()
    return out

old_root, new_root = sys.argv[1], sys.argv[2]
a, b = snap(old_root), snap(new_root)
objs = sorted(k for k in a if k.endswith('.obj'))
changed = [k for k in a if k in b and a[k] != b[k]]
changed_objs = sorted(k for k in changed if k.endswith('.obj'))
# config.json and dep embed the output directory, which differs by construction
noise = {'config.json', 'dep'}
other = sorted(k for k in changed if not k.endswith('.obj') and k not in noise)

if not objs:
    # "0 units, 0 changed" reads as a pass but means the comparison never
    # happened - guard, don't report success.
    print('[split-ab] FAIL: no objects found under %s' % old_root)
    raise SystemExit(1)

print()
print('[split-ab] units (objects):        %d' % len(objs))
print('[split-ab] objects byte-identical: %d' % (len(objs) - len(changed_objs)))
print('[split-ab] objects changed:        %d' % len(changed_objs))
for k in changed_objs[:40]:
    print('    %s' % k)
if len(changed_objs) > 40:
    print('    ... and %d more' % (len(changed_objs) - 40))
print('[split-ab] only in old: %d   only in new: %d' % (len(set(a) - set(b)), len(set(b) - set(a))))
print('[split-ab] other changed files (excluding config.json/dep): %s' % (other or 'none'))
print()
if changed_objs or other or set(a) ^ set(b):
    print('[split-ab] SPLIT OUTPUT MOVED - this is version-bump-worthy.')
else:
    print('[split-ab] split output identical.')
PY

if [[ $KEEP -eq 1 ]]; then
    echo "[split-ab] keeping $WORK_ROOT"
else
    rm -rf "$WORK_ROOT"
fi
