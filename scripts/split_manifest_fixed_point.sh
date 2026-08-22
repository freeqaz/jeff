#!/usr/bin/env bash
# Is `dtk xex split` still a fixed point of its own input, now that it also
# declares what it writes?
#
# THE RULE (dc3-decomp/docs/tools/BUILD_SYSTEM.md): re-running the split on an
# unchanged tree must leave the tree unchanged. If the manifest churns -- new
# bytes, or merely a new mtime -- then any ninja edge declaring it self-refires
# on every build, and the cure is worse than the disease.
#
# THE TRAP THIS AVOIDS: "the second run did not crash" is not the assertion.
# Neither is "the manifest exists". Both are equally true of a manifest that is
# rewritten from scratch every run with a timestamp in it. So this script
# asserts on CONTENT and on MTIME, and it carries its negative control INSIDE
# the run: after proving stability it deliberately edits `symbols.txt`, and the
# manifest MUST move. A stability check that cannot be made to fail is not a
# check.
#
# Usage:
#   scripts/split_manifest_fixed_point.sh <dtk> <repo-root> <config.yml> [out-dir]
#
# e.g.
#   scripts/split_manifest_fixed_point.sh \
#       ./target/release/dtk \
#       /home/free/code/milohax/dc3-decomp \
#       config/373307D9/config.yml
#
# Everything is written to a scratch out-dir; the repo's own build/ is never
# touched. The one thing it does mutate is `symbols.txt`, for the negative
# control, and it restores it from a byte copy in a trap -- including on
# Ctrl-C, because leaving a decomp repo with a sabotaged symbols.txt is a much
# worse outcome than a failed test.
set -uo pipefail

DTK=${1:?usage: $0 <dtk> <repo-root> <config.yml> [out-dir]}
REPO=${2:?usage: $0 <dtk> <repo-root> <config.yml> [out-dir]}
CONFIG=${3:?usage: $0 <dtk> <repo-root> <config.yml> [out-dir]}
OUT=${4:-}

DTK=$(readlink -f "$DTK")
REPO=$(readlink -f "$REPO")
if [ -z "$OUT" ]; then
  OUT=$(mktemp -d -t dtk-fixed-point-XXXXXX)
  OWN_OUT=1
else
  OWN_OUT=0
fi

cd "$REPO" || exit 2

# symbols.txt is what the negative control edits. Find it in the config.
SYMBOLS=$(python3 - "$CONFIG" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
# ProjectConfig flattens `base` at the top level; tolerate both spellings.
print(doc.get("symbols") or (doc.get("base") or {}).get("symbols") or "")
PY
)
if [ -z "$SYMBOLS" ] || [ ! -f "$SYMBOLS" ]; then
  echo "FATAL: could not locate symbols.txt from $CONFIG (got '$SYMBOLS')" >&2
  exit 2
fi

BACKUP=$(mktemp -t symbols-backup-XXXXXX)
cp -p "$SYMBOLS" "$BACKUP"
restore() {
  cp -p "$BACKUP" "$SYMBOLS"
  rm -f "$BACKUP"
  [ "$OWN_OUT" = 1 ] && rm -rf "$OUT"
  return 0
}
trap restore EXIT INT TERM

MANIFEST="$OUT/split_manifest.json"
fail=0
say() { printf '%s\n' "$*"; }
check() { # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then say "  GREEN  $1"; else say "  RED    $1"; say "           expected: $2"; say "           actual:   $3"; fail=1; fi
}
check_ne() {
  if [ "$2" != "$3" ]; then say "  GREEN  $1"; else say "  RED    $1 (values are equal: $2)"; fail=1; fi
}

say "== run 1 (cold) =="
"$DTK" xex split "$CONFIG" "$OUT" >/dev/null 2>&1 || { echo "FATAL: split 1 failed" >&2; exit 2; }
[ -f "$MANIFEST" ] || { echo "FATAL: no manifest at $MANIFEST" >&2; exit 2; }
h1=$(sha1sum "$MANIFEST" | cut -d' ' -f1)
m1=$(stat -c %Y "$MANIFEST")
n_out=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["outputs"]))' "$MANIFEST")
n_in=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["inputs"]))' "$MANIFEST")
say "  manifest declares $n_out outputs, $n_in inputs"

# The denominator matters: a manifest that declares 3 of 2,223 objects is a
# green check over nothing. Assert it covers every object config.json names.
n_units=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(len(d.get("units") or d["base"]["units"]))' "$OUT/config.json")
covered=$(python3 - "$MANIFEST" "$OUT/config.json" <<'PY'
import json, os, sys
man = json.load(open(sys.argv[1]))["outputs"]
cfg = json.load(open(sys.argv[2]))
units = cfg.get("units") or cfg["base"]["units"]
missing = [u["object"] for u in units if os.path.normpath(u["object"]) not in man]
print(f"{len(units) - len(missing)}/{len(units)}")
PY
)
say "  config.json objects covered by the manifest: $covered"
check "every object config.json names is declared" \
      "$n_units/$n_units" \
      "$covered"

# And that the recorded hashes are true of the files on disk, not of some
# intention. This is the assertion a "manifest exists" test would miss.
onq=$(python3 - "$MANIFEST" <<'PY'
import hashlib, json, sys
man = json.load(open(sys.argv[1]))
bad = 0
for path, rec in man["outputs"].items():
    try:
        data = open(path, "rb").read()
    except OSError:
        bad += 1; continue
    if len(data) != rec["size"] or hashlib.sha1(data).hexdigest() != rec["sha1"]:
        bad += 1
print(bad)
PY
)
check "every declared output's sha1 is true of the file on disk (0 wrong)" "0" "$onq"

say "== run 2 (unchanged input) =="
# The OTHER half of the fixed-point rule, and the older one: the split writes
# symbols.txt and splits.txt back, so it must not perturb them on an unchanged
# run or the depfile edge that names them self-refires forever.
SPLITS=$(python3 - "$CONFIG" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
print(doc.get("splits") or (doc.get("base") or {}).get("splits") or "")
PY
)
sym_h1=$(sha1sum "$SYMBOLS" | cut -d' ' -f1); sym_m1=$(stat -c %Y "$SYMBOLS")
spl_h1=$(sha1sum "$SPLITS" | cut -d' ' -f1);  spl_m1=$(stat -c %Y "$SPLITS")

sleep 1.1   # so an mtime bump would be observable at 1 s granularity
"$DTK" xex split "$CONFIG" "$OUT" >/dev/null 2>&1 || { echo "FATAL: split 2 failed" >&2; exit 2; }
h2=$(sha1sum "$MANIFEST" | cut -d' ' -f1)
m2=$(stat -c %Y "$MANIFEST")
check "manifest CONTENT is a fixed point" "$h1" "$h2"
check "manifest MTIME is a fixed point (write_if_changed)" "$m1" "$m2"
check "symbols.txt CONTENT unchanged by its own split" "$sym_h1" "$(sha1sum "$SYMBOLS" | cut -d' ' -f1)"
check "symbols.txt MTIME unchanged by its own split"   "$sym_m1" "$(stat -c %Y "$SYMBOLS")"
check "splits.txt CONTENT unchanged by its own split"  "$spl_h1" "$(sha1sum "$SPLITS" | cut -d' ' -f1)"
check "splits.txt MTIME unchanged by its own split"    "$spl_m1" "$(stat -c %Y "$SPLITS")"

# Objects too: a split that rewrote every .obj unconditionally would defeat
# write_coff_if_changed and cascade a full rebuild on every ninja run.
obj_moved=$(find "$OUT/obj" -newermt "@$m1" -name '*.obj' | wc -l)
check "no target .obj rewritten by the unchanged re-split" "0" "$obj_moved"

say "== NEGATIVE CONTROL: rename one symbol in $SYMBOLS =="
# The whole point of the manifest is that a symbols.txt edit rewrites the COFF
# symbol tables of the objects it touches. If the manifest cannot see THAT, it
# cannot see anything, and the two GREENs above are vacuous.
python3 - "$SYMBOLS" <<'PY'
import re, sys
path = sys.argv[1]
lines = open(path).read().splitlines(keepends=True)
for i, line in enumerate(lines):
    m = re.match(r"^(\s*)([A-Za-z_?][\w?@$]*)( = \.text:.*type:function.*)$", line.rstrip("\n"))
    if m and "fn_" not in m.group(2) and not m.group(2).startswith("__imp_"):
        # Keep the newline. Dropping it merges this line into the next, and the
        # split then dies on a *parse* error rather than on the rename -- which
        # would make the "manifest moved" assertion below true for the wrong
        # reason. (Caught by exactly that failure while writing this.)
        lines[i] = f"{m.group(1)}zzSABOTAGE{m.group(2)}{m.group(3)}\n"
        print(f"  sabotaged line {i+1}: {m.group(2)} -> zzSABOTAGE{m.group(2)}")
        break
else:
    sys.exit("FATAL: found no symbol line to sabotage")
open(path, "w").writelines(lines)
PY
[ $? -eq 0 ] || exit 2
LOG=$(mktemp -t sabotage-split-XXXXXX.log)
if ! "$DTK" xex split "$CONFIG" "$OUT" >"$LOG" 2>&1; then
  echo "FATAL: sabotaged split failed; tail of $LOG:" >&2; tail -20 "$LOG" >&2; exit 2
fi
rm -f "$LOG"
h3=$(sha1sum "$MANIFEST" | cut -d' ' -f1)
check_ne "manifest moves when symbols.txt moves" "$h2" "$h3"
moved=$(python3 - "$MANIFEST" <<'PY'
import json, sys
man = json.load(open(sys.argv[1]))
print(sum(1 for k in man["inputs"] if k.endswith("symbols.txt")))
PY
)
check "symbols.txt is one of the declared inputs" "1" "$moved"

say "== restore and re-verify =="
cp -p "$BACKUP" "$SYMBOLS"
"$DTK" xex split "$CONFIG" "$OUT" >/dev/null 2>&1 || { echo "FATAL: restore split failed" >&2; exit 2; }
h4=$(sha1sum "$MANIFEST" | cut -d' ' -f1)
check "manifest returns to its pre-sabotage value" "$h2" "$h4"

if [ "$fail" = 0 ]; then say "ALL GREEN"; else say "FAILED"; fi
exit "$fail"
