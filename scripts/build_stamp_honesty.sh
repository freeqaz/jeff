#!/usr/bin/env bash
# Does `dtk --version` tell the truth about the tree it was built from?
#
# WHY. On 2026-08-18 the deployed `dtk` reported
#     dtk 1.14.0 b4b25bcb4805a7a7f1701ff48c31ab5a3a9768de
# while containing code from `614331e`, a commit that was not even an ancestor
# of `main`. It had been built from a dirty tree a minute before `b4b25bc`
# landed, and `git rev-parse HEAD` reported the commit that was CHECKED OUT
# rather than the code that was COMPILED. That binary writes the reference side
# of every diff in three decomp repos. The only check that could tell was
#     strings -a dtk | grep -c __comdat_gap
#
# THE TRAP THIS AVOIDS. "the stamp contains a sha" is not the assertion -- that
# is equally true of the broken version, which is the entire problem. So this
# script SABOTAGES: it builds clean, dirties the one file that decides how
# objects are split, rebuilds, and requires the stamp to SAY SO. Then it cleans
# up and requires the stamp to come back to exactly its pre-sabotage value, so a
# stamp that is permanently "-dirty" fails too.
#
# It caught a real defect while being written. The first version of `build.rs`
# declared only the git refs as `rerun-if-changed` inputs -- which switches off
# cargo's "any file in the package" fallback, so an unstaged source edit no
# longer re-ran the build script and the `-dirty` marker never appeared. The
# fix (declaring `src/` as well) is in `build.rs`; this script is why it was
# found rather than shipped.
#
# Usage:
#   scripts/build_stamp_honesty.sh [path-to-a-clean-checkout]
#
# Defaults to the repo this script lives in. It edits a tracked file and
# restores it from a byte copy in a trap, including on Ctrl-C.
set -uo pipefail

REPO=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
cd "$REPO" || exit 2

# The file to dirty: the splitter itself, so a false GREEN is maximally damning.
VICTIM=src/util/xex.rs
[ -f "$VICTIM" ] || { echo "FATAL: $VICTIM not found under $REPO" >&2; exit 2; }

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "FATAL: $REPO already has modified tracked files." >&2
  echo "       This test needs a clean starting point to have a control." >&2
  git status --porcelain --untracked-files=no >&2
  exit 2
fi

BACKUP=$(mktemp -t xex-backup-XXXXXX)
cp -p "$VICTIM" "$BACKUP"
# NOTE the deliberate absence of `-p`, and the `touch`. Restoring with `cp -p`
# puts the ORIGINAL mtime back -- older than the sabotaged version -- and cargo
# watches `rerun-if-changed` paths by MTIME, not content, so it does not notice
# and leaves the previous binary in place. State 3 below went red for exactly
# that reason the first time this ran. It is the same mtime-invisible class the
# split manifest exists to defeat (restore `symbols.txt` with an older mtime and
# ninja does not plan a SPLIT at all), and it is worth knowing that cargo has it
# too: a `git stash pop`, a `tar -x` or a reflinked worktree can leave you
# running a binary built from code that is no longer on disk.
restore() { cp "$BACKUP" "$VICTIM"; touch "$VICTIM"; rm -f "$BACKUP"; return 0; }
trap restore EXIT INT TERM

fail=0
say() { printf '%s\n' "$*"; }
check() { if [ "$2" = "$3" ]; then say "  GREEN  $1"; else say "  RED    $1"; say "           expected: $2"; say "           actual:   $3"; fail=1; fi; }
check_contains() { case "$3" in *"$2"*) say "  GREEN  $1";; *) say "  RED    $1"; say "           expected to contain: $2"; say "           actual:              $3"; fail=1;; esac; }
check_not_contains() { case "$3" in *"$2"*) say "  RED    $1"; say "           must NOT contain: $2"; say "           actual:          $3"; fail=1;; *) say "  GREEN  $1";; esac; }

build_and_stamp() {
  cargo build --release >/dev/null 2>&1 || { echo "FATAL: cargo build failed" >&2; exit 2; }
  ./target/release/dtk --version
}

say "== state 1: clean tree =="
CLEAN=$(build_and_stamp); say "  $CLEAN"
check_not_contains "a clean build is not marked dirty" "-dirty" "$CLEAN"
check_contains "a clean build names its commit" "$(git rev-parse HEAD)" "$CLEAN"
check_contains "a clean build carries the authoritative hash" "xxh3 " "$CLEAN"

say "== state 2: dirty tree (an UNSTAGED edit to $VICTIM) =="
printf '\n// deliberate dirt: scripts/build_stamp_honesty.sh\n' >> "$VICTIM"
DIRTY=$(build_and_stamp); say "  $DIRTY"
check_contains "a dirty build SAYS SO" "-dirty" "$DIRTY"
check_ne_hash() {
  local a b
  a=$(printf '%s' "$1" | sed -n 's/.*xxh3 \([0-9a-f]*\).*/\1/p')
  b=$(printf '%s' "$2" | sed -n 's/.*xxh3 \([0-9a-f]*\).*/\1/p')
  if [ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ]; then say "  GREEN  $3"; else say "  RED    $3 ($a vs $b)"; fail=1; fi
}
check_ne_hash "$CLEAN" "$DIRTY" "the authoritative hash moved with the code"

say "== state 3: restored =="
restore; trap - EXIT INT TERM
BACK=$(build_and_stamp); say "  $BACK"
# The control for state 2: a stamp permanently stuck at "-dirty", or a hash that
# never returns, would pass everything above and be just as useless.
check "restoring the file restores the stamp exactly" "$CLEAN" "$BACK"

say ""
if [ "$fail" = 0 ]; then say "ALL GREEN"; else say "FAILED"; fi
exit "$fail"
