# T3 — regression tests: the red half of the red/green witness

Branch `jeff-t3`, worktree `.worktrees/t3`, base `main` = `8a42efb`,
commit `50aa582`. Written before any fix exists, so the fix has a witness.

Files owned by T3 (T4/T5 must not touch them):

- `src/util/xex_reloc_tests.rs` (new, 466 lines) — **committed on `jeff-t3`**
- `src/util/mod.rs` (one two-line hunk: `#[cfg(test)] mod xex_reloc_tests;`) —
  **committed on `jeff-t3`**
- this file, and the T3 entry in `../NOTES.md` — **NOT committed anywhere.** The
  whole session folder is untracked in the main checkout (`git ls-files
  docs/sessions/` is empty; the scribe left commits to the integrator), so these
  live only in the main checkout's working tree, alongside `README.md` and
  `NOTES.md`. Committing a copy on a lane branch would make `git merge jeff-t3`
  abort on an untracked-file overwrite when the integrator lands it.

---

## 0. Correction to the brief: `cargo test --lib` cannot run here

The task's verification command was
`CARGO_TARGET_DIR=<worktree>/target-scratch cargo test --lib xex_reloc`.
That command **cannot work in this repo**, and not because of anything I did:

```
$ CARGO_TARGET_DIR=.../target-scratch cargo test --lib xex_reloc
error: no library targets found in package `decomp-toolkit`
```

`Cargo.toml` declares only `[[bin]] name = "dtk", path = "src/main.rs"`. There is
no `[lib]` target and no `src/lib.rs`, so every unit test in this crate — including
the pre-existing `#[cfg(test)] mod tests` inside `src/util/xex.rs` and
`src/util/disasm_tests.rs` — runs under the **bin** test harness. The working
command, used for every number below, is:

```
CARGO_TARGET_DIR=<worktree>/target-scratch cargo test --bin dtk xex_reloc
```

I deliberately did **not** add a `[lib]` target to make the brief's command work.
That is a structural change to a shared `Cargo.toml` (it would require creating
`src/lib.rs`, re-exporting the module tree, and would change what `cargo build
--release` produces) — far out of proportion to a test-registration task, and
`Cargo.toml` is not a file T3 owns. The integrator should either accept
`--bin dtk` or take that change deliberately.

## 1. What was built

Three tests in one new file, each with a synthetic `ObjInfo` fixture constructed
in-test. No test reads a dc3 or rb3-xenon checkout, an XEX, `objdiff.json`, a
compiler, or `objdiff-cli`. They run in 0.00s.

Structure follows `src/util/disasm_tests.rs` (a `src/util/` module registered from
`src/util/mod.rs`) and reuses the fixture idiom already proven in
`src/util/xex.rs`'s own `mod tests` (`ObjInfo::new(...)` + `symbols.add_direct`).
Readback is via the `object` crate (`object::File::parse` → `sections()` →
`relocations()` → `RelocationFlags::Coff { typ }` / `RelocationTarget::Symbol`),
not a hand-rolled COFF parser: COFF *read* support is available because the
`object` dependency is a git dep **without** `default-features = false`, so the
default `read` feature (which includes `coff`) is on.

| test | shape | status at `8a42efb` |
|---|---|---|
| `shape2_intra_function_conditional_branch_emits_no_relocation` | Shape 2 | **RED** |
| `ds_form_immediate_zeroing_must_preserve_xo_bits` | Q8 / FINDING 8 | **RED** |
| `refhi_reflo_pair_record_shape_is_pinned` | characterization | GREEN |

### (1) SHAPE 2 — intra-function conditional branch must produce no relocation

Fixture: a 0x40-byte `.text`, one Global Function symbol `Curl_resolv_unlock` at
offset 0 size 0x40, `0x419A0010` (`beq cr6, +0x10`) at `fn+0x24` — the exact word
NOTES.md FINDING 7 measured byte-identical in both objects — and an
`ObjRelocKind::PpcRel14` at 0x24 anchored on the function itself with the
in-memory addend 0x34 that `tracker.rs:860` would have recorded.

Assertion: parse the emitted COFF back, take `.text`'s relocation records, and
require **zero** `IMAGE_REL_PPC_REL14` (0x0007) records whose site lies inside
`[fn, fn+size)` and whose anchor symbol is that same function. Ground for the
invariant is NOTES.md FINDING 3: MSVC emits zero REL14 across 2,193
compiler-produced objects in dc3 and rb3-xenon, so *every* REL14 in a target
object is splitter-originated.

### (2) DS-FORM — the immediate zeroing must not clear the XO bits

Fixture: three `PpcAddr16Lo` relocations on three consecutive words in `.text`,
targeting a `.rdata` object symbol.

| offset | input | expected out | rationale |
|---|---|---|---|
| +0x00 | `0xE96B0002` | `0xE96B0002` | DS-form `lwa r11, 0(r11)` — the exact word measured at three REFLO sites in our own `system/gesture/ArcDetector.obj` (FINDING 8). XO=2 must survive. |
| +0x04 | `0xE96B004A` | `0xE96B0002` | same `lwa` with displacement 0x48 — proves the displacement really *is* zeroed, so a fix cannot pass by deleting the arm. |
| +0x08 | `0x398C0048` | `0x398C0000` | **D-form control** `addi r12, r12, 0x48`. Passes today and must keep passing. |

The control is the point of the third row: it makes "just stop zeroing" a failing
fix rather than a passing one. Only the two DS-form rows are red.

### (3) Characterization — today's REFHI/REFLO + PAIR record shape, pinned

Not a bug. This pins the layout so future anchor/label work cannot change it
silently — in particular it fails if anyone starts carrying the intra-function
offset in the PAIR `SymbolTableIndex` displacement channel, which FINDING 2 shows
would move the artifact rather than remove it (PAIR displacement is 0 in
**342,386 of 342,386** dc3 compiler REFHI/REFLO).

Fixture starts with *nonzero* immediates (`lis r12, 0x8200` / `addi r12, r12,
0x1234`) so invariant 4 is an assertion about the fixup, not about the input.

Pinned invariants, all four measured green at `8a42efb`:

1. exactly one PAIR per REFHI and per REFLO;
2. each PAIR sits at the same section offset as, and immediately after, its partner;
3. the PAIR's `SymbolTableIndex` field is **0**;
4. the in-place 16-bit immediate at each REFHI/REFLO site is 0, and the rest of
   the instruction survives (`0x3D800000`, `0x398C0000`).

Measured record table (captured with a temporary `println!`, since removed):

```
.text relocation records:
  offset 0x0, typ 0x10 (REFHI), SymbolTableIndex 2  -> "?g_target@@3HA"
  offset 0x0, typ 0x12 (PAIR),  SymbolTableIndex 0  -> "@comp.id"
  offset 0x8, typ 0x11 (REFLO), SymbolTableIndex 2  -> "?g_target@@3HA"
  offset 0x8, typ 0x12 (PAIR),  SymbolTableIndex 0  -> "@comp.id"
.text bytes: 3D 80 00 00  60 00 00 00  39 8C 00 00  4E 80 00 20
```

Note index 0 resolves to a real symbol, `@comp.id` — `write_coff` adds it first
precisely so the PAIR's index lands on 0 (the `object::write` API demands a
`SymbolId` for a field that is not a symbol reference). The test asserts on the
raw index, not the name, because 0 is what MSVC writes.

---

## 2. The red output — verbatim

`main` = `8a42efb`, worktree `.worktrees/t3` at commit of `xex_reloc_tests.rs`:

```
$ CARGO_TARGET_DIR=/home/free/code/milohax/jeff/.worktrees/t3/target-scratch \
    cargo test --bin dtk xex_reloc

running 3 tests
test util::xex_reloc_tests::refhi_reflo_pair_record_shape_is_pinned ... ok
test util::xex_reloc_tests::shape2_intra_function_conditional_branch_emits_no_relocation ... FAILED
test util::xex_reloc_tests::ds_form_immediate_zeroing_must_preserve_xo_bits ... FAILED

failures:

---- util::xex_reloc_tests::shape2_intra_function_conditional_branch_emits_no_relocation stdout ----

thread 'util::xex_reloc_tests::shape2_intra_function_conditional_branch_emits_no_relocation' (3646108) panicked at src/util/xex_reloc_tests.rs:226:5:
write_coff emitted 1 intra-function IMAGE_REL_PPC_REL14 record(s); MSVC emits zero REL14 in 2,193 compiler-produced objects across dc3 and rb3-xenon (session NOTES.md FINDING 3). Offenders: [
    CoffRelocRecord {
        offset: 0x24,
        typ: 0x7,
        symbol_index: 0x1,
        symbol_name: "Curl_resolv_unlock",
    },
]
All .text records: [
    CoffRelocRecord {
        offset: 0x24,
        typ: 0x7,
        symbol_index: 0x1,
        symbol_name: "Curl_resolv_unlock",
    },
]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

---- util::xex_reloc_tests::ds_form_immediate_zeroing_must_preserve_xo_bits stdout ----

thread 'util::xex_reloc_tests::ds_form_immediate_zeroing_must_preserve_xo_bits' (3646106) panicked at src/util/xex_reloc_tests.rs:326:5:
write_coff's REFHI/REFLO immediate zeroing corrupted 2 of 3 sites.
  +0x00: in 0xE96B0002 -> out 0xE96B0000, expected 0xE96B0002 (XO bits in=0x2 out=0x0 expected=0x2)
  +0x04: in 0xE96B004A -> out 0xE96B0000, expected 0xE96B0002 (XO bits in=0x2 out=0x0 expected=0x2)
`insn & 0xFFFF0000` clears the low two bits, which on a DS-form opcode (primary 58/62) are the opcode extension, not displacement: `lwa` becomes `ld`. Session NOTES.md FINDING 8 / README Q8.


failures:
    util::xex_reloc_tests::ds_form_immediate_zeroing_must_preserve_xo_bits
    util::xex_reloc_tests::shape2_intra_function_conditional_branch_emits_no_relocation

test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 159 filtered out; finished in 0.00s

error: test failed, to rerun pass `--bin dtk`
```

Whole-suite baseline, same command without the filter — the two reds are the only
failures, nothing pre-existing broke:

```
$ CARGO_TARGET_DIR=.../target-scratch cargo test --bin dtk
test result: FAILED. 160 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s
```

159 pre-existing tests, all green, + my 3 = 162; 160 pass, 2 fail.

The DS-form failure is the direct runtime confirmation of FINDING 8, which until
now was a code read plus a static census. `0xE96B0002` (`lwa`) goes into
`write_coff` and `0xE96B0000` (`ld`) comes out. FINDING 8's caution stands — this
proves the writer defect, not that it fired on dc3 retail (`grep -rE '^\s+lwa\s'
build/373307D9/asm/` is still 0).

## 3. Caveats the fixer must read

**(a) Test 1 pins the WRITER seam, not the root cause — deliberately.** The
fixture already contains the bad `PpcRel14`, so only a `write_coff`-side filter
turns it green. README §2.3 / Q5 says the real producer may be
`analysis/tracker.rs`, and fixing it there would be the better root-cause fix —
but this test would **stay red** after such a fix, because `write_coff` would still
faithfully copy the relocation in this fixture. That is intended: the writer is
the last place the invariant "no intra-function REL14 ever reaches a COFF" can be
enforced unconditionally, and the census says the compiler emits zero REL14 at
all, so a defensive drop there costs nothing. If the integrator decides the drop
belongs only in the tracker, **this test must be re-pointed at the tracker rather
than deleted** — do not "fix" it by weakening the assertion.

**(b) Test 1 does not assert on rendering, only on record presence.** It says
nothing about whether objdiff would still charge the row. That is the A/B
harness's job (Q6), not a unit test's.

**(c) Test 3 will legitimately need updating if label synthesis lands.** If a fix
synthesises `$LN`/`lbl_<addr>` anchors, the *anchor symbol* changes but invariants
1–4 must not. If a change to test 3 becomes necessary, the changed invariant is
the thing to argue about in review — that is the whole point of pinning it now.

**(d) Test 2's expected value assumes the fix zeroes bits [15:2] on DS-form.**
If the eventual fix instead keys on the relocation target's alignment, or refuses
to fix up DS-form at all, the expectation may need restating. The load-bearing
claim — XO must survive — does not change.

**(e) No `objdiff.json`, no ruler, no A/B here.** T3 is unit-grain only. Nothing
in this file is evidence about scores, and nothing in it licenses a deploy.

## 4. Hazard compliance

- Built **only** with `CARGO_TARGET_DIR=/home/free/code/milohax/jeff/.worktrees/t3/target-scratch`.
  No bare `cargo build --release` was ever run in this repo.
- `ls -la /home/free/code/milohax/jeff/target/release/dtk` →
  `-rwxr-xr-x 2 free free 8371016 Aug  8 22:32` — **mtime unchanged** (Aug 8 22:32),
  checked after the last build. The deployed dc3/rb3-xenon splitter was not touched.
- Worktree branch `jeff-t3`, never `main`. No `git stash`. Nothing pushed.
- dc3 was not rebuilt, re-split, or read. `report.json` was not consulted.
- `target-scratch/` is untracked and was never staged (explicit `--` pathspec on
  every commit).
