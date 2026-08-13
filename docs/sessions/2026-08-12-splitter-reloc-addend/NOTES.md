# NOTES — append-only phase log

Rules: append, never rewrite. One dated entry per phase/session. Negative
results are first-class entries. Every number gets a command or artifact path
next to it.

---

## 2026-08-12 — scribe: session doc written (no code touched)

- Wrote `README.md` in this folder from the gap-bug-hunt reviewer readout
  (`decomp-bench/archive/runs/2026-08-12-gap-bug-hunt/README.md` §4) and a
  code-reading pass at `main` = `8a42efb`.
- Verified in-repo while writing (commands in README):
  - `git rev-list --left-right --count main...upstream/main` → `269 16`;
    the 16 upstream subjects are listed in README §3 Q1.
  - `upstream/main` has no `src/util/xex.rs` / COFF writer — the XEX→COFF
    path is fork-original, so the fix cannot be a pure port.
  - `dc3-decomp/configure.py:164` confirms hazard 1 (bare build = deploy).
  - Prior merged lane `fix/jumptable-internal-branch-targets` (`dde965c`) is
    adjacent prior art: internal branch targets seeding functions — a
    different defect, but its fixtures may be reusable.
- Candidate loss point from code reading (UNCONFIRMED at runtime, README §2):
  anchor chosen by `tracker.rs:835-881` + `symbols.rs:545-576` (function
  symbol + addend), addend destroyed by the REFHI/REFLO immediate zeroing in
  `xex.rs write_coff` `:2123-2138`. Validator must confirm via Q7 before any
  patch.
- Nothing committed by the scribe; integrator owns commits.

Next phase (validator): answer README §3 Q1–Q7, in this file, before any code.

---

## 2026-08-12 — validator: measured pass. Premise 22/23 WRONG — the fix is already in objdiff, undeployed

All numbers below are first-hand from the real dc3/rb3-xenon objects and the
deployed binaries. Scratch + scripts: `scratch/` in this folder (probe2.py is the
per-function relocation dumper; `objdiff-target-scratch/` is a PRIVATE
`CARGO_TARGET_DIR` build of objdiff — the deploy path was not touched).

### FINDING 1 (headline) — 22 of the 23 rows are already fixed in objdiff `main`

`objdiff-core/src/diff/code.rs` contains `interior_self_reference()`, landed in
objdiff commit `4c38c31` "NameCheck: the switch-dispatch base is the same
address; dtk lost the addend", **2026-08-12 06:03:38 +0000**. Its doc comment
diagnoses this exact defect, from the same evidence (dc3
`SaveLoadManager::GetDialogMsg`), and describes the dtk COFF writer dropping the
addend. It is gated on `functionRelocDiffs == NameCheck`.

The deployed binary `~/.local/bin/objdiff-cli` -> `objdiff/target/release/objdiff-cli`
was built **2026-08-12 05:56** — seven minutes BEFORE that commit. So the
gap-bug-hunt measured a ruler that predates its own fix.

Measured, both binaries, all 23 rows (command: `objdiff-cli diff -p . -u <unit>
<symbol> --include-instructions`, run in `/home/free/code/milohax/dc3-decomp`):

| arm | rows still charged |
|---|---|
| deployed objdiff-cli (built 05:56) | 23 / 23 |
| objdiff HEAD `9138611` built in scratch | **1 / 23** (G36 only) |

G11 G12 G13 G15 G16 G17 G19 G20 G21 G24 G25 G26 G27 G28 G29 G33 G34 G35 G37 G38
G39 G40 all go to **zero instruction mismatches / 100.0% normalized**. Only G36
`Curl_resolv_unlock` survives.

**Consequence: Shape 1 needs no splitter change.** It needs an objdiff-cli
rebuild + a parity account. Shape 2 is the only live splitter defect.

### FINDING 2 — the §1.1 mechanism claim is wrong: PPC-COFF DOES have an addend field

`IMAGE_REL_PPC_PAIR`'s `SymbolTableIndex` field is, per the MS PE/COFF spec, a
**displacement, not a symbol index**. This repo already knows it —
`src/util/xex.rs:2468-2471` says so verbatim. So "REFHI/REFLO carry no addend
field" is false.

It is nonetheless an unusable channel, for a measured reason rather than the
stated one. Across all 989 dc3 compiler-produced objects: **342,386 REFHI/REFLO
relocations, PAIR displacement = 0 in 342,386 of 342,386**, in-place immediate
nonzero in 3. MSVC never uses it; the compiler's convention is a symbol whose
*value* sits at the target address. Using the PAIR displacement would move the
artifact, not remove it.

### FINDING 3 — Q2 ANSWERED: rb3-xenon IS affected. Project-wide census (both games)

Self-referential REFHI/REFLO = anchor symbol is the function enclosing the
relocation site. This is the Shape-1 population (it includes a legitimate
address-of-own-entry subset; ours has one, `?CharTerminate@@YAXXZ`).

| tree | objects | self-ref REFHI/REFLO | distinct fns | REL14 | REL14 intra-fn |
|---|---|---|---|---|---|
| dc3 TARGET `build/373307D9/obj` | 2223 | **350** | **154** | **8** | **2** |
| dc3 OURS `build/373307D9/src` | 989 | 6 | 3 | **0** | 0 |
| rb3-xenon TARGET `build/45410914/obj` | 3085 | **262** | **110** | **650** | **59** |
| rb3-xenon OURS `build/45410914/src` | 1204 | 20 | 10 | **0** | 0 |

Two things this settles. (a) The "23" was a sample count, not a census — dc3's
real Shape-1 population is 154 functions. (b) **The MSVC compiler emits ZERO
REL14 relocations in 2,193 objects across both games.** Every REL14 in a target
object is splitter-originated. rb3-xenon carries 650 of them, 59 intra-function
— Shape 2 is ~30x bigger on rb3-xenon than on dc3.

### FINDING 4 — §1.3's rb3 claim is unsupported and almost certainly false

`rb3` is the **Wii/mwcceppc/ELF** target (`objdiff.json` unit 0:
`build/SZBE69_B8/obj/App.o`). Its objects come from the ELF writer, which emits
RELA with an explicit `r_addend` (`src/util/elf.rs:743` — verified). The
addend-less PPC-COFF encoding is not in that path, so this fix cannot retire
rb3's 16 branch rows. The affected sibling is **rb3-xenon**, not rb3. §Q4 was
right to flag it; the §1.3 sentence should not have asserted it.

### FINDING 5 — the shipped ruler is `name_check`, not `none`

`objdiff.json` `options.functionRelocDiffs` is **`name_check`** in all three of
dc3-decomp, rb3, rb3-xenon. This matters twice: the entire `interior_self_reference`
tolerance is NameCheck-only, and any label-synthesis fix must survive a ruler
that compares relocation target NAMES. `is_compiler_local_label()` already
forgives a `$`-prefixed left-side name, but a synthesized `lbl_<addr>` is
forgiven by `is_placeholder_symbol_name()` instead — both paths exist, which one
applies must be checked, not assumed.

### FINDING 6 — Q1 ANSWERED: this is NOT a port, and task #144's premise is half wrong

`git rev-list --left-right --count main...upstream/main` = `269 16` (reproduced).
`git ls-tree -r --name-only upstream/main src/` matches nothing for
coff/xex/msvc/ppc — upstream has no COFF writer and no XEX path, confirmed.

Of the 16: 5 are version bumps / edition-2024 reformat / clippy / precommit
(`e4219e7 6baa8a0 c4de1b4 06749b8 0e8ea40 2b39879 65fdf9b 6bef60c`), 1 splits
dwarf printing (`fdf1ed0`), 2 are GC-only extab (`af8595e 46e6052`), 1 is REL
section vaddr (`8c77e49`), 1 advisories (`02b343f`). Only three touch analysis
that could matter: `89106d0` clamps inferred jump-table size to section size
(`src/analysis/mod.rs`, +9/-4 — a bounds fix on table LENGTH, nothing to do with
anchor selection), `aa635e1` stricter prologue terminator checks
(`src/analysis/slices.rs`), `43d602b` warn-and-continue on a missing REL target.
**None addresses anchor selection or the addend.** Describing the 16 as
"splitter correctness fixes" (#144) is not accurate; the rebase is still worth
doing for its own sake but it is not on this critical path.

### FINDING 7 — confirmations (the doc was right about these)

- G33 `?SongInfoAudioTypeToSym`: TARGET `fn+0x2c/0x34` REFHI/REFLO -> the
  function symbol (val 0x0); OURS -> `$LN27` val **0x48**, storage class **6 =
  IMAGE_SYM_CLASS_LABEL**. Both in-place words `3d800000`/`398c0000`. Exactly as
  written.
- G24 `?HandleEventResponse@SaveLoadManager@@QAAXPAVHamProfile@@H@Z`: TARGET
  `fn+0x25c/0x264` -> function symbol val 0x0; OURS -> `$LN34` val **0x164**,
  class 6. **Anchor delta 0x164 CONFIRMED.**
- Jump tables byte-identical CONFIRMED: target `jumptable_820FDEF0` (section
  `/60`, 0x1b bytes) and our `$T224728` (`.rdata`+0x190) agree on all 27 bytes:
  `0049654465000000 6565656565656554 65655959656000 65`.
- `BranchDest` typing CONFIRMED: objdiff's JSON gives `lis`/`addi` a
  `{"type":"BranchDest"}` operand (`typed_args`), target value 0 vs base 356
  (=0x164). The opcode is not a branch; the tier predicate was fooled exactly as
  described.
- G36 `Curl_resolv_unlock`: target carries `+0x24` REL14 -> `Curl_resolv_unlock`
  (sym val 0x518 = function start); ours carries none. objdiff renders
  `beq cr6, 0x518` vs `beq cr6, 0x34`.
- Every §2 line-number citation verifies at `8a42efb` (xex.rs:1781 `write_coff`,
  tracker.rs:795 `apply_relocations`, symbols.rs:545 `for_relocation`,
  elf.rs:743 `r_addend`, split.rs:1426, xex.rs:1911, xex.rs:2321).
- Q7 answered by code, not runtime: `tracker.rs:860` records
  `(symbol_idx, target.address - symbol_address)`, so the ObjInfo DOES carry the
  addend; `xex.rs:2123-2138` (`insn & 0xFFFF0000`) is where it dies. A runtime
  assert is still worth having, but the read is unambiguous.

### FINDING 8 (new, latent) — the immediate-zeroing corrupts DS-form opcodes

`write_coff`'s `PpcAddr16Ha | PpcAddr16Lo` arm does `insn & 0xFFFF0000`. In a
DS-form instruction (primary opcode 58 `ld/ldu/lwa`, 62 `std/stdu`) the low TWO
bits are opcode extension, not displacement. Zeroing them silently rewrites
`lwa`->`ld` and `stdu`->`std`.

Measured: dc3 target has **74** REFLO sites on a DS-form opcode, rb3-xenon **51**
— and the XO bits are 0 at all 74. Our own compiler objects prove the shape is
real: `system/gesture/ArcDetector.obj` has three `lwa` (`0xe96b0002`, XO=2) at
REFLO sites. NOT yet proven to have fired on retail: `grep -rE '^\s+lwa\s'
build/373307D9/asm/` returns **0** across the whole dc3 disassembly, so dc3
retail may genuinely contain no `lwa` at a relocated site. Treat as a latent
writer defect to be closed by construction, not as a measured dc3 corruption.
The equivalent check has not been run on rb3-xenon.

---

## 2026-08-12 — T3: regression tests written before the fix. 2 RED, 1 GREEN, at `8a42efb`

Branch `jeff-t3`, worktree `.worktrees/t3`, commit `50aa582`. Code on the branch:
`src/util/xex_reloc_tests.rs` (new), `src/util/mod.rs` (+2 lines). Docs here in the
session folder: `findings/T3-regression-tests.md` (full detail + verbatim failure
output) and this entry.

Three tests, each on a synthetic `ObjInfo` built in-test. No dc3/rb3-xenon
checkout, no XEX, no compiler, no `objdiff-cli`; total runtime 0.00s. Readback of
the emitted COFF is via the `object` crate (`File::parse` → `sections()` →
`relocations()`); COFF *read* is available because the `object` git dependency
does not set `default-features = false`.

### CORRECTION to the T3 brief — `cargo test --lib` cannot run in this repo

```
$ CARGO_TARGET_DIR=.../target-scratch cargo test --lib xex_reloc
error: no library targets found in package `decomp-toolkit`
```

`Cargo.toml` declares only `[[bin]] name = "dtk"`. There is no `[lib]` target and
no `src/lib.rs`, so every unit test in this crate — including the pre-existing
`mod tests` inside `src/util/xex.rs` — runs under the **bin** harness. The working
command is `cargo test --bin dtk xex_reloc`. I did not add a `[lib]` target to
make the brief's command work: that is a structural change to a shared
`Cargo.toml` and out of proportion to a test task. Integrator's call.

### The red half of the witness (verbatim, trimmed to the assertions)

```
running 3 tests
test util::xex_reloc_tests::refhi_reflo_pair_record_shape_is_pinned ... ok
test util::xex_reloc_tests::shape2_intra_function_conditional_branch_emits_no_relocation ... FAILED
test util::xex_reloc_tests::ds_form_immediate_zeroing_must_preserve_xo_bits ... FAILED

---- shape2_intra_function_conditional_branch_emits_no_relocation ----
write_coff emitted 1 intra-function IMAGE_REL_PPC_REL14 record(s); ... Offenders: [
    CoffRelocRecord { offset: 0x24, typ: 0x7, symbol_index: 0x1,
                      symbol_name: "Curl_resolv_unlock" },
]

---- ds_form_immediate_zeroing_must_preserve_xo_bits ----
write_coff's REFHI/REFLO immediate zeroing corrupted 2 of 3 sites.
  +0x00: in 0xE96B0002 -> out 0xE96B0000, expected 0xE96B0002 (XO in=0x2 out=0x0)
  +0x04: in 0xE96B004A -> out 0xE96B0000, expected 0xE96B0002 (XO in=0x2 out=0x0)

test result: FAILED. 1 passed; 2 failed; 0 ignored; 159 filtered out
```

Whole suite, same private target dir: `160 passed; 2 failed` — the two failures
are the intended reds; the 159 pre-existing tests are untouched and green.

### NEW MEASUREMENT — FINDING 8 confirmed at runtime, not only by code read

FINDING 8 was a code read (`insn & 0xFFFF0000`) plus a static census of DS-form
REFLO sites. It is now reproduced end-to-end through `write_coff`: `0xE96B0002`
(`lwa r11, 0(r11)`, the exact word measured at three REFLO sites in our own
`system/gesture/ArcDetector.obj`) goes in, `0xE96B0000` (`ld`) comes out. A second
site `0xE96B004A` (same `lwa`, displacement 0x48) also comes out `0xE96B0000`,
which shows the two failures are one defect and not a displacement artefact. The
fixture also carries a **D-form control**, `addi r12, r12, 0x48` → `0x398C0000`,
which passes today and must keep passing — so a "fix" that merely deletes the
zeroing arm fails the test. FINDING 8's caution is unchanged: this proves the
*writer* defect, not that it fired on dc3 retail.

### NEW MEASUREMENT — today's REFHI/REFLO+PAIR record shape, pinned

Captured from the emitted COFF (temporary `println!`, since removed):

```
.text relocation records:
  offset 0x0, typ 0x10 (REFHI), SymbolTableIndex 2  -> "?g_target@@3HA"
  offset 0x0, typ 0x12 (PAIR),  SymbolTableIndex 0  -> "@comp.id"
  offset 0x8, typ 0x11 (REFLO), SymbolTableIndex 2  -> "?g_target@@3HA"
  offset 0x8, typ 0x12 (PAIR),  SymbolTableIndex 0  -> "@comp.id"
.text bytes: 3D 80 00 00  60 00 00 00  39 8C 00 00  4E 80 00 20
```

So: one PAIR per REFHI/REFLO, same offset, immediately after its partner,
`SymbolTableIndex` 0, in-place immediate zeroed (input immediates were nonzero —
`0x3D808200` / `0x398C1234` — so invariant 4 tests the fixup, not the input).
Index 0 resolves to a real symbol, `@comp.id`, which `write_coff` adds first
precisely so the index lands on 0. This is now a test, so any future anchor work
that starts carrying the addend in the PAIR displacement channel — which FINDING 2
shows would move the artifact rather than remove it (0 in 342,386 of 342,386) —
trips it.

### Caveat the fixer must read before going green

Test 1 asserts at the **`write_coff` seam** on a fixture that already contains the
bad `PpcRel14`. Only a writer-side filter turns it green. If the root-cause fix
lands in `analysis/tracker.rs` (README §2.3 / Q5), that is the better fix but this
test **stays red**, because `write_coff` would still copy the relocation through.
That is deliberate — the writer is the last place the invariant "no
intra-function REL14 ever reaches a COFF" can be enforced unconditionally, and
FINDING 3 says MSVC emits zero REL14 at all, so a defensive drop costs nothing. If
the integrator decides the drop belongs only in the tracker, **re-point this test;
do not weaken the assertion.** Test 3 will also legitimately need updating if label
synthesis lands — invariants 1–4 must survive the anchor change, and if one of them
cannot, that is the thing to argue about in review.

### Hazards

Built **only** with `CARGO_TARGET_DIR=<worktree>/target-scratch`; no bare
`cargo build --release` was run. `ls -la target/release/dtk` after the last build:
`-rwxr-xr-x 2 free free 8371016 Aug  8 22:32` — **mtime unchanged**, the deployed
dc3/rb3-xenon splitter was not replaced. dc3 was not built, split, or read;
`report.json` was not consulted. Nothing pushed, nothing merged, `main` untouched.
PROCESS NOTE / near-miss worth recording: I first appended this entry inside my
worktree and committed it. That was wrong and it failed silently. `git ls-files
docs/sessions/` is **empty** -- the whole session folder is untracked in the main
checkout (the scribe left commits to the integrator), so a fresh worktree of
`main` does not contain it, and `cat >>` created a NOTES.md holding only my own
entry. It looked like a successful append. I reset the branch to code-only and
appended here instead. Two consequences for anyone else working this campaign:
append to the main checkout's copy, not your worktree's; and do not commit the
session folder on a lane branch, or `git merge` will abort on an untracked-file
overwrite when the integrator lands it.

---

## 2026-08-12 — T2: Shape 2 root-caused. The tracker walks past `function_end`

Investigation only, branch `jeff-t2`, worktree `.worktrees/t2`. **No `src/`
change survives** — two temporary `eprintln!` probes were added to
`src/analysis/tracker.rs`, used to capture the values below, and reverted with
`git checkout -- src/analysis/tracker.rs`. `git status` in the worktree shows
`src/` untouched. Splitter built with
`CARGO_TARGET_DIR=.worktrees/t2/target-scratch`; `target/release/dtk` was never
written. dc3 was split into `.worktrees/t2/scratch/out` against a *private copy*
of `config/373307D9/{config.yml,symbols.txt,splits.txt}`, so dtk's symbols-file
rewrite never touched the project tree. Full writeup:
`findings/T2-rel14-rootcause.md`; census scripts in `findings/scripts/`.

**Producer: `src/analysis/tracker.rs:503`** (`Relocation::Rel14(target)` in the
`StepResult::Branch` / `BranchTarget::Address` arm; insert statement at `:496`),
in the **FIRST** tracker pass (`src/cmd/xex.rs:2618-2622`), not
`retrack_unanalyzed_functions`. Confirmed with the repo's own `JEFF_DUMP_RELOCS`
dump, which prints `RELOC 0x8256AAFC PpcRel14 -> Curl_resolv_unlock (+0x34)`
immediately after `tracker.apply`, before any repair pass.

Captured at the moment of insertion (hostip.obj `Curl_resolv_unlock`, site
`.text+0x53c` = fn+0x24 = VA `0x8256AAFC`):

```
T2 branch-reloc INSERT ins=0x8256AAFC op=Bc link=false
   target=Address(4:0x8256AB0C) is_fn_addr=false
   function_start=0x8256AAB8 function_end=0x8256AAD8
```

`0x8256AAB8`/`0x8256AAD8` are **`Curl_resolv_timeout`'s** bounds. The executor
ran off the end of the previous function and kept evaluating instructions
against stale bounds: the `b Curl_resolv` at `0x8256AAD0` seeds
`possible_missed_branches` with `ins_addr+4 = 0x8256AAD4` (`tracker.rs:443-446`),
that word is the 4-byte `0x00000000` alignment pad, and `StepResult::Illegal`
returns `ExecCbResult::Continue` (`tracker.rs:421-429`) instead of ending the
block — so the walk runs straight into `Curl_resolv_unlock`. Nothing bounds the
executor at `function_end`. The full 18-line walk trace is in the findings doc.

**NEGATIVE RESULT — the brief's hypothesised mechanism is ruled out.** The
`SectionAddress::new(SectionIndex::MAX, 0)` dummy path does insert
`Rel14(RelocationTarget::External)`, but such a record can never reach an
object: `apply_relocations` calls `kind_and_address()` (`tracker.rs:39-53`),
which returns `None` for `External`, and `continue`s (`tracker.rs:797-800`). The
emitted record has a resolved symbol and a `+0x34` addend, reachable only via
`RelocationTarget::Address` — and the capture shows `Address(4:0x8256AB0C)`.

**Second trigger on the same line, not anticipated by the brief.** When a
function's last declared instruction is a `bc`, the fall-through pseudo-branch
(`vm.rs:743-746`, target `ins_addr+4`) has `ins_addr+4 == function_end` and
fails the exclusive test at `tracker.rs:284`, so the site is relocated against
the *fall-through*, not the branch destination. Captured at
`buildcfg.obj+0x40`: record → `lbl_82D51A34` (val `0x44`) while the instruction
`0x4198FFE8` encodes `0x28`. Same at `buildssa.obj+0x158`. These records are not
coarse anchors, they name a different basic block.

**Census of every REL14 in both target trees** (`findings/scripts/`):

| tree | REL14 | same section | cross-section | site outside declared fn | intra-fn | cross-fn |
|---|---|---|---|---|---|---|
| dc3 `build/373307D9/obj` | 8 | 8 | 0 | 2 | 2 | 4 |
| rb3-xenon `build/45410914/obj` | 650 | 634 | 16 | 4 | 141 | 493 |

Two corrections to FINDING 3 above, both definitional:

- Its "REL14 intra-fn = 59" for rb3-xenon counts records whose *target symbol*
  is the enclosing function symbol. Counted by *where the branch actually
  goes*, intra-function REL14 is **141**, not 59 (dc3 stays 2). The extra 82
  anchor on an interior `lbl_*` and are the same defect.
- **182 of rb3-xenon's 634 same-section REL14 (and 4 of dc3's 8) have a
  relocation target that disagrees with the encoded branch destination.**

**Proposed rule R1 — emit REL14 only when the destination leaves the emitted
SECTION.** Keep/drop against the currently emitted records: **dc3 keep 0, drop
8; rb3-xenon keep 16, drop 634.** It is the correct containment but it is a
symptom fix; the bounds bug must be fixed too, because the same runaway walk
also emits `Rel24` (`tracker.rs:452-455`) and pollutes
`data_types`/`stores_to`/`hal_to`, which the section rule does not touch.

The brief's caution that "the six dc3 cross-function REL14 to `lbl_*`/`fn_*`
may be legitimate and must not be broken" does not survive measurement: all six
are **same-section**, two of them are the wrong-target fall-through defect, and
the other four are redundant within one section (the XEX displacement is copied
verbatim — `PpcRel14` has no arm in `write_coff`'s fixup match, `xex.rs:2139`).
Their "cross-function" status is itself a carving artifact:
`??$FindSetBitInArray@I@…` is declared `size:0x40` while its body continues
through `lbl_82D51A34`.

**New latent defect, flagged not proven.** `write_coff` documents the MSVC
convention `new_disp = (S + A) − section_start_VA` and implements it for
`PpcRel24` by rewriting the in-place to `−offset_in_section` (verified: hostip
`bl Curl_share_lock` at section offset `0x548` carries `0xFFFAB8` = `−0x548`).
`PpcRel14` never gets that rewrite, so its `A` stays as the original
`target − site` and the linker would add it on top of its own computation.
`xex.rs:2016-2040` exists because REL14 fixups have overflowed this linker
before (LNK2013), and the affected units are all in `link_order.txt`. Nobody has
relinked to observe it — worth a check independent of objdiff.
---

## 2026-08-12 — T6: the self-reference census, split into a defect count

Tool `tools/selfref_census.py`; full readout `findings/T6-selfref-census.md`.
Read-only pass: no re-split, no `cargo build`, nothing written to any build tree
or to `target/release/dtk`. Scratch (gitignored) in `scratch-t6/`.

### RESULT — 154 was not the defect count; 148 is. rb3-xenon's is 101, not 110

| game | arm | self-ref | fns | real loss | fns | legitimate fn+0 | fns | unclassified | witness disagreement |
|---|---|---|---|---|---|---|---|---|---|
| dc3 TARGET | obj | 350 | 154 | **332** | **148** | 18 | 6 | 0 | 0 |
| dc3 OURS | src | 6 | 3 | 0 | 0 | 6 | 3 | 0 | 0 |
| rb3-xenon TARGET | obj | 262 | 110 | **226** | **101** | 36 | 9 | 0 | 0 |
| rb3-xenon OURS | src | 20 | 10 | 0 | 0 | 20 | 10 | 0 | 0 |

All four upper-bound totals reproduce FINDING 3 exactly and are asserted by the
script (exit 1 on drift). Classes are disjoint per function (148+6=154,
101+9=110). Every compiler-produced self-reference on both games is legitimate.
Campaign sizing: 37 of the 148 dc3 real-loss functions and 21 of the 101
rb3-xenon ones also exist in our own object tree, i.e. that is the subset whose
score can move today.

### Discriminator: the ObjInfo addend, read out of the splitter's OWN asm

`split_write_obj_exe` (`xex.rs:2771`) builds `split_objs` once and hands the same
immutable slice to `write_coff` (`:2790-2813`) and `write_asm` (`:2920-2945`).
`write_asm` renders a relocation as `SYM+0xNNN@ha` (`asm.rs:357`) — literally
`tracker.rs:860`'s `(symbol_idx, target.address - symbol_address)`. So
`build/<id>/asm/**.s` **is** the pre-`write_coff` addend, from the run that wrote
`obj/**.obj`. No instrumented rebuild needed; Q7's runtime assert is answerable
for free from artifacts already on disk.

Cross-checked on every site against a second, independent witness: the asm byte
comment carries the ORIGINAL instruction word (write_coff zeroes the immediate
only in its output copy), so the materialised address is recomputable with no
reference to the anchor. **W1 and W2 agree on 612/612 target sites; 0
unclassified, 0 disagreements**, and every self-ref is a clean REFHI+REFLO pair
at the same addend (166+166 / 9+9 dc3; 113+113 / 18+18 rb3-xenon).
`?HandleEventResponse@SaveLoadManager@@QAAXPAVHamProfile@@H@Z` classifies
real_loss at delta 0x164; `?CharTerminate@@YAXXZ` classifies legitimate.

### NEGATIVE RESULT — instruction context is the worse discriminator

Computed alongside as an advisory tag. It is wrong on 9 of dc3's 350 sites:
324/332 real-loss carry `mtctr`+`bctr` within 8 insns, but the 8 that do not are
real losses anyway (`_fsopen+0xF8`, `_wfsopen+0xF8`, `_UnwindNestedFrames+0x64`
×2 — an interior block address passed in a register, no jump table), and 1 of 18
legitimate sites (`?SynthTerminate@@YAXXZ`, both games) has an unrelated
`mtctr`/`bctr` in window. Do not classify these by opcode neighbourhood.

### Two incidental findings the campaign should carry

1. **rb3-xenon target `.obj` are NOT pristine splitter output.** A post-SPLIT
   ninja step runs `scripts/obj_target_symbol_renamer.py --batch --apply`
   (`rb3-xenon/configure.py:680-700`), rewriting `fn_<addr>` symbols to MSVC
   mangled names in 1822 of 3085 objects, matching on symbol NAME `fn_%08X`, not
   address. Any rb3-xenon A/B must stage that step or the arms differ for a
   non-splitter reason.
2. **UNEXPLAINED: the rb3-xenon asm VA column is not a reliable function
   address.** `asm/xdk/xmic/xmicapi.s` prints `.fn fn_82C27048`'s first
   instruction at 0x82C26F98 — 0xB0 below what `config/45410914/symbols.txt`
   gives for that symbol — and the drift is not uniform across the unit. 106 of
   262 rb3-xenon sites needed the symbols.txt address; dc3 needed it on 0 of 350.
   Only W2 depended on it (using the asm column produced 8 spurious
   disagreements); no §RESULT number changes. Flagging rather than sitting on it.

Provenance caveats, both benign: dc3 `obj/system/rndobj/MetaMaterial.obj` carries
a bogus 2030-01-01 mtime (holds no self-ref site); 1822 rb3-xenon objects are 1s
newer than the newest `.s` because of the renamer in (1), not a second split. The
load-bearing evidence is content, not mtimes — all 612 sites matched their exact
instruction offset in the asm.

Not done here (out of scope, unchanged): the intra-function REL14 (Shape 2)
population, and any splitter change.

---

## 2026-08-12 — T1: parity account for the objdiff-cli rebuild. PASS, and it moves rb3

Findings of record: [`findings/T1-ruler-parity.md`](findings/T1-ruler-parity.md).
Artifacts: `decomp-bench/archive/runs/2026-08-12-objdiff-ruler-parity/`
(analysed files banked on decomp-bench branch `bench-t1-ruler-parity` `a351003a`
— the primary decomp-bench checkout was parked on a peer's branch, so the bank
went through a worktree off `main`; the 384 MB of reports and 45 MB of binaries
stay on disk at that path, gitignored). Code on jeff branch `jeff-t1` `ca7543f`.

Nothing in jeff was built. `target/release/dtk` untouched;
`objdiff/target/release/objdiff-cli` untouched (mtime still 05:56). All builds
went to private `CARGO_TARGET_DIR`s under `jeff/.worktrees/t1/`.

**Verdict: PASS.** 569 moved symbols across four projects, every one assigned to
a named commit, **zero unexplained, zero downward, zero symbol-set skew.**

### The A/B

Five binaries — `A_deployed`, and scratch builds of `cb238c8`, `745b7e3`,
`4c38c31`, `9138611` — × 4 projects, one `-o` path per arm (the report `.cache`
sidecar does not key on the binary; all 17 runs logged `cache: 0 hits`). Both
arms read the **same object trees**: nothing rebuilt, nothing re-split, so the
binary is the only variable. Hazard 5 does not bite — the before arm is a report
generated in-session by the deployed binary, not a remembered `report.json`.

| project | ruler | moved | 4c38c31 | f2424d6 | fb80730 | unexplained | downward |
|---|---|---|---|---|---|---|---|
| dc3-decomp | name_check | 173 | 37 | 137 | 0 | 0 | 0 |
| rb3-xenon | name_check | 164 | 21 | 144 | 0 | 0 | 0 |
| rb3 (Wii/mwcc) | name_check | 232 | **0** | 232 | 0 | 0 | 0 |
| cea-decomp | name_only | **0** | 0 | 0 | 0 | 0 | 0 |

`matched_code_percent`: dc3 42.702670 → 43.098682 (+0.396012), rb3-xenon
32.506813 → 32.613857 (+0.107044), rb3 63.091927 → 63.141228 (+0.049301). These
reproduce `4c38c31`'s and `f2424d6`'s own commit-message deltas **to six decimal
places**, from a different absolute baseline (the author measured dc3 at
41.731250; our tree gives 42.702670). 39 functions reach `fuzzy = 100`
(28 dc3, 10 xenon, 1 rb3).

### Four things worth having in this log

1. **The deployed binary's identity is now measured, not inferred from mtime.**
   `A_deployed` and a scratch build of `cb238c8` produce **byte-identical
   (sha256) reports on dc3, rb3-xenon and rb3** — 7,185 units. The validator's
   "built seven minutes before the fix" reading is confirmed by behaviour.
2. **There is a THIRD functional commit, and it is the largest of the three.**
   `fb80730` "Port preferredStringEncoding from upstream" (15 files, +329/-90,
   touching `arch/mod.rs` and `diff/code.rs`) sits between the two NameCheck
   commits. Measured inert: `C_745b7e3` reports are sha256-identical to
   `B_cb238c8` on all four projects. Inert *here* — a project that sets the
   property (tww) is not covered by this account.
3. **`f2424d6`, not the Shape-1 fix, is the majority of the movement** — 137/173
   on dc3, 144/164 on xenon, 232/232 on rb3. The brief's expected explanation
   set ("Shape-1 rows move and nothing else moves") would have failed.
4. **rb3 (Wii/mwcceppc/ELF) IS moved by this deploy, by 232 symbols.** README
   §1.3's correction and FINDING 4 are right that the *addend* defect cannot
   reach rb3 — and rb3's `4c38c31` delta is byte-identically zero, which proves
   it. But `~/.local/bin/objdiff-cli` is one global symlink, and `f2424d6`
   (a dtk *coverage* hole, not an addend hole) moves rb3 too. rb3 was outside
   the brief's scope; it is inside the deploy's.

`cea-decomp` is the negative control that makes the gating claim testable: same
target family (X360 MSVC PPC, dtk-split), but `functionRelocDiffs: name_only`.
Its two 3,675-unit reports are **sha256-identical**. Neither tolerance leaks
outside NameCheck.

### Causal, not just temporal

Bisection assigns a symbol to a commit boundary; it does not prove the
mechanism. So all 337 moved dc3+xenon symbols were re-diffed under both binaries
and the charged rows enumerated (674 invocations, `work/sample_rows.py`):
**178 rows removed, 0 added.**

- `4c38c31` class, 124 rows: **100% `lis`/`addi`, perfectly paired 62/62**,
  target operand the literal `0x0` in 124/124, base a nonzero interior offset in
  124/124 — `lis r12, 0x0` vs `lis r12, 0x4c`. Exactly README §1.1 Shape 1.
- `f2424d6` class, 54 rows: **0/54** have that shape. Every one is a bare
  target-side constant against a named base symbol, over 8 opcodes —
  `lwz r3, 0x1d80, r10` vs `lwz r3, ?kAssertStr@@3PBDB, r10`.

The classes are disjoint in shape as well as in commit. Second direction check:
the CLI's own `Diff Score` improved on 293 of the 337 and **worsened on 0**.

The brief's spot-check reproduces: `HandleEventResponse` charges 2 rows
(score 10/21100) under the deployed binary and **0 rows (0/21100)** under HEAD.

### Two cautions for whoever deploys

- **16 functions cross `match_percent_normalized` into exactly 100.0** (6 dc3,
  3 xenon, 7 rb3). `normalized == 100` is the selection predicate for the
  gap-bug-hunt lane, so that lane's population changes. It is **not**
  byte-exactness (task #150) and these are not cracks. One of them, rb3
  `TourDesc::Configure`, is the function `f2424d6` explicitly says stays
  charged — and it does: `fuzzy` 99.91084 → 99.93976, still short of 100. Only
  the presentation metric rounds up.
- Every `report.json` consumer is holding a number from the old ruler.
  Regenerate as part of the deploy; do not diff across the boundary.

### Side finding (pre-existing, not caused by the deploy)

**`objdiff-cli diff --format proto` ignores the project-level
`functionRelocDiffs`.** `objdiff-cli/src/cmd/diff.rs:849` passes
`project_config` as `None` on the `run_oneshot` path only (`run_json` :934 and
`run_interactive` :3057 both pass it), and the base config is
`FunctionRelocDiffs::DataValue` (:879). Measured, not read: same binary, same
symbol, proto output with and without an explicit
`-c functionRelocDiffs=name_check` differ (1,920,687 vs 1,904,440 bytes). Any
consumer scoring through proto is on a different ruler than `report.json`.

Not done here (out of scope, unchanged): Shape 2, any splitter change, and the
actual deploy — this is the license, not the act.

---

## 2026-08-13 — T4: Shape 2 fixed at the writer. dc3 8 REL14 -> 0, rb3-xenon 643 -> 17, nothing else moves

Branch `jeff-t4` (off `jeff-t3`), worktree `.worktrees/t4`, commit `f830e16`.
Full writeup: [`findings/T4-shape2-fix.md`](findings/T4-shape2-fix.md); the A/B
tool is `findings/scripts/t4_obj_ab_diff.py`.

Hazards: every build used `CARGO_TARGET_DIR=<worktree>/target-scratch`.
`target/release/dtk` is still **`2026-08-08 22:32:10`, 8371016 bytes** — the
deployed splitter was never written. Both games were split into scratch dirs
against private config copies; project trees read-only. Nothing pushed or merged.

### What shipped — T2's rule R1, at the WRITER, and `tracker.rs` untouched

`write_coff` drops a `PpcRel14` record whose destination lands in the same
**emitted** section as the branch site, and keeps it otherwise. "Same emitted
section" is same `ObjInfo` section **and** same COMDAT region, because
`write_coff` extracts COMDAT regions into their own COFF sections.

`src/analysis/tracker.rs` is unchanged, deliberately, and this is the load-bearing
finding of the task:

**The COMDAT keep-back pass (`xex.rs:2012`) reads these very REL14 records to
force both ends of every REL14 to stay in the contiguous parent `.text` — and it
fires 7 times on one dc3 split** (`RUST_LOG=dtk::util::xex=debug`, its own
"Keeping REL14-involved function in main .text" line). That pass is what *makes*
"same emitted section" true at the drop point. Removing the record upstream in
the tracker — before the split has happened, where "emitted section" is not even
knowable — stops the keep-back pass seeing it, re-enables COMDAT extraction, and
can separate an intra-section branch from its target with no relocation left to
fix it.

Measured, not argued: a mis-patched control binary (see the second confound
below) disabled exactly that pass and nothing else. rb3-xenon moved **185
objects** by `SECTION_LAYOUT|SYMBOL_TABLE`, and REL14 records started appearing
at COMDAT-relative offsets (`xdk/xgraphics/import.obj` at `0x4/0x1c/0x28`
instead of `0x6b8/0x6d0/0x6dc`). That is the blast radius of a tracker-side drop
landing without reworking the keep rule. **Follow-up task for the integrator:**
derive the keep-back rule from the conditional-branch instructions in each
candidate COMDAT region instead of from the relocation records, then land T2's
`tracker.rs:503` fix — which is still worth doing for the `Rel24` /
`data_types` / `stores_to` pollution R1 does not touch. It needs its own parity
account.

### Tests

Baseline `jeff-t3` `50aa582`: **160 passed, 2 failed**. After `f830e16`:
**163 passed, 1 failed**. T3's
`shape2_intra_function_conditional_branch_emits_no_relocation` flips RED -> GREEN;
the remaining red is T3's DS-form XO test, left out of scope on purpose. The +2
are negative controls added to `xex.rs`'s own `mod tests` (I did not edit T3's
file): a REL14 to a symbol not defined in this object survives, and so does one
whose target sits in a COMDAT region while the site stays in the parent `.text`.
The second is discriminating — with the region half of the predicate replaced by
`true`, it fails `left: 0, right: 1`. Together they are what a blanket "never
emit REL14" cannot pass. (`cargo test --lib` still does not exist here; the
command is `cargo test --bin dtk`, as T3 recorded.)

### Object-level parity, per-object and classified by WHAT differs

| game | objects | identical | differ | only difference | reloc delta |
|---|---|---|---|---|---|
| dc3 | 2223 | 2218 | **5** | `RELOC_REMOVED_REL14` in all 5 | **-8 REL14** |
| rb3-xenon | 3085 | 2902 | **183** | `RELOC_REMOVED_REL14` in all 183 | **-626 REL14** |

Zero section-layout, section-data and symbol-table changes on either game.
Determinism control on dc3 (same binary, two runs): **2223/2223 byte-identical**.

| tree | REL14 | intra_fn | same_section | cross_section |
|---|---|---|---|---|
| dc3 baseline split | 8 | **2** | 8 | 0 |
| dc3 fixed split | **0** | **0** | 0 | 0 |
| rb3-xenon baseline split (converged input) | 643 | **53** | 627 | 16 |
| rb3-xenon fixed split | **17** | **0** | 1 | 16 |

**Intra-function REL14: dc3 2 -> 0, rb3-xenon 53 -> 0.** The bar quoted 59 for
rb3-xenon; 59 is the count on the *build tree*, which is not pristine splitter
output — `obj_target_symbol_renamer.py` rewrites 1822 of 3085 objects (T6
finding 1) and `intra_fn` is a name comparison. Total REL14 is 650 on both the
build tree and my run-1 baseline, so the 53/59 gap is the classifier, not the
splitter.

Cross-function: dc3 4 -> 0 and rb3-xenon's same-section 627 -> 1, all
adjudicated by T2 §5 (same-section, redundant inside one section, malformed for
the linker, and 2 of dc3's 6 name a *different basic block* than the instruction
branches to). **The 16 load-bearing records are verified as a SET, not a count:**
keyed on (object, offset, instruction word, target symbol) the cross-section
REL14 set is identical between arms — 0 dropped, 0 added. All 16 target a symbol
undefined in the emitting object, i.e. a `bc` into another split unit. The 17th
survivor is the COMDAT-boundary case, captured at the decision point:
`xdk/d3dx9/d3dxmath.obj .text+0xa4`, `site_region=None dest_region=Some(88)`.

### Two confounds that produced a FALSE parity account before they were removed

1. **`dtk xex split` rewrites the symbols file you hand it.** My private
   `cfg-rb3x/symbols.txt` was rewritten 24 s into the first rb3-xenon split
   (mtime 23:47:50, 15 lines shorter) and never again — so run 1 and run 2 had
   different inputs, and baseline-run-1 vs fixed-run-2 reported **15 objects
   with `SECTION_LAYOUT|SYMBOL_TABLE` differences that the fix did not cause**.
   Re-running the baseline on the converged file removed all 15. dc3 is not
   affected (its symbols file was not rewritten). **Any future splitter A/B must
   put both arms on a symbols file that has already been through one split, or
   give each arm a pristine copy and the same number of runs.**
2. **A "neutralised" control binary that was not neutral.** The patch string
   `            if matches!(reloc.kind, ObjRelocKind::PpcRel14) {` occurs
   **twice at the same indentation** — `xex.rs:2021` (the COMDAT keep-back pass)
   and `:2426` (the new filter) — so a first-occurrence replace disabled the
   keep-back pass instead. Caught because the "baseline-behaviour" arm produced
   582 REL14 with `intra_fn=0`, which no baseline does. It became the §4
   measurement above. Verify a control by its *output signature*, not by the fact
   that the patch applied.

### Left out of scope on purpose (each is a separate, separately-accountable task)

- REFHI/REFLO anchor selection (Shape 1) — untouched. I do **not** think anchor
  synthesis is warranted now: T1 shows objdiff HEAD clears 22 of 23 rows and T6
  shows every compiler-produced self-reference is legitimate, so what remains is
  splitter readability, not a defect.
- The DS-form XO-bit corruption (FINDING 8 / T3 test 2). One line — mask
  `[15:2]` when the primary opcode is 58/62 — but it rewrites in-place
  instruction bytes at 74 dc3 + 51 rb3-xenon sites, a second independent movement
  of the ruler.
- A real `PpcRel14` arm in the section-data fixup for the 16 survivors (T2's
  `-offset_in_section` convention). Still unimplemented, still worth a link-level
  check independent of objdiff.

---

## 2026-08-13 — T5: FINDING 8 is NOT latent. It fired on dc3 retail, and the grep that said otherwise was broken

Branch `jeff-t5` (off `jeff-t4`), worktree `.worktrees/t5`, commit `b204ebd`.
Full writeup: [`findings/T5-dsform-hardening.md`](findings/T5-dsform-hardening.md).

Hazards: every build used `CARGO_TARGET_DIR=<worktree>/target-scratch`.
`target/release/dtk` is still **`2026-08-08 22:32:10`, 8371016 bytes** — untouched.
Both games split into scratch dirs against private config copies; project trees
read-only; `objdiff-cli` not rebuilt. Nothing pushed or merged.

### CORRECTION to FINDING 8 — the "0 lwa across the whole dc3 disassembly" is a false negative

`grep -rE '^\s+lwa\s' build/373307D9/asm/` cannot match a dtk asm file: the
mnemonic follows the byte comment (`/* VA OFF  BB BB BB BB */\tstd r31, …`), so
no line starts with whitespace-then-mnemonic. The same pattern returns **0 for
`lwz` and 0 for `stw`** on dc3, which is the tell. Corrected pattern anchors on
the comment close (`'\*/[[:space:]]+<mnem>[[:space:]]'`). This is worth carrying
beyond T5: the asm tree is this campaign's pre-`write_coff` witness (T6), so a
grep of this shape silently answers "the writer never fired" for any question of
this shape.

Corrected whole-tree census:

| tree | files | ld | ldu | lwa | std | stdu | corruptible |
|---|---|---|---|---|---|---|---|
| dc3 `build/373307D9/asm` | 33,031 | 27,713 | 137 | 433 | 31,369 | 209 | **779** |
| rb3-xenon `build/45410914/asm` | 3,085 | 21,128 | 51 | 377 | 24,374 | 81 | **509** |

Restricted to REFHI/REFLO sites (`sym@l` / `sym@ha` operand) — the only ones the
arm touches:

| tree | ld | lwa | std | total | XO != 0 |
|---|---|---|---|---|---|
| dc3 | 21 | **1** | 52 | **74** | **1** |
| rb3-xenon | 15 | 0 | 36 | **51** | **0** |

74 and 51 reproduce FINDING 8's census exactly, so this is the same population
counted correctly. FINDING 8's "all currently XO=0" was measured on the
**emitted objects** — it was measuring the corruption itself.

**rb3-xenon is clean** (the brief's open question): 0 corrupted sites.

### The one live corruption, and it charges

`system/gesture/ArcDetector.s:2704`, VA `0x82E025AC`, in
`?UpdateOverlay@ArcDetector@@QAAMPAVRndOverlay@@M@Z`:
`/* E9 6B 46 EE */ lwa r11, lbl_82F446EE@l(r11)`, part of an `int`→`double`
`lwa`/`std`/`lfd`/`fcfid` sequence — code, not misdisassembled data. The emitted
object carries `0xE96B0000` (`ld`) at COMDAT `/53` `+0x824`. Our own compiler
object has three DS-form REFLO sites and **all three are `lwa`, XO=2, immediate
0** — the compiler's convention is exactly what the fix now emits.

objdiff-cli (deployed binary, `name_check`), `UpdateOverlay` row **574**:

| arm | target | base | match_type |
|---|---|---|---|
| before | `ld r11, lbl_82F446EE, r11` | `lwa r11, sDefaultHoverTimer, r11` | **replace** |
| after | `lwa r11, lbl_82F446EE, r11` | `lwa r11, sDefaultHoverTimer, r11` | **equal** |

fuzzy 71.83148 → 71.83334, diff_score 15211 → 15210. The before number
reproduces the real project run to five decimals. The move is tiny; the point is
that **no source could ever have won that row** — the ruler was demanding an
instruction the retail game does not contain.

### The fix

`write_coff`'s `PpcAddr16Ha | PpcAddr16Lo` arm: `insn & 0xFFFF0000` becomes a
mask chosen by primary opcode — `0xFFFF0003` for 58 (`ld`/`ldu`/`lwa`) and 62
(`std`/`stdu`), `0xFFFF0000` otherwise. DQ-form `lq`/`stq` and DS-form
`lfdp`/`stfdp` are not implemented by Xenon, so 58/62 is the complete set.

Tests: `jeff-t4` `f830e16` was **163 passed / 1 failed**; `b204ebd` is
**164 passed / 0 failed**. The cleared failure is T3's
`ds_form_immediate_zeroing_must_preserve_xo_bits`; T4's two negative controls
stay green. (`cargo test --bin dtk`; `--lib` still does not exist here.)

### Object-level parity (T4's `t4_obj_ab_diff.py`)

| game | objects | identical | differ | only difference | reloc delta |
|---|---|---|---|---|---|
| dc3 | 2223 | 2222 | **1** (`system/gesture/ArcDetector.obj`) | `SECTION_DATA` | **{} empty** |
| rb3-xenon | 3085 | **3085** | **0** | — | **{} empty** |

Zero section-layout and zero symbol-table changes on either game. Determinism
control on dc3 (same fixed binary, two runs, separate configs and output dirs):
**2223/2223 byte-identical**, so the 1-object delta is causal. rb3-xenon's
inertness was predicted from the census before the run and then measured; both
its arms got a pristine `symbols.txt` copy and one run each (T4 confound 1) and
converged to the same hash.

Every changed byte in the one moved object: `file+0x3d6b` `0x00`→`0x02` (the
instruction, `ld`→`lwa`) and `file+0x7a50..0x7a53`, which is symbol-table entry
#122's **aux section-definition `CheckSum`** for COMDAT `/53` — derived from the
section data, not an independent change. Five bytes, one of them semantic.
Because exactly one object moved, the project-wide score account is closed by
construction; no `report.json` was regenerated (hazard 5).

### NEW DEFECT found in passing — flagged, not fixed. The DS-form target ADDRESS is decoded wrong too

The splitter names that relocation's target `lbl_82F446EE`. The DS-form EA is
`hi<<16 | (lo & ~3)` = `0x82F4_0000 + 0x46EC` = **`0x82F446EC`**. The analysis
side read the full low 16 bits as displacement — the same [15:0]-vs-[15:2]
mistake `write_coff` made, one layer up. It is baked into dc3's checked-in
config:

```
symbols.txt:198199: sDefaultHoverTimer = .data:0x82F446EC; // size:0x2
symbols.txt:198200: lbl_82F446EE       = .data:0x82F446EE; // size:0xA
```

`sDefaultHoverTimer` is `static int … = 600` (4 bytes) recorded as `size:0x2`
and split two bytes in by a `lbl_` that should not exist. Our compiler object
anchors the site on `sDefaultHoverTimer`; the splitter anchors two bytes past it.
`tracker.rs`/`cfa.rs` side, out of T5's scope.

**Open question the integrator must weigh, stated as a question.** If MSVC's
REFLO is *additive* (what `xex.rs:2124-2129` asserts about COFF relocations
generally), the two defects were **compensating** at this site: `0x0000 +
lo(0x82F446EE) = 0x46EE` relinks to the correct `lwa`, while after the fix
`0x0002 + lo(0x82F446EE) = 0x46F0` relinks to `ld` at the wrong displacement. If
REFLO *replaces* the field, the fix is link-neutral. **Nobody has relinked** —
T2 left the equivalent `PpcRel14` `-offset_in_section` question open on the same
grounds. One task should fix the address decode and then relink once, checking
LNK2013/LNK1223 and the resulting words for both. Until then: the fix is
**measured correct against the ruler** (which is what moves every score) and
**unproven against the linker** (which nothing in the pipeline exercises today).

Not done here, on purpose: `src/analysis/` untouched; nothing added to
`src/util/mod.rs` or T3's `xex_reloc_tests.rs`; no `report.json`, no
`objdiff-cli` rebuild, no in-place re-split of either project tree.

---

## 2026-08-13 — T7: the parity account. T4 is licensed; T5 is not, and the relink is why

Branch `jeff-t7` (off `jeff-t5`), worktree `.worktrees/t7`, commit `3bf1c0c`
(one new file, `scripts/coff_reloc_parity.py` — no `src/` change). Full writeup:
[`findings/T7-splitter-parity.md`](findings/T7-splitter-parity.md). Artifacts:
`decomp-bench/archive/runs/2026-08-13-splitter-parity-t7/` (analysed files
committed on decomp-bench branch `bench-t7-splitter-parity` `c803d894` through a
worktree off `main`, because the primary bench checkout is parked on a peer's
branch; the 58 MB of objdiff reports and 39 MB of linker maps stay on disk there,
gitignored).

Hazards: every build used `CARGO_TARGET_DIR=<worktree>/target-scratch`.
`target/release/dtk` is still **`2026-08-08 22:32`, 8371016 bytes** and
`objdiff/target/release/objdiff-cli` still **`2026-08-12 05:56`** — neither
deploy path was written. Both games split into scratch dirs; both project trees
read-only; no `report.json` read or regenerated; nothing pushed or merged.

### The harness self-check FIRED — quoted, not assumed

`--old <candidate> --new <deployed>`, deliberately: `--verify-against` only
checks the `--new` side, and the candidate is *supposed* to differ from the live
objects. So the check asks the falsifiable question instead.

```
[split-ab] verify vs .../dc3-decomp/build/373307D9/obj: identical 2223, different 0, missing 0
[split-ab] verify vs .../rb3-xenon/build/45410914/obj: identical 3085, different 0, missing 0
[split-ab] staging is faithful: the new side reproduces the project byte-for-byte.
```

Both projects' `rule split` was replayed (dc3: prune; rb3-xenon: JEFF_MERGE_PROTECT
+ prune + `obj_target_symbol_renamer.py`). This doubles as the control — the
BEFORE arm reproduces an independently produced tree exactly — and it retires the
"is the dc3 target tree stale?" question for the target half.

### Object and record parity

| game | objects | differ | only difference | reloc delta |
|---|---|---|---|---|
| dc3 | 2223 | **6** | 5 × `RELOC_REMOVED_REL14`, 1 × `SECTION_DATA` (ArcDetector, 1 byte) | **−8 REL14** |
| rb3-xenon | 3085 | **188** | `RELOC_REMOVED_REL14` in all 188 | **−633 REL14**, 0 added, 0 data bytes |

All 6 dc3 objects are enumerated record-by-record in the findings doc; the 188
are in `work/rb3x-changed-objects.txt`. Zero section-layout and zero symbol-table
changes on either game.

**T4's 183/−626 becomes 188/−633 here, and the difference is T4's baseline, not
the fix.** T4's baseline arm ran on an already-converged symbols file (its
confound 1), which suppressed 7 records in 5 objects; this run gives each arm a
pristine copy and one run each, so the BEFORE arm reproduces the project's live
650 REL14 exactly.

Record shape, over six trees (both arms × both games + both compiler trees):
`PAIR == REFHI + REFLO` in all six, **every** PAIR at its partner's offset with
displacement 0, **zero** shape violations, D-form in-place immediate 0 at
1,157,700 of 1,157,700 sites. **This also corrects FINDING 2**: its "in-place
immediate nonzero in 3 of 342,386" compiler sites are not stray addends, they are
the three DS-form XO bits (`e96b0002` etc.). The compiler's *displacement* is
zero everywhere, which is exactly what the candidate now emits.

Intra-function REL14 needs three witnesses, because they disagree on the
survivors: target-symbol-is-enclosing-fn → dc3 2→**0**, xenon 59→**0**;
target-defined-in-this-object → 8→**0**, 634→**1** (the COMDAT-boundary keep);
encoded-destination → 6→0, 95→10, and those 10 are an artifact — all 17 xenon
survivors target a symbol undefined in their own object, so their encoded
displacement is a stale pre-split value the linker overwrites.

### objdiff A/B, ONE ruler (the deployed 05:56 binary; T1 has landed nothing)

Four shadow projects of symlinks — same base objects, same `icf_aliases.map`,
target tree the only variable; one `-o` per arm, all four runs `cache: 0 hits`.

| project | symbols | skew | moved | up | down |
|---|---|---|---|---|---|
| dc3 | 48,344 | 0 | **2** | 2 | 0 |
| rb3-xenon | 69,231 | 0 | **23** | 21 | **2** |

`matched_code` +156 (dc3, = `Curl_resolv_unlock` entire) and +1,840 (xenon, = the
15 functions that reach fuzzy 100). **No function crosses
`match_percent_normalized` into 100 on either game**, so this deploy does not
move the `normalized == 100` population the way T1's ruler deploy does.

The two downward rows are real and are disclosed rather than buried: `HttpGet
?GetNextLine…` 1.875 → 0.0 and `ProfileMgr fn_82545AFC` 0.714 → 0.0, both in
`match_percent_normalized` only, both **raw 0.0 % in both arms** (0 matched bytes
either way). `fn_82545AFC` is mechanically explained: objdiff's
`funclet_signature` (`objdiff-core/src/diff/mod.rs:840-867`) **zeroes the 4-byte
word at every relocation address**, so the spurious REL14 masked its two `beq`
words, a byte-signature pairing formed with an unrelated base funclet, and the
report row carried objdiff's own `masked_equal: true` disclosure. Remove the
invented relocation and the invented pairing goes with it. For `?GetNextLine…` I
could not reproduce the row accounting through `objdiff-cli diff` (it reports
0.0/0.0 in BOTH arms even with `-c functionRelocDiffs=name_check` — the oneshot
path is a different ruler configuration, T1's side finding); causality is still
pinned (only REL14 records changed in that object, and the move reproduces on a
2-unit shadow project), the row-level mechanism is stated as class, not claimed
as measured.

### THE RELINK — new, and it cuts both ways

dc3's own `rule msvc_link` links **1,256 split target objects**; both arms were
linked with the project's `X360/16.00.11886.00/link.exe` under `wibo`, from
shadow trees, writing only to scratch.

- Stock link line: both arms exit 96 with **byte-identical diagnostics** (15,063
  LNK lines). The failure is pre-existing (`LNK1120: 51 unresolved externals`
  from our *source* objects). **No LNK2013, no LNK1223 in either arm.**
- With `/FORCE:UNRESOLVED` (+ the two changed objects the real link line does not
  carry): both arms **link, exit 0**, same 26,654,208-byte image, identical
  diagnostics, `.map` identical but for timestamp/path/debug-size.

The two images differ in **28 bytes**: 2 header (timestamp), 12 `.rdata` (my own
`…before.pdb`/`…after.pdb` string), and 14 in `.text` = 8 instruction words.

**Seven of those eight are the case for landing T4, and it is stronger than the
objdiff account.** At each, the AFTER word equals the word in the split object —
which is the retail encoding, since `write_coff` never rewrites a `PpcRel14`
in-place — and the BEFORE word does not: the linker consumed the spurious record
and rewrote the branch. `419a0528` vs retail `419a0010` (hostip), `42404e08` vs
`42400234` (nuiruntime), `41980144` vs `4198ffe8` (buildssa), and so on. T2
flagged this as a risk and left it unmeasured; it is measured now, and it fires
at 7 of dc3's 8 REL14 sites. The 8th (qprocessing `.text+0x94`, target = its own
enclosing function) is identical in both images — the linker's recomputation
coincided with the encoded displacement. The symbol is in both maps, so it is a
coincidence at a linked site, not an unlinked one.

**The eighth word answers T5's open question, and the answer is against T5 as
landed. MSVC's REFLO is ADDITIVE.** At `ArcDetector ?UpdateOverlay`, the linked
low half moves by exactly T5's in-place byte: `e96b5566` → `e96b5568`. So BEFORE
= wrong object (`ld`) that links to the retail `lwa` because the DS-form zeroing
and the 2-byte-off address decode cancel; AFTER = right object (`lwa`) that links
to `ld` at displacement+2. The root cause is the decode T5 found and flagged:
`lbl_82F446EE` should be `sDefaultHoverTimer` at `0x82F446EC`. (Scope: that
object is not in dc3's real link line — I injected it — so nothing in the
shipped pipeline breaks either way.)

### Recommendation to the integrator

1. **Land T4** (`f830e16`). Licensed on every leg above, and it fixes a real
   corruption of the linked image at 7 dc3 sites.
2. **Hold T5** (`b204ebd`) until the analysis-side DS-form address decode is
   fixed, then relink and re-check that one word (`link/` in the run dir has the
   harness). Landing it alone trades +0.00185 fuzzy on one function for a linked
   instruction that is wrong.
3. **Version bump 1.11.0 → 1.12.0** (repo convention, `287a322`), and regenerate
   every consumer's `report.json` after the deploy — do not diff across it.
4. **Deploy the splitter and T1's ruler in separate steps**, each with its own
   parity account, or neither account is readable.
5. **cea-decomp is in the blast radius and was not measured** (also X360,
   dtk-split). Measure it or accept it explicitly before the deploy.
