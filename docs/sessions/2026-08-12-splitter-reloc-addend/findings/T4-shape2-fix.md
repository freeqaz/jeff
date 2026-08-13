# T4 — Shape 2 fixed: a REL14 is emitted only when the branch leaves the emitted section

Branch `jeff-t4` (off `jeff-t3`), worktree `.worktrees/t4`, commit `f830e16`.
Everything below was measured on this box, 2026-08-12/13, against jeff `main` =
`8a42efb` + T3's tests.

Deploy hazards, first: every build used
`CARGO_TARGET_DIR=/home/free/code/milohax/jeff/.worktrees/t4/target-scratch`.
`target/release/dtk` is **still `2026-08-08 22:32:10`, 8371016 bytes** — the
splitter dc3 and rb3-xenon actually run was never written. dc3 and rb3-xenon
were split into scratch dirs under the worktree against **private copies** of
`config/<id>/{config.yml,symbols.txt,splits.txt}`; the project trees were only
read. Nothing merged, nothing pushed, `main` untouched.

---

## 1. What shipped

`src/util/xex.rs`, in `write_coff`'s relocation-record loop: a `PpcRel14` record
is dropped when its destination lands in the **same emitted section** as the
branch site, and kept otherwise. "Same emitted section" is computed exactly —
same `ObjInfo` section *and* the same COMDAT region (`None` = stays in the
parent section), because `write_coff` extracts COMDAT regions into their own
COFF sections a few hundred lines earlier.

This is T2's rule R1. The justification is the one T2 measured: the MSVC
compiler emits **zero** REL14 across 2,193 compiler-produced objects in dc3 and
rb3-xenon, and within one emitted section the split copies the XEX bytes
verbatim, so the encoded 14-bit displacement is already correct. The record is
not merely redundant, it is wrong twice: PPC-COFF puts no addend on the record,
so objdiff resolves the operand to `symbol+0` and renders a control-flow
difference that does not exist (G36 `Curl_resolv_unlock`: `beq cr6, 0x518` vs
`beq cr6, 0x34`); and `write_coff` has no `PpcRel14` arm in its section-data
fixup, so the in-place displacement is never rewritten to the MSVC
`-offset_in_section` convention and a linker would add it on top of its own
computation.

`src/analysis/tracker.rs` is **unchanged**. §4 is the argument for why, with the
measurement that decided it.

Two negative controls were added to `xex.rs`'s own `mod tests` (T3 owns
`xex_reloc_tests.rs`; I did not edit it):

- `test_rel14_to_external_symbol_is_kept` — a REL14 whose target is not defined
  in this object survives.
- `test_rel14_across_a_comdat_boundary_is_kept` — so does one whose target sits
  inside a COMDAT region the writer extracts while the branch site stays in the
  parent `.text`.

Both are discriminating, not decorative: with the region half of the predicate
replaced by `true` (i.e. the naive "same `ObjInfo` section" rule), the COMDAT
one fails `left: 0, right: 1`. Together they are what a blanket "never emit
REL14" — which also passes T3's test 1 — cannot satisfy.

## 2. Tests

| arm | result |
|---|---|
| baseline (`jeff-t3`, `50aa582`) | **160 passed, 2 failed** |
| after the fix (`f830e16`) | **163 passed, 1 failed** |

`shape2_intra_function_conditional_branch_emits_no_relocation` flips RED → GREEN.
The one remaining red is T3's `ds_form_immediate_zeroing_must_preserve_xo_bits`,
deliberately left out of scope (§5). +2 green are the negative controls above.

**The brief's command does not exist here.** `cargo test --lib xex_reloc` errors
`no library targets found in package decomp-toolkit` — `Cargo.toml` declares only
`[[bin]] dtk`. T3 already recorded this. The working command is:

```
CARGO_TARGET_DIR=<worktree>/target-scratch cargo test --bin dtk xex_reloc
```

## 3. The object-level parity account

Both games split with the baseline binary and with the fixed binary, into
scratch dirs, and every `.obj` compared field by field —
`findings/scripts/t4_obj_ab_diff.py` classifies each differing object by *what*
differs (section list/sizes/flags, section raw data, symbol table, relocation
records) rather than tallying bytes.

### dc3 — clean, causal, and complete

| | value |
|---|---|
| objects | 2223 base / 2223 fix, no adds or removals |
| identical | **2218** |
| differ | **5**, and the only difference in all 5 is `RELOC_REMOVED_REL14` |
| relocation delta | **−8 REL14**, nothing else added or removed |
| section layout / section data / symbol tables | **unchanged in every object** |

REL14 census (`findings/scripts/rel14_census.py`):

| tree | REL14 | intra_fn | same_section | cross_section |
|---|---|---|---|---|
| dc3 build tree `build/373307D9/obj` (reference) | 8 | 2 | 8 | 0 |
| my baseline split | 8 | **2** | 8 | 0 |
| my fixed split | **0** | **0** | 0 | 0 |

**Intra-function REL14: 2 → 0.** Cross-function: 4 → 0, plus the 2
site-outside-declared-function rows → 0. All 8 were same-section, so R1 drops
all 8, and that is the intended outcome, not collateral: T2 §5 adjudicated these
six row by row (two are the fall-through-anchored records whose relocation names
a *different basic block* than the instruction branches to; the other four point
at the right address but are redundant inside one section and malformed for the
linker). dc3 keeps zero REL14, which is exactly what the compiler does.

Determinism control, same binary, two runs into different output dirs:
**2223 / 2223 byte-identical.** So the 5-object delta is causal.

### rb3-xenon — clean, after two confounds were removed

| | value |
|---|---|
| objects | 3085 / 3085 |
| identical | **2902** |
| differ | **183**, and the only difference in all 183 is `RELOC_REMOVED_REL14` |
| relocation delta | **−626 REL14**, nothing else |
| section layout / section data / symbol tables | **unchanged in every object** |

| tree | REL14 | intra_fn | same_section | cross_section |
|---|---|---|---|---|
| rb3-xenon build tree `build/45410914/obj` (reference) | 650 | 59 | 634 | 16 |
| my baseline split (converged input) | 643 | **53** | 627 | 16 |
| my fixed split | **17** | **0** | 1 | 16 |

**Intra-function REL14: 53 → 0.** The bar quoted 59; 59 is the count on the
build tree, which is **not pristine splitter output** — a post-split ninja step
runs `scripts/obj_target_symbol_renamer.py` over 1822 of 3085 objects (T6
finding 1), and the census's `intra_fn` predicate compares the relocation target
name against the enclosing symbol name, so renaming moves the count. The
splitter-output number is 53 and it goes to 0. Total REL14 is 650 on both the
build tree and my run-1 baseline, so this is a classifier difference, not a
splitter difference.

**The 16 load-bearing records are untouched, verified as a set, not a count.**
Keyed on (object, offset, instruction word, target symbol), the cross-section
REL14 set is **identical** between arms: 0 dropped, 0 added. All 16 target a
symbol not defined in the emitting object, i.e. a `bc` into another split unit,
which genuinely has no valid encoded displacement after the split.

**The 17th survivor is the COMDAT-boundary case, and it is the reason the naive
rule is wrong.** `xdk/d3dx9/d3dxmath.obj .text+0xa4` (`0x4200ffc8`) →
`lbl_82858E94`. Captured at the decision point: `site=0xa4 site_region=None`,
`dest=0x6c dest_region=Some(88)` — the destination is inside the COMDAT region
`[88, 148)`, which `write_coff` extracts into its own `.text$dup` section while
the branch site stays in the parent `.text`. Different emitted sections, so the
relocation is kept. A rule that only asked "same `ObjInfo` section" would have
dropped it and broken the branch.

### Two confounds that had to be removed first — both would have produced a false account

1. **`dtk xex split` rewrites the symbols file it is given.** My private
   `cfg-rb3x/symbols.txt` was rewritten 24 s into the first rb3-xenon split
   (mtime `23:47:50`, 15 lines shorter) and never again. So run 1 and run 2 had
   *different inputs*. Comparing run 1 (baseline) against run 2 (fixed)
   reported **15 objects with `SECTION_LAYOUT|SYMBOL_TABLE` differences** that
   had nothing to do with the fix. Re-running the baseline on the converged file
   removed all 15. dc3 is not affected — its symbols file was not rewritten
   (byte-identical to the project copy, mtime unchanged).
   **Anyone doing a splitter A/B must run both arms on a symbols file that has
   already been through one split, or give each arm its own pristine copy and
   the same number of runs.**
2. **A "neutralised" control binary that was not neutral.** I built a variant
   with the new filter disabled to test causality. The patch string
   `            if matches!(reloc.kind, ObjRelocKind::PpcRel14) {` occurs
   **twice** at the same indentation — line 2021 (the COMDAT keep-back pass) and
   line 2426 (my filter) — and a first-occurrence replace hit the keep-back
   pass. See §4: the result is an accidental but decisive experiment.

## 4. Why the root-cause fix in `tracker.rs` is NOT in this commit

T2 root-caused the emission at `analysis/tracker.rs:503` (the executor walks past
`function_end` and evaluates `is_function_addr` against a previous function's
bounds; second trigger, the fall-through pseudo-branch at `ins_addr+4 ==
function_end`). Fixing it there is the better fix in the abstract. It cannot land
alone, for a measured reason.

`write_coff` has a pass at `xex.rs:2012`, *"Remove COMDAT entries involved in
REL14 relocations"*, which reads these very relocation records and forces both
ends of every REL14 to stay in the contiguous parent `.text` — because a REL14
has only ±32 KB of range and a `.text$dup` section can be relaid out arbitrarily
far away (the comment cites LNK2013, which has bitten this writer before). It is
not hypothetical: **it fires 7 times on a single dc3 split** (counted with
`RUST_LOG=dtk::util::xex=debug`, grepping its own
`Keeping REL14-involved function in main .text` line).

That pass is *what makes "same emitted section" true* at my drop point. Remove
the record upstream — in the tracker, before the split has even happened, where
"emitted section" is not knowable — and the keep-back pass stops seeing it, the
region gets COMDAT-extracted, and an intra-section branch can be separated from
its target with no relocation left to fix it.

The accidentally-mis-patched binary in §3 measured exactly that blast radius:
with the keep-back pass disabled and nothing else changed, rb3-xenon moved
**185 objects** by `SECTION_LAYOUT|SYMBOL_TABLE`, and REL14 records started
appearing at COMDAT-relative offsets (`xdk/xgraphics/import.obj` at `0x4`,
`0x1c`, `0x28` instead of `0x6b8`, `0x6d0`, `0x6dc`). That is the shape of a
tracker-side drop that lands without reworking the keep rule.

**Recommended follow-up task, for the integrator to open separately:** rework
the keep-back rule so it is derived from the *conditional-branch instructions*
in each candidate COMDAT region (does any `bc` in this region branch outside
it?) instead of from the relocation records; then the tracker-side fix can land
and the emitted objects stay correct. Note this is worth doing on its own
merits — the same runaway walk also emits `Rel24` and pollutes
`data_types`/`stores_to`/`hal_to`, which R1 does not touch (T2 §5/§6). It needs
its own parity account, because it moves the COMDAT layout.

## 5. Deliberately out of scope

- **REFHI/REFLO anchor selection (Shape 1).** Untouched, per the brief. It is
  retired by the objdiff rebuild (T1), and moving it here would move the same
  scores twice. **I do not think anchor synthesis is warranted right now**: T1
  measured objdiff HEAD clearing 22 of 23 rows, and T6 measured that every
  compiler-produced self-reference on both games is legitimate — so the
  remaining question is whether the *splitter* should mint `$LN`-shaped labels
  for its own readability, not whether the ruler needs it. That is a want, not a
  defect, and it should be argued on its own.
- **The DS-form XO-bit corruption (FINDING 8 / Q8, T3's test 2).** Still red.
  The one-line fix is to mask bits `[15:2]` instead of `[15:0]` when the primary
  opcode is 58 or 62 in `write_coff`'s `PpcAddr16Ha | PpcAddr16Lo` arm. I left
  it out for the same reason as the anchor: it rewrites **in-place instruction
  bytes** at 74 dc3 and 51 rb3-xenon sites, which is a second, independent
  movement of the ruler, and mixing it into this change would make both parity
  accounts unreadable. It is a clean, small, separately-accountable task.
- **A real `PpcRel14` arm in the section-data fixup.** T2 flagged that the 16
  surviving cross-section records keep a stale in-place displacement instead of
  the MSVC `-offset_in_section` convention. Unchanged here (it would move bytes
  at those 16 sites); still worth a link-level check independent of objdiff.

## 6. Artifacts

Scratch, gitignored, under `.worktrees/t4/scratch/`:
`dtk-baseline`, `dtk-fixed`, `{base,base2,fix,probe,neutral}-rb3x/`,
`{base,fix,probe}-dc3/`, `census/*.json`, `t4probe-rb3x.txt`, split logs.
Committed here: `findings/scripts/t4_obj_ab_diff.py`.
