# DS-form decode — the follow-up task the integrator named, done as one change

Branch `dsform-160-dsform-decode`, worktree `.worktrees/dsform-160`, based on
`main` = `c0cc506`. Measured on this box 2026-08-13.

**Verdict: LAND.** The analysis-side DS-form address decode is fixed and T5's
writer-side mask (reverted at integration by `dbc887a`) is restored, in one
commit, because either half alone makes something worse. Across the whole of
dc3 **one object of 2223 changes** and it is the intended one; rb3-xenon is
**3085/3085 byte-identical** and cea-decomp **3675/3675 byte-identical**, with
the staging self-check firing on dc3 and cea; T3's
`ds_form_immediate_zeroing_must_preserve_xo_bits`
is un-ignored and green with its assertion untouched (163 passed / 1 ignored →
**164 passed / 0 ignored / 0 failed**). A relink in which the anchor symbol is
actually defined shows the fixed arm's linked instruction is `lwa` pointing at
`sDefaultHoverTimer`, where the baseline's is `lwa` pointing two bytes before
`lbl_82F446EE` — i.e. correct only while those two symbols stay adjacent.

Deploy hazards first. Every build used
`CARGO_TARGET_DIR=<worktree>/target-scratch{,-baseline}`.
`/home/free/code/milohax/jeff/target/release/dtk` is **unchanged**:
`2026-08-13 06:38`, 8,355,688 bytes at both the start and the end of this
session. (Note that is *not* the mtime the integration doc recorded — a peer
deployed the merged `main` at 06:38 today, before this task started. Nothing in
this session wrote it.) dc3-decomp, rb3-xenon and cea-decomp were **read only**:
both arms of every A/B ran against separate pristine copies of
`config/<id>/`, and every split wrote into `<worktree>/scratch/`. Nothing
merged, nothing pushed, `main` untouched.

---

## 1. The change

One commit, `3ece0b6`, three files:

```
 src/analysis/vm.rs          | 38 +++++++++++++++++++++++++++++++++++--   (38 added, 1 removed)
 src/util/xex.rs             | 27 ++++++++++++++++++++++++++-             (27 added, 1 removed)
 src/util/xex_reloc_tests.rs | 45 +++++++++++++++++-----------------------  (18 added, 27 removed)
 3 files changed, 83 insertions(+), 29 deletions(-)
```

### 1.1 Analysis side — the root cause

`src/analysis/vm.rs`, the `is_load_store_op` arm of `VM::step`. The effective
address of a load/store off a **constant** base was

```rust
let address = base.wrapping_add(ins.field_simm() as u64) as u32;
```

`field_simm()` is `(code & 0xffff) as i16` — the whole low halfword. On a
DS-form instruction (primary opcode 58 `ld`/`ldu`/`lwa`, 62 `std`/`stdu`) the
displacement is the 14-bit `DS` field, bits [15:2] scaled by 4, and bits [1:0]
are an opcode extension. So the decode overshot the effective address by the XO
value. At dc3 `system/gesture/ArcDetector` VA `0x82E025AC` the retail word is
`0xE96B46EE` (`lwa`, XO = 2) and the decode produced `0x82F446EE`, where the
real target is `sDefaultHoverTimer` at `0x82F446EC`.

It now calls a named predicate:

```rust
pub fn is_ds_form_load_store_op(op: Opcode) -> bool {
    matches!(op, Opcode::Ld | Opcode::Ldu | Opcode::Lwa | Opcode::Std | Opcode::Stdu)
}
pub fn load_store_displacement(ins: &Ins) -> i32 {
    if is_ds_form_load_store_op(ins.op) { ins.field_ds() as i32 } else { ins.field_simm() as i32 }
}
```

`field_ds()` is `(code & 0xfffc) as i16`, i.e. the same halfword with the
opcode extension masked off, sign-extended. D-form load/stores, `addi`/`addis`,
`cmpi` and the `Stw`/`Lwz` stack-slot trackers are untouched — measured, not
asserted: the D-form census below is unchanged to the record.

Scoping is by opcode, not by a bit test, so the set is auditable. DQ-form
`lq`/`stq` and DS-form `lfdp`/`stfdp` are not implemented by the Xenon CPU, so
58/62 is complete here.

### 1.2 Writer side — T5's mask, restored verbatim

`git revert dbc887a` restores `write_coff`'s `PpcAddr16Ha | PpcAddr16Lo` arm to
zero the displacement only:

```rust
let keep_mask = match insn >> 26 {
    58 | 62 => 0xFFFF0003, // DS-form: preserve XO [1:0]
    _ => 0xFFFF0000,       // D-form: whole immediate
};
```

### 1.3 Why the two must land together

`dbc887a` reverted 1.2 because MSVC's REFLO is **additive** (T7 relinked; the
linked low half moves by exactly the in-place word). This session reproduces
that arithmetic in both directions at the same site:

| arm | in-place | + `lo(anchor)` | linked field | XO | instruction | points at |
|---|---|---|---|---|---|---|
| deployed / baseline | `0x0000` | `lo(lbl_82F446EE)` | `= lo(S)` | 2 | `lwa` | `S − 2` |
| T5 alone (reverted) | `0x0002` | `lo(lbl_82F446EE)` | `= lo(S)+2` | 0 | **`ld`** | `S + 2` |
| **this branch** | `0x0002` | `lo(sDefaultHoverTimer)` | `= lo(S)+2` | 2 | `lwa` | **`S`** |

Row 1 is right at link time only because both errors cancel. Row 2 is the
integrator's reason for the revert. Row 3 is right on both sides.

### 1.4 The test

T3's `ds_form_immediate_zeroing_must_preserve_xo_bits` is un-ignored. The
assertion, the fixture and the three sites are byte-for-byte T3's — only the
`#[ignore]` attribute is gone and the doc comment gained a history paragraph.
The D-form control (`0x398C0048 → 0x398C0000`) still pins that a "fix" cannot
pass by deleting the arm.

```
BEFORE (main = c0cc506):
test util::xex_reloc_tests::ds_form_immediate_zeroing_must_preserve_xo_bits ... ignored, writer fix reverted at integration: correct in the object, wrong at link time until the DS-form anchor decode is fixed -- see the doc comment
test result: ok. 163 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.03s

AFTER (3ece0b6):
test util::xex_reloc_tests::ds_form_immediate_zeroing_must_preserve_xo_bits ... ok
test result: ok. 164 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

`cargo test --release --bin dtk` both times, private target dirs. The delta is
exactly +1 passed / −1 ignored. No other test moved.

---

## 2. The minted symbol: `lbl_82F446EE` → `sDefaultHoverTimer`

Direct evidence, `diff` of the two arms' emitted asm for the one changed unit
(`<` baseline, `>` fixed):

```
1235c1235
< /* 82E010DC 00DF5ADC  E9 6B 46 EE */	lwa r11, 0x46ec(r11)
> /* 82E010DC 00DF5ADC  E9 6B 46 EE */	lwa r11, sDefaultHoverTimer@l(r11)
1525c1525
< /* 82E01508 00DF5F08  E9 7E 46 EE */	lwa r11, 0x46ec(r30)
> /* 82E01508 00DF5F08  E9 7E 46 EE */	lwa r11, sDefaultHoverTimer@l(r30)
2697c2697
< /* 82E02590 00DF6F90  3D 60 82 F4 */	lis r11, lbl_82F446EE@ha
> /* 82E02590 00DF6F90  3D 60 82 F4 */	lis r11, sDefaultHoverTimer@ha
2704c2704
< /* 82E025AC 00DF6FAC  E9 6B 46 EE */	lwa r11, lbl_82F446EE@l(r11)
> /* 82E025AC 00DF6FAC  E9 6B 46 EE */	lwa r11, sDefaultHoverTimer@l(r11)
```

Two things beyond the asked-for one:

- the site the integrator named (`82E025AC`) moves off `lbl_82F446EE` onto
  `sDefaultHoverTimer`, both at the `@ha` and the `@l`;
- **two further sites that previously resolved to nothing now resolve.**
  `82E010DC` in `?GetSwipeAmount@ArcDetector@@QBAMXZ` and `82E01508` in
  `?PrintJointPath@ArcDetector@@QBAXXZ` rendered as a bare `0x46ec(rX)` before
  — the asm writer already used the DS field, so the displacement it *printed*
  was right while the analysis that mints anchors was wrong. They are the same
  datum: at `82E010D8` the D-form `addi r30, r11, sDefaultHoverTimer@l` was
  already anchored correctly, two instructions from a DS-form load of the same
  address that was not.

Record level, `scripts/coff_reloc_parity.py objdiff` (baseline → fixed):

```
removed:  /53#62 +0x808 REFHI lbl_82F446EE 3d600000   ?UpdateOverlay@ArcDetector@@QAAMPAVRndOverlay@@M@Z
          /53#62 +0x824 REFLO lbl_82F446EE e96b0000   ?UpdateOverlay@…
          /53#62 +0x824 PAIR  @comp.id     e96b0000
added:    /53#46 +0x24  REFLO sDefaultHoverTimer e96b0002  ?GetSwipeAmount@ArcDetector@@QBAMXZ
          /53#46 +0x24  PAIR  @comp.id           e96b0002
          /53#49 +0x158 REFLO sDefaultHoverTimer e97e0002  ?PrintJointPath@ArcDetector@@QBAXXZ
          /53#49 +0x158 PAIR  @comp.id           e97e0002
          /53#62 +0x808 REFHI sDefaultHoverTimer 3d600000  ?UpdateOverlay@…
          /53#62 +0x824 REFLO sDefaultHoverTimer e96b0002  ?UpdateOverlay@…
          /53#62 +0x824 PAIR  @comp.id           e96b0002
data bytes: 5   (/53#46 +0x38..39 46ee→0002, /53#49 +0x346..347 46ee→0002, /53#62 +0x827 00→02)
```

After the change the object carries **three** DS-form REFLO sites, all anchored
on `sDefaultHoverTimer`, all with zero displacement and XO preserved. That is
exactly what MSVC emits for the same translation unit — measured, not recalled,
on `dc3-decomp/build/373307D9/src/system/gesture/ArcDetector.obj`:

| tree | DS-form REFLO sites | displacement 0 | XO ≠ 0 | words |
|---|---|---|---|---|
| our compiler's `ArcDetector.obj` | 3 | 3 | **3** | `e96b0002`, `e97f0002`, `e96b0002` |
| split, baseline | 1 | 1 | 0 | `e96b0000` |
| split, **fixed** | 3 | 3 | **3** | `e96b0002`, `e97e0002`, `e96b0002` |

Not fixed here, deliberately: dc3's checked-in
`config/373307D9/symbols.txt` still carries the damage the old decode caused —
`sDefaultHoverTimer = .data:0x82F446EC; // size:0x2` (it is a 4-byte `int`) and
a `lbl_82F446EE` that should not exist. Editing a project config is a separate
blast radius (INTEGRATION §6.3) and this task is forbidden to touch dc3. §5 is
why that matters more than it looks.

---

## 3. Split-output diff, whole trees, three projects

Harness: `scripts/xex_split_ab_compare.sh`, separate pristine config copies per
arm, one run each, each project's own `rule split` env and post-split steps
replayed, `--verify-against` the project's live objects.

### dc3 — 1 object of 2223, and it is the intended one

```
[split-ab] verify vs /home/free/code/milohax/dc3-decomp/build/373307D9/obj: identical 2223, different 0, missing 0
[split-ab] staging is faithful: the new side reproduces the project byte-for-byte.

[split-ab] units (objects):        2223
[split-ab] objects byte-identical: 2222
[split-ab] objects changed:        1
    obj/system/gesture/ArcDetector.obj
[split-ab] only in old: 0   only in new: 0
[split-ab] other changed files (excluding config.json/dep): ['asm/system/gesture/ArcDetector.s']
```

The staging self-check **fired** — 2223 objects hashed against the tree dc3
actually scores — so this is measured against what the project uses, not
against a staging artefact. `t4_obj_ab_diff.py` classifies the single change as
`RELOC_ADDED_{PAIR,REFHI,REFLO} | RELOC_REMOVED_{REFHI,REFLO} | SECTION_DATA |
SYMBOL_TABLE`; net record delta `+4` (`+3 REFLO, +2 PAIR, +1/−1 REFHI, −1
REFLO`), 5 data bytes. Zero section-layout changes anywhere.

Whole-tree record census, `coff_reloc_parity.py shape`:

| tree | D-form sites | imm = 0 | DS-form sites | disp = 0 | **XO ≠ 0** | REFHI | REFLO | PAIR |
|---|---|---|---|---|---|---|---|---|
| dc3 baseline | 263,799 | 263,799 | 74 | 74 | 0 | 120,891 | 142,982 | 263,873 |
| dc3 **fixed** | 263,799 | 263,799 | 76 | 76 | **3** | 120,891 | 142,984 | 263,875 |

The D-form column does not move by one record, which is the check that the
predicate is scoped. `PAIR == REFHI + REFLO` in both arms and every PAIR carries
a zero displacement channel, so the record shape is still compiler-form. All
three XO ≠ 0 sites are the ArcDetector ones listed in §2.

### rb3-xenon — provably inert, and measured inert

**3085 / 3085 byte-identical, 0 changed, empty record delta.** Predicted from
T5's census (0 of 51 rb3-xenon DS-form REFLO sites has XO ≠ 0) and confirmed
arm-against-arm.

One thing to state rather than bury: rb3-xenon's `--verify-against` self-check
**did not pass** — 37 of 3085 of the project's live objects differ from what
either of my arms emits (`ADSR.obj`, `BandDirector.obj`, `VocalTrack.obj`, …,
a subset of the 188 that T7 measured moving under T4's REL14 filter). Both of
my arms are identical to each other, so the causal question this task asks is
answered regardless; what the 37 say is that **rb3-xenon's `build/45410914/obj`
is stale with respect to the splitter that is deployed right now** — it has not
been re-split since a peer deployed the merged `main` at 06:38 today. That is a
pre-existing project condition, it is not caused by this change, and it is not
this task's to fix. dc3's tree is current (2223/2223).

### cea-decomp — measured, not assumed, and inert

cea-decomp is dtk-split X360 and is in this change's blast radius by
construction. It was measured in this session rather than argued about:

```
[split-ab] verify vs /home/free/code/milohax/cea-decomp/build/2011-07-28/obj: identical 3675, different 0, missing 0
[split-ab] staging is faithful: the new side reproduces the project byte-for-byte.

[split-ab] units (objects):        3675
[split-ab] objects byte-identical: 3675
[split-ab] objects changed:        0
[split-ab] split output identical.
```

**8,983 objects across the three projects; 1 changes.**

---

## 4. The relink

Harness: T7's `link/link2-before.rsp` from
`decomp-bench` branch `bench-t7-splitter-parity`
(`archive/runs/2026-08-13-splitter-parity-t7/`), run under the project's own
`build/compilers/X360/16.00.11886.00/link.exe` via `wibo`, from a shadow tree of
symlinks (`src` and `data` → the real dc3 tree, `obj` → that arm's split
output). Nothing was written into dc3.

### 4.1 The word at VA `0x830746b8`, exactly as asked

`?UpdateOverlay@ArcDetector@@QAAMPAVRndOverlay@@M@Z` lands at `0x83073e94` in
**both** arms, and the site is `+0x824`, so `0x830746b8` is the right address in
both.

| arm | word at `0x830746b8` | primary | XO | mnemonic |
|---|---|---|---|---|
| baseline | `e96b5566` | 58 | 2 | **`lwa`** |
| fixed | `e96b0002` | 58 | 2 | **`lwa`** |
| retail (`ArcDetector.s:2704`, `E9 6B 46 EE`) | — | 58 | 2 | **`lwa`** |

The baseline word reproduces T7's `e96b5566` exactly, which is the check that
this relink is the same experiment. **Both arms decode to the same opcode as
retail**, which is the success criterion, and the criterion is met.

But `e96b0002` is the *unrelocated* word, and that needs saying plainly rather
than being scored as a pass: in T7's link set **`sDefaultHoverTimer` is not
defined**, so under `/FORCE:UNRESOLVED` the linker leaves the field alone.

```
ArcDetector.obj : error LNK2019: unresolved external symbol sDefaultHoverTimer
  referenced in function "public: void __cdecl ArcDetector::ResetHoverTimer(void)"
```

That line appears in **both** arms. It is pre-existing: the *baseline* split
`ArcDetector.obj` already carries **8** relocation records anchored on
`sDefaultHoverTimer` and only **2** on `lbl_82F446EE`. The reason is a hybrid-link
naming gap, not this change — dc3 has decompiled
`system/gesture/StandingStillGestureFilter`, and a decompiled unit's data-glue
object (`data/system/gesture/StandingStillGestureFilter.obj`) exports its data
as `lbl_82F446EC`, `lbl_82F446EE`, … and never as `sDefaultHoverTimer`, while
the compiled `src/system/gesture/ArcDetector.obj` defines `sDefaultHoverTimer`
as a **static** (storage class 3), invisible to other objects. So T7's link set
resolves the `lbl_` spelling and cannot resolve the config spelling, in either
arm.

So this relink cannot adjudicate the *displacement*. It adjudicates the opcode,
and the opcode is right.

### 4.2 The relink that can adjudicate

Same rsp plus one line: `build/373307D9/obj/system/gesture/StandingStillGestureFilter.obj`,
the split's own target object for that unit, which **does** export
`sDefaultHoverTimer` as EXTERNAL. Prepended, so `/FORCE:MULTIPLE` picks it.
Both arms plus a determinism control (the baseline arm linked twice). All three
`/OUT:` paths were made the same length after the first attempt showed that
`…before.exe` vs `…after.exe` shifts `.rdata` by 16 bytes and moves 9.3 MB of
the image — an artifact of the harness, not of the change.

| arm | word at the site | mnemonic | displacement | points at |
|---|---|---|---|---|
| A baseline | `e96b5c42` | `lwa` | `0x5c40` | `lbl_82F446EE (0x83545c42) − 2` |
| B **fixed** | `e96b548a` | `lwa` | `0x5488` | **`sDefaultHoverTimer (0x835c5488)`** |
| C baseline re-run | `e96b5c42` | `lwa` | `0x5c40` | identical to A |

REFLO's additivity is visible in both rows: `0x0000 + 0x5c42 = 0x5c42` and
`0x0002 + 0x5488 = 0x548a`.

This is the result that decides the task. The fixed arm names the datum and
lands on it. The baseline arm lands two bytes before a *different* symbol and is
correct only for as long as the linker keeps `sDefaultHoverTimer` and
`lbl_82F446EE` adjacent — and in this very link it does not: they are separate
COMDATs and the linker put them 0x7f846 bytes apart, so **the baseline arm reads
the wrong datum here and the fixed arm reads the right one.**

Determinism control: A and C differ in 389 bytes (PE timestamp and the debug
directory), and **not at the site**. Any real signal has to clear that floor.

### 4.3 Diagnostics parity

| link | LNK lines | LNK2013 | LNK1223 | code histogram |
|---|---|---|---|---|
| T7 rsp, baseline vs fixed | 15,234 / 15,234 | 0 / 0 | 0 / 0 | identical |
| +StandingStill, baseline vs fixed | 15,259 / 15,259 | 0 / 0 | 0 / 0 | identical |

No malformed-relocation complaint (`LNK2013`) and no `LNK1223` in any arm: the
linker parses and fixes up every split object under both binaries.

### 4.4 Scope, so nothing here is overstated

`dc3-decomp/build/373307D9/default.exe.rsp` contains
`src/system/gesture/ArcDetector.obj` and `data/system/gesture/ArcDetector.obj`
and **zero** occurrences of `obj/system/gesture/ArcDetector.obj`. dc3's shipped
link does not use the object this change moves. The relinks above had to inject
it, exactly as T7's did. **Nothing in the shipped pipeline changes either way**
— which is the same statement the integrator made when holding T5, and it cuts
the same way now that the trade has flipped.

---

## 5. What this does NOT fix, stated so nobody assumes it did

1. **dc3's `config/373307D9/symbols.txt` is still wrong.**
   `sDefaultHoverTimer` is recorded `size:0x2` for a 4-byte `int` and a spurious
   `lbl_82F446EE` still splits it. This branch changes what the *analysis*
   decodes; it does not rewrite a project config. Consequence, visible in §4.2:
   the split emits `sDefaultHoverTimer` and `lbl_82F446EE` as two independent
   data COMDATs, so a linker is free to separate them. That is a live defect in
   dc3's config and it wants its own task, with its own parity account.
2. **The hybrid-link naming gap is untouched and now covers one more site.**
   A decompiled unit's data-glue object exports `lbl_<addr>` names; a split
   target object that references the same datum by its config name does not
   resolve against it. The baseline object already had 8 such records; this
   branch makes it 12 and removes the 2 `lbl_`-anchored ones. If some future
   link line carries the *target* ArcDetector.obj next to the *decompiled*
   StandingStillGestureFilter, that site changes from "resolves to the right
   place by accident" to "does not resolve". Today no link line does. This is
   the one honest cost of landing, and it is the mirror image of the cost the
   integrator weighed when holding T5.
3. **`src/analysis/tracker.rs:503`** — T2's runaway executor walk — is still
   there, still emitting Rel24 and still polluting `data_types`/`stores_to`.
   Untouched (INTEGRATION §6.1).
4. **No objdiff report was generated.** The object-level statement is stronger:
   exactly one object changes on dc3 and none anywhere else, so no symbol
   outside `ArcDetector.obj` can move. The expected movement inside it is the
   one the integrator priced at **+0.00185 fuzzy** on
   `?UpdateOverlay@ArcDetector@@QAAMPAVRndOverlay@@M@Z`, plus whatever the two
   newly-anchored sites in `?GetSwipeAmount` and `?PrintJointPath` are worth.
   **This is a correctness fix, not a scoring fix** — do not quote it as one.
5. **No deploy.** `target/release/dtk` is untouched. No version bump: split
   output does move on dc3, so the repo convention (`287a322`) says the deploy
   wants `1.12.0 → 1.13.0`, but a version bump on an unmerged branch is the
   integrator's step, not this task's.

---

## 6. Reproduce

```bash
# tests
CARGO_TARGET_DIR=<worktree>/target-scratch cargo test --release --bin dtk

# split A/B, whole tree, staging self-check on
scripts/xex_split_ab_compare.sh --old <fixed-dtk> --new <baseline-dtk> \
  --project /home/free/code/milohax/dc3-decomp --config config/373307D9/config.yml \
  --post-split 'python3 tools/prune_split_outputs.py "$SPLIT_OUT"' \
  --verify-against build/373307D9/obj --work-dir <scratch>/dc3-ab --keep

# what moved, and at record grain
python3 docs/sessions/2026-08-12-splitter-reloc-addend/findings/scripts/t4_obj_ab_diff.py <base>/obj <fix>/obj
python3 scripts/coff_reloc_parity.py objdiff <base>/obj <fix>/obj
python3 scripts/coff_reloc_parity.py shape <base>/obj <fix>/obj

# the relink (rsp from decomp-bench branch bench-t7-splitter-parity)
git -C ../decomp-bench show bench-t7-splitter-parity:archive/runs/2026-08-13-splitter-parity-t7/link/link2-before.rsp
# shadow tree: build/373307D9/{src,data} -> dc3, obj -> that arm's split output
../wibo/build/release/wibo <dc3>/build/compilers/X360/16.00.11886.00/link.exe /NOLOGO @<arm>.rsp
# and the adjudicable variant: prepend build/373307D9/obj/system/gesture/StandingStillGestureFilter.obj
```

Artifacts (gitignored, ~2 GB, under `<worktree>/scratch/`): `dc3-ab/`,
`rb3x-ab/`, `cea-ab/` both arms' object trees; `link/{before,after,o_a,o_b,o_c}/`
the five linked images, maps, logs and response files.
