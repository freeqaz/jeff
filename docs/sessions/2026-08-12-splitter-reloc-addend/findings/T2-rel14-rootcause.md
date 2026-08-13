# T2 — Root cause of the intra-function REL14 (Shape 2)

Investigation only. **No code change was landed.** Two temporary `eprintln!`
probes were added to `src/analysis/tracker.rs` to capture runtime values, the
splitter was rebuilt in a private `CARGO_TARGET_DIR`, and the probes were
reverted with `git checkout -- src/analysis/tracker.rs` before this document was
written. `git status` in the worktree shows no modification under `src/`.

Everything below is measured on this box, 2026-08-12, at jeff `main` = `8a42efb`.
Scratch, scripts and captured logs: `.worktrees/t2/scratch/` (gitignored, not
committed — the census scripts themselves are committed under
`docs/sessions/.../findings/scripts/`).

---

## 0. Answer in one paragraph

The REL14 is inserted by **`src/analysis/tracker.rs:503`**
(`Relocation::Rel14(target)` inside the `StepResult::Branch` /
`BranchTarget::Address` arm, statement at `:496`). It fires because the
executor **walked past `function_end` into the next function's body and kept
evaluating instructions against the previous function's bounds**. At the
hostip.obj site the captured values are `function_start=0x8256AAB8`,
`function_end=0x8256AAD8` — those are **`Curl_resolv_timeout`'s** bounds, not
`Curl_resolv_unlock`'s — while `ins_addr=0x8256AAFC` and
`target=Address(4:0x8256AB0C)` are both inside `Curl_resolv_unlock`. Against the
wrong bounds `is_function_addr` is false, so the `bc` is treated as leaving its
function and gets a relocation. The brief's proposed mechanism (the
`SectionAddress::new(SectionIndex::MAX, 0)` dummy for a non-`Address` target) is
**not** what happens and cannot be what happens — see §3.

---

## 1. Captured evidence at the hostip.obj site

Reproduction (private target dir, private config copy, scratch output dir — the
shared `dc3-decomp` tree is only read):

```
cd /home/free/code/milohax/dc3-decomp
JEFF_T2_WALK=0x8256AAB8 <worktree>/target-scratch/release/dtk xex split \
    <worktree>/scratch/cfg/config.yml <worktree>/scratch/out
```

`Curl_resolv_unlock = .text:0x8256AAD8; // type:function size:0x9C`
(`config/373307D9/symbols.txt:137199`), so the function is
`[0x8256AAD8, 0x8256AB74)`. The relocation site is `hostip.obj .text+0x53c`
= fn+0x24 = VA `0x8256AAFC`; the branch word is `0x419A0010`, i.e.
`beq cr6, +0x10` → real destination `0x8256AB0C` = fn+0x34.

**Runtime capture — the whole runaway walk** (`T2 walk` lines are one per
`instruction_callback`, printed only when `function_start == 0x8256AAB8`):

```
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAB8 op=Addi  result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AABC op=Cmpi  result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAC0 op=Stw   result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAC4 op=Bc    result=Branch([(Address(4:0x8256AAC8), false), (Address(4:0x8256AAD0), false)])
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAD0 op=B     result=Jump(Address(4:0x8256A8D0))
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAC8 op=Addi  result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AACC op=Bclr  result=Jump(Return)
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAD4 op=Illegal result=Illegal      <-- padding word
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAD8 op=Mfspr result=Continue        <-- NEXT FUNCTION
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AADC op=Stw   result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAE0 op=Std   result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAE4 op=Std   result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAE8 op=Stwu  result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAEC op=Lwz   result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAF0 op=Or    result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAF4 op=Or    result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAF8 op=Cmpli result=Continue
T2 walk fn=[0x8256AAB8,0x8256AAD8) ins=0x8256AAFC op=Bc    result=Branch([(Address(4:0x8256AB00), false), (Address(4:0x8256AB0C), false)])
```

**Runtime capture — the insertion itself** (probe on the `if branch.link ||
!is_fn_addr` arm, `tracker.rs:495`):

```
T2 branch-reloc INSERT ins=0x8256AAFC op=Bc link=false target=Address(4:0x8256AB00) is_fn_addr=false function_start=0x8256AAB8 function_end=0x8256AAD8
T2 branch-reloc INSERT ins=0x8256AAFC op=Bc link=false target=Address(4:0x8256AB0C) is_fn_addr=false function_start=0x8256AAB8 function_end=0x8256AAD8
```

**The requested values, at the moment of insertion:**

| field | captured value | what it should have been |
|---|---|---|
| `ins_addr` | `0x8256AAFC` | — |
| `function_start` | **`0x8256AAB8`** (`Curl_resolv_timeout`) | `0x8256AAD8` (`Curl_resolv_unlock`) |
| `function_end` | **`0x8256AAD8`** | `0x8256AB74` |
| `target` (taken) | `RelocationTarget::Address(SectionIndex 4, 0x8256AB0C)` | same |
| `is_fn_addr` | **`false`** | `true` |
| `branch.link` | `false` | — |

Both branch entries insert at the same key (`self.relocations` is a
`BTreeMap` keyed on `ins_addr`), so the second (taken-path) insert overwrites
the first (fall-through) one. The surviving record is
`Rel14(Address(0x8256AB0C))`.

**Which pass**: the FIRST tracker pass, in `split_write_obj_exe`
(`src/cmd/xex.rs:2618-2622`). Confirmed with the repo's own env-gated dump,
which prints the relocation set immediately after `tracker.apply`, before any
repair pass:

```
$ JEFF_DUMP_RELOCS="0x8256AAB0-0x8256AB80" dtk xex split ...
RELOC 0x8256AAD0 PpcRel24 -> Curl_resolv        (+0x0)  [sect .text]
RELOC 0x8256AAFC PpcRel14 -> Curl_resolv_unlock (+0x34) [sect .text]
RELOC 0x8256AB08 PpcRel24 -> Curl_share_lock    (+0x0)  [sect .text]
...
SYM 0x8256AAD8 kind=Function size=0x9c size_known=true sect=Some(4) name=Curl_resolv_unlock
FUNC SIZE STATS: size_known=69307 size_unknown=0
```

`retrack_unanalyzed_functions` (`src/cmd/xex.rs:2497`) is **not** the producer,
and could not be: it drops any code relocation it adds whose addend is non-zero
(`src/cmd/xex.rs:2565-2585`, "Dropping unrepresentable … (interior target)"),
which is exactly this one's `+0x34`.

**Where the addend then dies** — as the brief says, this is the *same*
addend-loss as Shape 1, not an independent bug:
`apply_relocations` (`tracker.rs:860`) resolves `0x8256AB0C` through
`symbols.for_relocation`, which returns the enclosing sized function symbol, and
records `(Curl_resolv_unlock, addend 0x34)`. `write_coff`'s section-data fixup
(`src/util/xex.rs:2093-2140`) has arms for `Absolute`, `PpcRel24` and
`PpcAddr16Ha|Lo` and falls through `_ => {}` for `PpcRel14`, and the emitted
COFF record carries no addend field. objdiff therefore resolves the operand to
`Curl_resolv_unlock + 0` = `0x518` and renders `beq cr6, 0x518` against our
`beq cr6, 0x34`.

## 2. The same producer, a second trigger: the fall-through entry

The other dc3 intra-object REL14 sites (`xdk/xgraphics/buildcfg.obj+0x40`,
`buildssa.obj+0x158`) come from the same line by a slightly different route,
also captured:

```
T2 walk fn=[0x82D519F0,0x82D51A30) ins=0x82D51A14 op=B   result=Jump(Address(4:0x82D51A2C))
T2 walk fn=[0x82D519F0,0x82D51A30) ins=0x82D51A2C op=Cmpl result=Continue
T2 walk fn=[0x82D519F0,0x82D51A30) ins=0x82D51A30 op=Bc  result=Branch([(Address(4:0x82D51A34), false), (Address(4:0x82D51A18), false)])
T2 branch-reloc INSERT ins=0x82D51A30 op=Bc link=false target=Address(4:0x82D51A34) is_fn_addr=false function_start=0x82D519F0 function_end=0x82D51A30
```

`??$FindSetBitInArray@I@D3DXShader@@YAIPAIIK@Z` is declared
`size:0x40` → `[0x82D519F0, 0x82D51A30)`, so the walk again ran one instruction
**past** `function_end`. Here the *taken* target `0x82D51A18` is in bounds, so
only the **fall-through** entry (`ins_addr + 4`, synthesised in
`src/analysis/vm.rs:743-746` as a `Branch` with `target = ins_addr + 4`) is out
of bounds — and it is the one that survives. The emitted relocation therefore
points at the instruction *after* the branch:

```
buildcfg.obj .text+0x40  word=4198ffe8  ->  lbl_82D51A34 (val 0x44)
                                            encoded destination = 0x28
```

The relocation says `0x44`; the instruction says `0x28`. That is a *worse*
failure than the addend loss — the anchor is not merely coarse, it is a
different basic block. Same shape at `buildssa.obj+0x158`
(`lbl_82D4FFAC` val `0x15c` vs encoded `0x140`).

**So `tracker.rs:503` has two distinct triggers, and only the first is what the
brief anticipated:**

- **A — walk escapes `function_end`.** Nothing bounds the executor at
  `function_end`. Two things feed it: `StepResult::Jump` seeds
  `possible_missed_branches` with `ins_addr + 4` after an unconditional `b`
  (`tracker.rs:443-446`) — at hostip that address is the 4-byte
  `0x00000000` alignment pad at `0x8256AAD4` — and `StepResult::Illegal`
  returns `ExecCbResult::Continue` (`tracker.rs:421-429`), so the pad does not
  end the block and the walk runs straight into the next function.
- **B — the fall-through pseudo-branch is treated as a relocation-worthy
  branch destination.** When the last instruction in a function's declared
  range is a `bc`, `ins_addr + 4 == function_end` fails the exclusive test at
  `tracker.rs:284` and the site is relocated against the fall-through.

Both are bugs in the *bounds*, not in the relocation kind. Note also
`tracker.rs:499` (`addr == function_start` → rewrite to `Rel24`) can never
fire in trigger A: the compared `addr` is the branch destination, and the
runaway walk's `function_start` belongs to a different function.

## 3. The brief's proposed mechanism is ruled out

> "when `target` is not a `RelocationTarget::Address`, the code substitutes a
> dummy `SectionAddress::new(SectionIndex::MAX, 0)` and sets `is_fn_addr=false`,
> which both forces a relocation AND fails the `addr == function_start` test,
> yielding Rel14."

That path (`tracker.rs:492-494`) does insert `Rel14(RelocationTarget::External)`,
but such a relocation **never reaches an object**: `apply_relocations` calls
`Relocation::kind_and_address()` (`tracker.rs:39-53`), which returns `None` for
`External`, and the loop `continue`s ("Skip external relocations")
(`tracker.rs:797-800`). The hostip record exists with a resolved symbol and a
`+0x34` addend, which is only reachable via `RelocationTarget::Address`. The
captured `target=Address(4:0x8256AB0C)` closes it.

## 4. Census: every REL14 in both target trees

`scripts/rel14_census.py` (raw COFF records) and `scripts/rel14_classify.py`
(resolves each site to a VA via the object's own symbols + the project
`symbols.txt`, then classifies against declared function ranges).

| tree | REL14 | same emitted section | cross-section | site outside its declared fn (A) | intra-function (B) | cross-function (C) |
|---|---|---|---|---|---|---|
| dc3 `build/373307D9/obj` (2223 objs) | **8** | 8 | **0** | 2 | 2 | 4 |
| rb3-xenon `build/45410914/obj` (3085 objs) | **650** | 634 | **16** | 4 | 139/141 | 490/493 |

(rb3-xenon: 12 of 650 sites could not be VA-resolved — no symbol in that
section appears in `symbols.txt` — so the A/B/C columns sum to 638. The two
"x/y" figures are with/without those 12 excluded from the same-section split.)

Two corrections to the numbers in `NOTES.md` FINDING 3, both from definition
rather than arithmetic:

- **"REL14 intra-fn: dc3 2, rb3-xenon 59"** counts records whose *target symbol
  is the enclosing function symbol*. Counting instead by *where the branch
  actually goes* (the encoded displacement), intra-function REL14 is
  **dc3 2, rb3-xenon 141**. The extra 82 are intra-function branches whose
  relocation happened to anchor on an interior `lbl_*` rather than on the
  function symbol; they are the same defect and objdiff mis-renders them the
  same way.
- **182 of rb3-xenon's 634 same-section REL14 (and 4 of dc3's 8) have a
  relocation target that disagrees with the encoded branch destination.** Those
  are not "coarse anchors", they are wrong ones. dc3's four: the two
  intra-function (addend dropped) plus the two fall-through-anchored above.

The measured premise that motivates any rule at all still holds and is
re-confirmed here: **the MSVC compiler emits zero REL14 across 989 dc3 + 1204
rb3-xenon compiler-produced objects.** Every REL14 in a target object is
splitter-originated.

## 5. Is "emit REL14 only when the target leaves the emitted SECTION" the right rule?

**Yes as the emission rule, no as the fix.** It is the correct *containment*,
and it is strictly safer than the current function-scoped test, but it treats
the symptom. The defect is that the tracker evaluates instructions against
another function's bounds; the section rule merely makes that harmless for
`bc`. Both should land, and the bounds fix should land first, because the same
runaway walk also produces `Rel24` records (`tracker.rs:452-455`) and pollutes
`data_types`/`stores_to`/`hal_to` — the section rule does nothing for those.

Why the section rule is correct on its own terms:

- Within one emitted section, `write_coff` copies the XEX section data verbatim
  and `PpcRel14` has **no** arm in the fixup match (`xex.rs:2139`), so the
  encoded 14-bit displacement survives untouched and is already correct. The
  linker preserves intra-section relative distances. The relocation is
  therefore **not needed**.
- Worse, it is malformed. `write_coff` documents the MSVC convention it must
  replicate — `new_disp = (S + A) − section_start_VA`, with `A` the in-place
  displacement — and implements it for `PpcRel24` by rewriting the in-place to
  `−offset_in_section` (`xex.rs:2103-2121`; verified on hostip: `bl
  Curl_share_lock` at section offset `0x548` carries in-place `0xFFFAB8` =
  `−0x548`). REL14 never gets that rewrite, so its `A` is left as the original
  `target − site`, which the linker would then add on top of its own
  computation. `xex.rs:2016-2040` already exists because REL14 fixups have
  overflowed the linker before (LNK2013). **Flagged, not proven:** nobody has
  relinked dc3 with these 8 sites to observe the corruption, and the affected
  units (`hostip.c`, `buildcfg.cpp`, …) are all in `link_order.txt`, so this
  deserves a check independent of objdiff.
- Cross-section REL14 genuinely needs the record: dtk carves functions into
  separate COMDAT sections, so a `bc` whose destination lands in another
  section has no valid encoded displacement after relayout. 16 such records
  exist on rb3-xenon, 0 on dc3.

**About the six dc3 cross-function REL14 the brief says "may be legitimate".**
Measured, they are 4 class-C plus the 2 fall-through-anchored class-A, and
**all six are same-section**, so the section rule drops all six. That is the
right outcome and does not "break" anything: two of the six are outright wrong
(§2), and the other four (`nuiruntime.obj+0x49a0`, `+0x49a4` →
`lbl_829CE124`; `buildssa.obj+0x148` → `fn_82D4FFE0`; `buildcfg.obj+0x30` →
`fn_82D51A64`) point at the right address but are redundant inside one section
and malformed for the linker per the bullet above. Their "cross-function"
status is itself an artifact of dtk's own carving — `??$FindSetBitInArray@I@…`
is declared `size:0x40` while its real body continues through `lbl_82D51A34`
and `lbl_82D51A5C`, so the `bne fn_82D51A64` at `+0x30` is a *within-function*
loop exit that only looks cross-function because the symbol is short. It should
not be preserved as evidence of a real cross-function conditional branch.

### Keep / drop, per game, against the currently emitted records

| rule | dc3 (of 8) | rb3-xenon (of 650) |
|---|---|---|
| **R1 — emit REL14 only when the destination leaves the emitted SECTION** | keep **0**, drop **8** | keep **16**, drop **634** |
| R0 — current rule (destination leaves the enclosing FUNCTION) | keep 8, drop 0 | keep 650, drop 0 |
| R2 — R1, *and* bound the walk at `function_end` + stop treating the fall-through as a branch target | keep ≤16 (see below) | keep ≤16 |

R2's exact count is not measurable without building the fix; it is bounded
above by R1's keep-set, since fixing the bounds can only remove insertions.
The 4 rb3-xenon and 2 dc3 class-A rows (site outside its declared function)
disappear under the bounds fix alone. Whether any of the 16 cross-section rows
survive the bounds fix is the one number a fix lane must re-measure — if all 16
turn out to be over-carve artifacts too, the correct emitted REL14 count is
**zero, matching the compiler**, and that is the hypothesis to test first.

Under R1 the objdiff-visible defect is fully retired on both games: every
record that objdiff currently mis-renders (182 + 4 wrong-target, plus the
141 + 2 intra-function) is same-section and therefore dropped.

## 6. What a fix lane must still settle

1. Bound the executor at `function_end`, or end the block on `StepResult::Illegal`,
   or stop seeding `possible_missed_branches` past a terminator — decide which,
   and measure the blast radius on `Rel24` and on `data_types`/section
   classification, not just on REL14. This changes the split output far beyond
   the 8/650 rows.
2. If R1 keeps any cross-section REL14, `write_coff` needs a real `PpcRel14`
   arm implementing the `−offset_in_section` convention. Today there is none.
3. The parity account required by README §5 is unchanged and is the expensive
   part: this moves the ruler for every score in dc3 and rb3-xenon.

## Reproduction artifacts

- Census scripts (committed): `scripts/rel14_census.py`, `scripts/rel14_classify.py`
  in this findings directory.
- Captured logs and JSON (not committed, gitignored scratch):
  `.worktrees/t2/scratch/{split.err,split2.err,split3.err,split4.err,dc3_rel14.json,rb3x_rel14.json,dc3_cls.json,rb3x_cls.json}`
- Splitter built at `main` = `8a42efb` with
  `CARGO_TARGET_DIR=<worktree>/target-scratch`; `target/release/dtk` in the
  main checkout was never written.
- dc3 was split into `<worktree>/scratch/out` against a private copy of
  `config/373307D9/{config.yml,symbols.txt,splits.txt}`, so dtk's symbols-file
  rewrite never touched the project tree.
