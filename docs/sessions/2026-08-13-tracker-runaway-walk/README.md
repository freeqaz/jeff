# Task 161 — the runaway tracker walk, fixed at the cause

Branch `tracker-161-runaway-walk`, worktree `.worktrees/tracker-161`, based on
jeff `main` = **`c0cc506`** (which is also the binary the three projects were
running when this session started — `jeff/target/release/dtk` sha256
`aaee03bf…`, byte-identical to a build of `c0cc506`).

Follows `../2026-08-12-splitter-reloc-addend/` — T2 root-caused the intra-function
REL14 to a tracker walk past `function_end`, T4 fixed the symptom at the writer,
and INTEGRATION §6 gap 1 left the cause open. This is the cause.

**Deploy hazard, first.** Every build used
`CARGO_TARGET_DIR=.worktrees/tracker-161/target-scratch`. Nothing was written to
`jeff/target/release/dtk`. dc3-decomp, rb3-xenon and cea-decomp were **read
only**: each split ran against a private copy of `config/<id>/` staged by
`scripts/xex_split_ab_compare.sh`, into scratch output dirs under this worktree.
Both projects' `symbols.txt` are unchanged (rb3-xenon's staged copies came out
byte-identical to the project's, sha `efff9d8f…`). Nothing pushed.

---

## 1. Verdict in one paragraph

The defect is real, it is fixed, and the literal reading of the brief — "stop the
walk at `function_end`" — is the **wrong fix**, on measurement: it costs 94
correct relocation records across 17 rb3-xenon objects. What is actually broken is
not that the walk strays but that the *containment test* is answered by the wrong
function; hi/lo dataflow pairing is bounds-independent and only the branch
question is not. Judging containment against the function that actually contains
the instruction fixes the defect and loses nothing. Alongside it, the COMDAT
keep-back is re-derived from the instruction stream (it was reading the very
relocation records the tracker fix removes), which uncovered a second, unrelated
defect — **COMDAT regions nest, and both containment lookups in `write_coff` only
ever consulted the nearest one**. Net object movement: **dc3 2 of 2223,
rb3-xenon 64 of 3085, cea-decomp 2 of 3675, every one accounted for, zero
unexplained.** Two pre-existing defects in the deployed objects are retired: one
extracted COMDAT on rb3-xenon contained a conditional branch that escaped it, and
dc3's two fall-through-anchored `.s` sites now render the destination the
instruction actually reaches.

## 2. Commits

| commit | what |
|---|---|
| (see `git log tracker-161-runaway-walk`) | tracker containment fix + regression test |
| | instruction-derived COMDAT keep-back + nesting-aware containment |
| | R1 emission rule judged against the encoded displacement, + out-of-section guard |
| | this document, `comdat_branch_audit.py`, INTEGRATION §4.3 correction |

Files: `src/analysis/tracker.rs`, `src/util/xex.rs`,
`docs/sessions/2026-08-12-splitter-reloc-addend/INTEGRATION.md`, this directory.

## 3. What changed, and why each piece is there

### 3.1 `tracker.rs` — containment, not bounds

`Executor::run` walks a basic block linearly (`ExecCbResult::Continue` advances
`state.address += 4`) and bounds that walk **at the end of the section**, not at
the end of a function — it has no notion of a function at all. Every path that
*enqueues* work is already function-bounded (`is_function_addr` guards the `Jump`,
jump-table and `Branch` pushes; `possible_missed_branches` is guarded by
`next_addr < function_end`), so **"refuse to enqueue" cannot fix this**: the
escape is the linear fall-through, which is not an enqueue. That leaves "stop the
walk" — and see §4 for why that is wrong too.

The fix: `function_start`/`function_end` are captured once per `process_function`
and do not follow the walk, so when the walk strays `is_function_addr` answers for
the wrong function. `enclosing_function_bounds(obj, ins_addr)` resolves the
function that actually contains the instruction, and `is_function_addr` is built
from that. It is consulted **only** when `ins_addr` is outside the walk's own
range, so the in-bounds path is untouched and costs nothing.

For an instruction in the gap after an under-sized symbol, `end` is the next
function symbol's address rather than the declared end. That is deliberate: dc3's
`??$FindSetBitInArray@I@D3DXShader@@YAIPAIIK@Z` is declared `size:0x40` while its
loop-exit `bc` sits one instruction past the declared end and branches back into
the body. With a strict declared range that site has no enclosing function and the
bogus record survives.

### 3.2 `xex.rs` — the COMDAT keep-back, re-derived from the instruction stream

The pass at `xex.rs:2012` ("Remove COMDAT entries involved in REL14 relocations")
scanned `sect.relocations` for `PpcRel14`. That coupled COMDAT layout to the
analyser's opinion about relocations, and the analyser was wrong. **Measured, the
bogus records were load-bearing**: the tracker fix alone, with this pass
unchanged, re-enabled COMDAT extraction on 2 dc3 objects — `Curl_resolv_unlock`
(`hostip.obj`) and `?QCcProcInitialize@MEC@@YAXXZ` (`qprocessing.obj`), both 0x9c.

It now decodes every `bc` in every code section directly out of the section bytes
(primary opcode 16, `AA = 0` ⇒ destination = site + sign_extend(BD‖0b00)) and
keeps a region whenever a branch crosses its boundary in either direction. The
instruction stream cannot go stale the way a relocation record can.

### 3.3 `xex.rs` — COMDAT regions NEST, and both lookups got it wrong

Not in the brief; found while explaining an unexpected result. `comdat_regions` is
a `BTreeMap` keyed `(section, start)`, and both containment lookups asked
`range(..=(sect, offset)).next_back()` — the single nearest region. Regions
**overlap**: dc3 `entropydec.obj` extracts `?prvDecodeFrameHeader@xWMA@@…` at
`[0x0, 0x600)` *and* `jumptable_82EA5A0C` at `[0xac, 0xd8)` inside it (the four
regions sum to 0x1a80 in a 0x19d0 `.text`). Asking about offset 0x200 finds the
jump table, sees 0x200 past its end, and answers "not in any region" — so an
ordinary intra-function branch reads as crossing a section boundary.

Measured cost of that mistake: with the naive lookup the new keep-back fired **19
spurious times across 9 dc3 objects** (`modelfittingstage.obj` alone lost 8
COMDATs). `build_comdat_region_index` + `comdat_region_containing` consider every
region and return the lowest-start one — which is where the real bytes end up,
because the extraction loop runs in ascending order and zeroes each region in the
parent after copying it. With the fix, dc3's changed-object count collapses 11 → 2.

The same helper now backs T4's `emitted_region` in the R1 emission rule, which had
the identical latent bug in the more dangerous direction (a false "same region"
verdict *drops* a needed relocation).

### 3.4 `xex.rs` — the out-of-section guard, and the encoded destination

Two hardenings of R1's drop test, both about not silently accepting a destination
that is not really there:

- **`dest_offset < sect.size`** (the guard the brief asked for). `symbol + addend`
  can land outside the section; a negative result wraps to a huge `u64` and an
  overlarge one is simply past the end. `emitted_region` answers `None` for both,
  which is indistinguishable from "in the parent section" — so an out-of-section
  destination compared EQUAL to a site in the parent `.text` and the record was
  dropped, deleting the one relocation that could still fix the branch.
- **Judge containment on the ENCODED displacement**, not on `symbol + addend`.
  They are allowed to disagree and routinely do — T2 §4 measured 182 of
  rb3-xenon's 634 REL14 records anchored on an address the `bc` does not branch
  to. Within one emitted section the instruction is authoritative (`write_coff`
  copies section bytes verbatim and has no `PpcRel14` arm in the data fixup).
  Without this, the keep-back change alone promoted **8 mis-anchored records into
  the objects** (REL14 17 → 24 on rb3-xenon); with it, 17 → **16**.

## 4. The negative result: "stop the walk" regresses, and the evidence

Implemented first, exactly as briefed — `EndBlock` on any `ins_addr` outside
`[function_start, function_end)`. dc3 was clean. rb3-xenon was not:

| arm | objects changed | relocation delta |
|---|---|---|
| bounds check (stop the walk) | **17** | −26 REFLO, −47 PAIR, −21 REFHI, −3 ADDR24, **0 added** |
| containment fix (landed) | **3** | +2 ADDR24, −1 ADDR24 |

Both measured against the same intermediate binary (COMDAT keep-back applied,
tracker varying), so the 17-vs-3 is the tracker change and nothing else.

The 94 lost records are **correct**. They are `lis`/`lfs` hi-lo pairs whose two
halves straddle a function boundary dtk carved in the wrong place:

```
EventTrigger.s, declared size 0x4 for a function that plainly continues:
  # .text:0x78 | 0x8249B200 | size: 0x4
  .fn fn_8249B200, global
  /* 8249B200  3D 60 82 01 */  lis  r11, lbl_82011658@ha     <- with the walk
  .endfn fn_8249B200
  /* 8249B204  81 43 00 CC */  lwz  r10, 0xcc(r3)
  /* 8249B208  2F 0A 00 01 */  cmpwi cr6, r10, 0x1
  /* 8249B20C  C0 0B 16 58 */  lfs  f0, lbl_82011658@l(r11)  <- with the walk

  with the bounds check the same two lines read
  /* 8249B200  3D 60 82 01 */  lis  r11, 0x8201
  /* 8249B20C  C0 0B 16 58 */  lfs  f0, 0x1658(r11)
```

`Color.obj` is the same shape across a real boundary: the `lis` sits in one
declared function and its `lfs` in `fn_824F5730`. Removing the records also stops
`write_coff` zeroing the in-place immediates, so those objects go back to carrying
raw XEX values with no relocation — a straight downgrade for a ruler that pairs on
relocation targets.

**The generalisable point:** hi/lo pairing, store classification and data-kind
inference are dataflow facts and do not depend on function bounds. Only the branch
question — "does this leave its function, and therefore need a relocation?" —
does. A bounds check on the whole callback throws the first away to fix the second.
That is why the landed fix narrows `is_function_addr` instead of ending the block.

## 5. A/B split parity — three projects

Old = `main` `c0cc506` built in this worktree (sha `aaee03bf…`, byte-identical to
the deployed splitter). New = this branch. Staging proven with `--verify-against`
on all three: **dc3 2223 identical / 0 different / 0 missing, rb3-xenon 3085 /
0 / 0, cea 3675 / 0 / 0** — 8,983 objects hashed against the trees the projects
actually score, and the check fired on all three.

### 5.1 dc3-decomp — 2 objects, both explained, zero relocation movement

| | value |
|---|---|
| objects | 2223 → 2223, 0 added, 0 removed |
| identical | **2221** |
| differ | **2**: `system/net/curl/lib/hostip.obj`, `xdk/nuiaudio/qprocessing.obj` |
| classification | `SECTION_LAYOUT\|SYMBOL_TABLE` in both |
| relocation record delta | **`{}` — nothing added, nothing removed, anywhere** |
| whole-tree totals | ADDR24 260052, PAIR 263873, REFHI 120891, REFLO 142982, ADDR32 165321, REL14 0 — **identical in both arms** |

**Determinism control: same binary, two runs, 2223/2223 byte-identical.** The
2-object delta is causal.

Both changed objects gain exactly one 0x9c COMDAT section:
`Curl_resolv_unlock` and `?QCcProcInitialize@MEC@@YAXXZ`. These are the two
regions the *bogus* REL14 was holding back. Neither contains a branch that leaves
it (§5.4), so extraction is safe and is what dtk intended for a symbol it has
listed in `comdat_symbols`.

At the site the campaign was convened for, the record is now never minted —
this is the tracker's own relocation set, upstream of any writer filter:

```
base:   RELOC 0x8256AAD0 PpcRel24 -> Curl_resolv        (+0x0)
        RELOC 0x8256AAFC PpcRel14 -> Curl_resolv_unlock (+0x34)   <-- the defect
        RELOC 0x8256AB08 PpcRel24 -> Curl_share_lock    (+0x0)
        RELOC DUMP: 7 relocation(s) in 0x8256AAB0..0x8256AB80
fixed:  RELOC 0x8256AAD0 PpcRel24 -> Curl_resolv        (+0x0)
        RELOC 0x8256AB08 PpcRel24 -> Curl_share_lock    (+0x0)
        RELOC DUMP: 6 relocation(s) in 0x8256AAB0..0x8256AB80
```

Nothing else in that window moved, and `Curl_resolv_unlock`'s own relocations are
all still there — the runaway walk was contributing nothing there but the bug.

**Two `.s` files improve** (`buildcfg.s`, `buildssa.s`), which is T2 §2's
"worse than the addend loss" pair — the record named a *different basic block*
than the instruction reaches:

```
- /* 82D51A30  41 98 FF E8 */  blt cr6, lbl_82D51A34     (record says +0x44)
+ /* 82D51A30  41 98 FF E8 */  blt cr6, .L_82D51A18      (instruction says +0x28)
```

The objects are unchanged there because T4's R1 rule already dropped those records
at emission; the listing is now honest as well.

### 5.2 rb3-xenon — 64 causal objects, and a nondeterminism floor that had to be measured first

**The rb3-xenon split is NOT deterministic.** The `c0cc506` binary run twice, from
separate pristine config copies, produces **8 differing objects**:
`BandCharacter`, `Gesture`, `HamPhotoDisplay`, `LayerDir`, `SkeletonClip`,
`auto_00_82000400_rdata`, `system/hamobj/PhotoSpotlightPositioner`,
`system/synth_xbox/Synth`. The signature is stable — `−7/+7` REFHI, `−7/+7`
REFLO, `−5/+5` ADDR32, 3 symbol-table-only — and it is a *naming* coin toss, not a
count change: whole-tree relocation totals are identical between the two base runs.
`?NewObject@PhotoSpotlightPositioner@@SAPAVObject@Hmx@@XZ` and `fn_8227B408` swap
places run to run. **This is a pre-existing defect in the deployed splitter,
unrelated to task 161, and it is why the numbers below are stated against BOTH
base runs.** It is also a trap: it cost this session an hour and a wrong
conclusion (§6). Anyone A/B-ing rb3-xenon at object granularity must run the
control.

| comparison | objects differing |
|---|---|
| base run 1 vs base run 2 (noise floor) | 8 |
| base run 1 vs candidate | 72 |
| base run 2 vs candidate | 64 |
| **differs from BOTH base runs (causal)** | **64** |
| differs from exactly one base run | 8 — *exactly the noise set, no overlap* |

Causal classification (base run 2 vs candidate, 3085 objects):

```
why:SECTION_LAYOUT|SYMBOL_TABLE                                    60
why:RELOC_ADDED_ADDR24|SECTION_DATA                                 1
why:RELOC_ADDED_ADDR24|SECTION_DATA|SYMBOL_TABLE                    1
why:RELOC_REMOVED_ADDR24|SECTION_DATA                               1
why:(everything — xdk/xgraphics/import.obj)                         1
```

Whole-tree relocation totals, base vs candidate:

| | ADDR24 | ADDR32 | PAIR | REFHI | REFLO | REL14 |
|---|---|---|---|---|---|---|
| base (both runs) | 219,239 | 83,164 | 201,191 | 90,585 | 110,606 | 17 |
| candidate | **219,240** | 83,164 | 201,191 | 90,585 | 110,606 | **16** |

So across 3,085 objects the entire relocation movement is **+1 ADDR24 and
−1 REL14**. Every one is named:

- **`Screenshot.obj` −1 ADDR24.** COMDAT region of `fn_823C8AC0`
  (VA 0x823C8964, size 0x58), offset 0x30 → the record targeted the region's own
  start symbol. The instruction there is `b .L_823C89A8`, an **intra-function**
  unconditional branch. This is the Rel24 analogue of the hostip REL14, the one
  T2 §5 predicted the writer-side rule could not reach. Removed.
- **`GemTrackResourceManager.obj` +1 ADDR24.** `.text+0xa48`, `b fn_8227CE58` —
  a genuine tail call that the stale bounds had mistaken for intra-function, so it
  carried **no** relocation and rendered as `b -0xd94fc`. Now relocated, and the
  in-place displacement rewritten to the MSVC `−offset_in_section` convention.
- **`system/rnddx9/ShaderMgr.obj` +1 ADDR24.** Same class, `.text+0x19f8` →
  `fn_827355D0`; the word goes `4bffff28` (raw XEX displacement) → `4bffe608`
  (= −0x19f8, the convention).
- **`xdk/d3dx9/d3dxmath.obj` −1 REL14.** `.text+0xa4 → lbl_82858E94`, T4's
  "17th survivor", the COMDAT-boundary case. The new keep-back holds the
  destination's region in the parent `.text`, so both ends share an emitted
  section, the encoded displacement is correct and the record is unnecessary.
  That is the strictly better outcome: INTEGRATION §6 gap 4 records that this very
  record keeps a stale pre-split in-place displacement, because `write_coff` has
  no `PpcRel14` arm in its data fixup.
- **60 objects `SECTION_LAYOUT|SYMBOL_TABLE`** and **`import.obj`**: the COMDAT
  keep-back set moved. Net +59 extracted COMDAT code sections (68,545 → 68,604).
  `import.obj` additionally shows `SECTION_DATA` and symmetric reloc adds/removes
  because a region that stops being extracted has its `PpcRel24` in-place
  displacements rewritten from `−offset_in_comdat` back to `−offset_in_parent`
  and its records move section — same records, different offsets.

**The 16 load-bearing REL14 survive as a SET, not a count**: all 16 are records
whose target symbol has `SectionNumber = 0`, i.e. a `bc` into another split unit,
which genuinely has no valid encoded displacement after the split. 0 dropped,
0 added.

### 5.3 cea-decomp — 2 objects

3675 → 3675, **3673 identical**, 2 differ (`lib/ui_gfx/cri_cs_win.obj`,
`xdk/nuiaudio/qprocessing.obj`), both `SECTION_LAYOUT|SYMBOL_TABLE`, relocation
record delta `{}`. `qprocessing.obj` is the same XDK unit that moved on dc3, which
is the expected cross-project consistency.

### 5.4 The COMDAT keep-back is now provably doing its job

`scripts/comdat_branch_audit.py` (this directory) asks a naming-independent,
byte-level question of the emitted objects: **does any extracted COMDAT code
section contain a `bc` (opcode 16, `AA = 0`) whose destination leaves that
section?** Extraction zeroes the region's bytes in the parent and applies no
fixup to a `bc`, so a yes is a branch the linker is free to break.

| tree | extracted COMDAT code sections | with an escaping `bc` |
|---|---|---|
| dc3 base | 68,949 | 0 |
| dc3 candidate | 68,951 | 0 |
| **rb3-xenon base (deployed)** | 68,545 | **1** |
| rb3-xenon candidate | 68,604 | **0** |

The one hit is `ProfileMgr.obj [/22 size=0x40] +0x2c  419affbc` — a `blt` whose
destination is 24 bytes *before* the extracted section, i.e. in dead zeroed space
in the parent. **The deployed splitter ships that object; this change fixes it.**
That is the answer to "what was the runaway walk providing, and did you preserve
it": it was providing an accidental, incomplete version of this protection, and
the replacement is both complete and independent of the analyser.

## 6. Implemented, measured, and deliberately NOT landed

**Suppressing the synthesized fall-through as a relocation target** (T2's second
trigger). `VM::step` builds the not-taken path of a `bc` as
`BranchTarget::Address(ins_addr + 4)`; when the `bc` is the last instruction of
its declared function that equals `function_end`, fails the exclusive
`is_function_addr` test, and is stamped with a Rel14 naming the instruction
*after* the branch. Skipping it removes 8 such records on rb3-xenon — the same 8
the encoded-displacement rule in §3.4 removes at the writer.

It is not landed because it buys nothing at the object level that §3.4 does not
already buy, and it perturbs `merge_fallthrough_leaf_fragments`
(`cmd/xex.rs:2049`), whose absorb decisions read "TRUE post-`tracker.apply`
reloc-target xref counts". Changing the tracker's relocation set changes symbol
merging, which changes emitted symbol names. **Caveat on that measurement,
recorded honestly:** the 15-object perturbation I first attributed to this change
was later shown to overlap the 8-object nondeterminism floor of §5.2, so its true
cost is smaller than first measured and possibly zero. It was not re-measured
after the floor was established, because the writer-side rule made the question
moot. A follow-up lane that wants it must A/B against **both** base runs.

Also not touched, and still open from the earlier session: the missing `PpcRel14`
arm in `write_coff`'s section-data fixup (the 16 survivors keep a stale in-place
displacement), and the rb3-xenon split nondeterminism itself — which deserves its
own task, since it means no two rb3-xenon splits are comparable at object
granularity without a control.

## 7. Tests

Baseline at the branch point (`c0cc506`), verbatim:

```
test result: ok. 163 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

This branch, verbatim:

```
test result: ok. 164 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.03s
```

The ignored one is still T5's DS-form hold, untouched. +1 is the new regression
test. `cargo test --lib` still does not exist in this crate (`[[bin]] dtk` only);
the command is `CARGO_TARGET_DIR=<private> cargo test --release --bin dtk`.

### 7.1 The regression test, proven red

`analysis::tracker::tests::walk_does_not_escape_function_end_into_the_next_function`
reproduces the hostip shape at toy addresses: `fn_a [0x1000,0x1010)` ending in a
tail `b` plus a `0x00000000` padding word, `fn_b [0x1010,0x1040)` containing an
intra-function `beq`. Only `fn_a` is handed to the tracker. It asserts both
directions — that the `b` out of `fn_a` is **still** recorded as
`Rel24 -> 0x1040` (a test that analysed nothing would pass without it), and that
nothing at all is recorded at an address `>= 0x1010`.

With `enclosing_function_bounds` disabled (`(function_start, function_end)`
substituted, one line), verbatim:

```
---- analysis::tracker::tests::walk_does_not_escape_function_end_into_the_next_function stdout ----
thread '...' panicked at src/analysis/tracker.rs:1364:9:
the walk of fn_a [0x1000,0x1010) escaped into fn_b and recorded 1 relocation(s) against fn_a's bounds: ["0:0x1018 -> Rel14(Address(0:0x1028))"]

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 164 filtered out
```

The fix was restored and the suite re-run green in the same command.

### 7.2 One existing test changed contract, on purpose

T4's `test_rel14_across_a_comdat_boundary_is_kept` asserted that a REL14 whose
destination lands in a COMDAT region the writer extracts **survives**, because the
record-derived keep-back could not see that case. The instruction-derived keep-back
can, and refuses to extract the region instead — both ends stay in the parent
`.text`, the encoded displacement stays correct, and no (malformed, un-fixed-up)
relocation is emitted. Renamed to
`test_comdat_region_reached_by_a_conditional_branch_is_kept_in_parent_text`, with
the old expectation and the reason it changed recorded in the doc comment.

It is still discriminating in both directions: a third COMDAT `func_c` that
nothing branches into **must still be extracted**, so the test now asserts
`comdat_section_sizes == [0x10]` as well as `REL14 == 0`. A rule that stopped
extracting COMDATs fails the first assertion; a blanket "never emit REL14" still
fails T4's other control, `test_rel14_to_external_symbol_is_kept`.

## 8. `INTEGRATION.md` §4.3 corrected: 16 of 17, not 17

The sentence read "all 17 survivors target a symbol not defined in the emitting
object". **Verified against the artifact before editing** — not against the doc.
The artifact is the deployed splitter's own output, `rb3-xenon/build/45410914/obj`,
read at the COFF record level: 17 `IMAGE_REL_PPC_REL14` records, of which 16 have
`SectionNumber = 0` (undefined) and one is **defined in its own object**,
`xdk/d3dx9/d3dxmath.obj .text+0xa4 -> lbl_82858E94`. That is the COMDAT-boundary
record §4.3 itself names two sentences earlier as "the 17th survivor" — the
sentence merged the two claims. T4-shape2-fix.md §3 had it right ("All **16**
target a symbol not defined in the emitting object").

A dated correction note is in place at §4.3 rather than a silent edit. It also
records that this task retires the 17th, so rb3-xenon now carries 16 REL14, all 16
undefined, and the sentence is true as written for the first time.

## 9. Caveat for whoever lands this

`main` moved during this session — it is now `7d9a761`
("Merge dsform-160: fix the DS-form decode on both sides"), which rewrites
in-place instruction bytes at 74 dc3 and 51 rb3-xenon REFHI/REFLO sites and
un-ignores T5's test (current `main` is 164 passed / 0 ignored). **Every number
above is measured against `c0cc506`**, which is what the three projects were
actually running. The two changes are disjoint in kind — DS-form moves section
bytes at REFHI/REFLO sites, this moves COMDAT layout and 3 branch records — but
they have not been measured together. Rebase onto `main` and re-run §5 before
deploying.

## 10. Artifacts

Committed here: `scripts/comdat_branch_audit.py`.

Reused from the previous session:
`../2026-08-12-splitter-reloc-addend/findings/scripts/{t4_obj_ab_diff.py,rel14_census.py}`
and `scripts/xex_split_ab_compare.sh`.

Gitignored scratch under `.worktrees/tracker-161/scratch/`:

- `bin/` — `dtk-base` (= `c0cc506`, = the deployed binary), `dtk-trackerfix`
  (bounds check only, §4), `dtk-keepbackonly` (writer only), `dtk-fix2`/`fix3`/
  `fix4`/`fix5` (the staging sequence; `fix5` is what this branch builds).
- `ab-dc3f/`, `ab-rb3x/{new,det2,kb,fix2,fix3,fix5}/`, `ab-cea/` — split outputs.
  `ab-rb3x/det2` is the determinism control, `ab-rb3x/kb` the intermediate that
  isolates the tracker change from the writer change.
- `ab-dc3det/` — the dc3 determinism control.
- `logs/` — every split and A/B log.
