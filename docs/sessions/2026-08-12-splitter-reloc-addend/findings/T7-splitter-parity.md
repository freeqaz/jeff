# T7 — splitter parity evidence: the license to replace `target/release/dtk`

Branch `jeff-t7` (off `jeff-t5`), worktree `.worktrees/t7`. Measured 2026-08-13 on
this box against the real dc3-decomp and rb3-xenon trees.

**Verdict: the REL14 half (T4) is licensed to deploy and is more than cosmetic —
a relink shows the deployed splitter's REL14 records make the LINKER rewrite 7
dc3 branch instructions away from their retail encoding. The DS-form half (T5)
is NOT licensed as it stands: the same relink answers T5's own open question —
MSVC's REFLO is ADDITIVE, so T5's `0x0002` in-place byte is added to the symbol
address and the one live dc3 site links to `ld` at displacement+2 where the
retail game has `lwa`.** Details in §6; recommendation in §7.

Deploy hazards, first. Every build used
`CARGO_TARGET_DIR=/home/free/code/milohax/jeff/.worktrees/t7/target-scratch`.
`/home/free/code/milohax/jeff/target/release/dtk` is **still `2026-08-08 22:32`,
8371016 bytes** at the end of this task — the deployed splitter was not written.
`objdiff/target/release/objdiff-cli` is still `2026-08-12 05:56` — the ruler was
not rebuilt either. Both games were split into scratch dirs under the worktree;
`build/373307D9` and `build/45410914` were only ever READ. No `report.json` was
consulted or regenerated. Nothing merged, nothing pushed, `main` untouched.

---

## 1. The two arms, and why they are named backwards in the harness output

| arm | binary | dtk version line |
|---|---|---|
| **BEFORE** (deployed) | `/home/free/code/milohax/jeff/target/release/dtk` | `dtk 1.11.0 30f75115655677fa56c7b68cc90de14b7a81ab74` |
| **AFTER** (candidate) | `.worktrees/t7/target-scratch/release/dtk` | `dtk 1.11.0 b204ebd893bdc6fc85bf1f5956e14900b009ee97` |

`30f7511` is `main`'s parent-of-the-harness-merge; `8a42efb` changes only
`scripts/xex_split_ab_compare.sh` (`git diff --stat 30f7511 8a42efb` = 1 file),
so the deployed binary is behaviourally `main`. `b204ebd` = `jeff-t5` = T3's
tests + T4's REL14 filter + T5's DS-form mask.

`xex_split_ab_compare.sh` verifies **only the `--new` side** against the
project's live objects, and the candidate deliberately differs from them. So the
run passes `--old <candidate> --new <deployed>`: the self-check then asks the
question that is actually falsifiable — *does this staging reproduce the project
byte-for-byte with the binary the project uses?* The per-object delta the harness
prints is symmetric, so nothing else is affected by the ordering.

## 2. The staging self-check FIRED, both games (hazard 6)

Verbatim from `logs/dc3-ab.log` and `logs/rb3x-ab.log` in the run dir:

```
[split-ab] verify vs /home/free/code/milohax/dc3-decomp/build/373307D9/obj: identical 2223, different 0, missing 0
[split-ab] staging is faithful: the new side reproduces the project byte-for-byte.

[split-ab] verify vs /home/free/code/milohax/rb3-xenon/build/45410914/obj: identical 3085, different 0, missing 0
[split-ab] staging is faithful: the new side reproduces the project byte-for-byte.
```

This is not a null: it is 5,308 objects hashed against the trees the projects
actually score, and it also **retires the "is the target tree stale?" worry for
the target half** — dc3's `build/373307D9/obj` is exactly what the deployed
splitter emits today (task #158's staleness is about the `src` side and
`report.json`, which this task never touched).

Both projects' `rule split` was replayed, not approximated:

- dc3: `--post-split 'python3 tools/prune_split_outputs.py "$SPLIT_OUT"'`.
- rb3-xenon: `--env JEFF_MERGE_PROTECT=scripts/target_symbol_map.json` plus
  `prune_split_outputs.py` **and** `scripts/obj_target_symbol_renamer.py --batch
  --apply --obj-dir "$SPLIT_OUT/obj"` (T6 finding 1: the renamer rewrites 1,822
  of 3,085 objects; without it the arms differ for a non-splitter reason).

T4's symbols-file confound is handled structurally: the harness stages a
**separate pristine copy** of `config/<id>/` per arm and runs each arm exactly
once, so `dtk`'s in-place symbols-file rewrite lands identically on both sides.
The 2223/3085 byte-for-byte reproduction is the proof that it did.

**Control.** T4 used "same binary twice → identical". This run has a stronger
one for free: the BEFORE arm reproduces an independently-produced tree exactly,
so the pipeline is deterministic *and* faithful, and every delta below is
attributable to the binary swap.

## 3. (a) Per-object byte deltas — complete, and every entry explained

Classifier: `findings/scripts/t4_obj_ab_diff.py` (T4's, unchanged) plus this
task's `scripts/coff_reloc_parity.py objdiff`, which enumerates the actual
records. Full per-object tables: `work/dc3-changed-objects.txt`,
`work/rb3x-changed-objects.txt`.

| game | objects | identical | differ | adds/removes |
|---|---|---|---|---|
| dc3 | 2223 | 2217 | **6** | 0 / 0 |
| rb3-xenon | 3085 | 2897 | **188** | 0 / 0 |

Zero section-layout changes and zero symbol-table changes on either game.

### dc3 — all 6, individually

| object | what differs | records |
|---|---|---|
| `xdk/nuiapi/nuiruntime.obj` | `RELOC_REMOVED_REL14` | −2: `.text+0x49a0 42400234 → lbl_829CE124`, `.text+0x49a4 42400230 → lbl_829CE124`, both inside `?NuipCameraReady@@YAHH@Z` |
| `xdk/nuiaudio/qprocessing.obj` | `RELOC_REMOVED_REL14` | −1: `.text+0x94 4200ffe8 → ?QCcProcInitialize@MEC@@YAXXZ` (target IS the enclosing function) |
| `xdk/xgraphics/buildcfg.obj` | `RELOC_REMOVED_REL14` | −2: `.text+0x30 40820044 → fn_82D51A64`, `.text+0x40 4198ffe8 → lbl_82D51A34` (T2's fall-through-anchored pair: the record names a *different* basic block than the instruction branches to) |
| `xdk/xgraphics/buildssa.obj` | `RELOC_REMOVED_REL14` | −2: `.text+0x148 40820048 → fn_82D4FFE0`, `.text+0x158 4198ffe8 → lbl_82D4FFAC` |
| `system/net/curl/lib/hostip.obj` | `RELOC_REMOVED_REL14` | −1: `.text+0x53c 419a0010 → Curl_resolv_unlock` — README §1.1's Shape 2, G36 |
| `system/gesture/ArcDetector.obj` | `SECTION_DATA` | 0 records; **1 byte**: COMDAT `/53` +0x827 `00 → 02`, i.e. the instruction word `e96b0000 → e96b0002` (`ld` → `lwa`). This is T5's site. Its REFLO and PAIR records are unchanged in offset, type and target (`lbl_82F446EE`, `@comp.id`); only the in-place word moved. (`coff_reloc_parity.py objdiff` keys records on their in-place word too, so it prints this one pair as removed+added — that is the tool's key, not a record change.) |

Total: **−8 REL14 records, 0 added, 1 section-data byte.** dc3's REL14 count goes
8 → 0, which is what the compiler does (0 REL14 in 989 compiler objects, T6/FINDING 3).

### rb3-xenon — all 188

Every one of the 188 has exactly one difference class, `RELOC_REMOVED_REL14`:
**−633 REL14 records, 0 added, 0 section-data bytes, 0 symbol-table bytes.**
The complete object list with per-object counts is `work/rb3x-changed-objects.txt`
(188 lines, `-REL14:n data_bytes=0` each). rb3-xenon has **no** DS-form site with
XO≠0 (T5 measured 0 of 51), so T5 moves nothing there — predicted before the run
and measured after it.

**650 → 17, not T4's 643 → 17.** T4's baseline arm ran on a symbols file that a
previous split had already converged, which suppressed 7 records in 5 objects;
this run gives both arms a pristine copy and one run each, so the BEFORE arm
reproduces the project's live 650 exactly (§2). Hence 188 changed objects rather
than T4's 183, and −633 rather than −626. The extra 5 objects and 7 records are a
*baseline* difference, not a candidate difference.

## 4. (b) Record-level confirmation with `coff.py`

Instrument: `scripts/coff_reloc_parity.py` (this task, committed on `jeff-t7`),
which imports `load`/`relocs` from the campaign's own
`decomp-bench/archive/runs/2026-08-12-gap-bug-hunt/work/review/coff.py` and adds
one 6-line reader for the COFF symbol `Type` field, which `coff.py` drops and the
REL14 classifiers need. Raw output: `work/shape.txt`, `work/shape2.txt`.

### REFHI/REFLO + PAIR shape — unchanged, and identical to compiler form

| tree | REFHI | REFLO | PAIR | PAIR displacement = 0 | shape violations |
|---|---|---|---|---|---|
| dc3 BEFORE (deployed split) | 120,891 | 142,982 | 263,873 | 263,873 | **0** |
| dc3 AFTER (candidate split) | 120,891 | 142,982 | 263,873 | 263,873 | **0** |
| dc3 OURS (compiler, 989 obj) | 159,741 | 182,645 | 342,386 | 342,386 | **0** |
| rb3-xenon BEFORE | 90,585 | 110,606 | 201,191 | 201,191 | **0** |
| rb3-xenon AFTER | 90,585 | 110,606 | 201,191 | 201,191 | **0** |
| rb3-xenon OURS (compiler, 1204 obj) | 297,804 | 352,227 | 650,031 | 650,031 | **0** |

"Shape violations" is checked, not assumed: exactly one PAIR immediately follows
each REFHI and each REFLO, at the same offset, with `SymbolTableIndex` (the
*displacement* channel, PE/COFF; `xex.rs:2468-2471`) equal to 0; no orphan PAIR;
no missing PAIR. `PAIR == REFHI + REFLO` in all six trees.

The in-place immediate at every REFHI/REFLO site, split by instruction form:

| tree | D-form sites | imm = 0 | DS-form sites | displacement[15:2] = 0 | XO ≠ 0 |
|---|---|---|---|---|---|
| dc3 BEFORE | 263,799 | **263,799** | 74 | **74** | 0 |
| dc3 AFTER | 263,799 | **263,799** | 74 | **74** | **1** |
| dc3 OURS | 342,347 | **342,347** | 39 | **39** | **3** |
| rb3-xenon BEFORE | 201,140 | **201,140** | 51 | **51** | 0 |
| rb3-xenon AFTER | 201,140 | **201,140** | 51 | **51** | 0 |
| rb3-xenon OURS | 649,967 | **649,967** | 64 | **64** | **3** |

The one AFTER-arm XO≠0 site is `system/gesture/ArcDetector.obj /53 +0x824
e96b0002` — the same shape the compiler emits in its own `ArcDetector.obj`
(`.text +0x24/+0x14c/+0x7bc`, `e96b0002`/`e97f0002`). **This also corrects
FINDING 2 in passing**: its "in-place immediate nonzero in 3 of 342,386" is not
three stray addends — those 3 *are* the DS-form XO bits. The compiler's
displacement field is zero in 342,386 of 342,386. Under the candidate the
splitter matches that convention exactly; under the deployed binary it does not.

### REL14 — three witnesses, because one of them lies on the survivors

| tree | REL14 | same-section | cross-section | W1 intra-fn | W2 intra-fn | W3 intra-fn |
|---|---|---|---|---|---|---|
| dc3 BEFORE | 8 | 8 | 0 | 2 | 6 | 8 |
| dc3 AFTER | **0** | 0 | 0 | **0** | **0** | **0** |
| rb3-xenon BEFORE | 650 | 634 | 16 | 59 | 95 | 634 |
| rb3-xenon AFTER | **17** | 1 | 16 | **0** | 10 | **1** |
| dc3 / rb3-xenon OURS | 0 | – | – | 0 | 0 | 0 |

- **W1** = the relocation's target symbol IS the function symbol enclosing the
  site (FINDING 3's classifier). **0 in both AFTER trees.**
- **W2** = the *encoded* branch destination lands inside the enclosing function
  (T2's classifier). It reads 10 on the AFTER rb3-xenon tree, and those 10 are a
  classifier artifact: all 17 survivors target a symbol **not defined in the
  emitting object** (16 cross-section `bc`s into another split unit, plus the one
  COMDAT-boundary case T4 captured at `xdk/d3dx9/d3dxmath.obj .text+0xa4`), so
  their encoded displacement is a stale pre-split value the linker overwrites —
  it is not a statement about where the branch goes after linking.
- **W3** = target symbol defined in this object at all. 1 on the AFTER tree, the
  COMDAT-boundary survivor, which is kept deliberately (T4's discriminating
  negative control).

So: **intra-function REL14 is 0 in both games' candidate trees under the
naming-independent witness and under the defined-in-object witness**, and the 16
load-bearing cross-section records survive as a set (T4 verified the set keyed on
object/offset/word/target; this run reproduces the count 16 → 16 with 0 added).

## 5. (c) objdiff report A/B — one ruler, per symbol, every move explained

**Ruler: the deployed `~/.local/bin/objdiff-cli` → `objdiff/target/release/objdiff-cli`,
built 2026-08-12 05:56, used for BOTH arms.** T1 has **not** landed a new
objdiff — the deploy path's mtime is unchanged and T1 explicitly recorded that it
banked binaries in a private `CARGO_TARGET_DIR` and deployed nothing. So the
single ruler is the one the projects use today. (T1's account of what the *ruler*
swap does is separate and still pending its own deploy; the two must not be
landed in one step, or neither parity account is readable.)

Method: four shadow project dirs, each a directory of symlinks — real
`objdiff.json`, real `build/<id>/src`, real `icf_aliases.map`, and
`build/<id>/obj` pointing at that arm's scratch tree. Both arms therefore read
the **same base objects and same alias map**; the target tree is the only
variable. One `-o` path per arm (the report `.cache` sidecar does not key on its
inputs); all four runs logged `Report cache: 0 hits`. Both projects ship
`functionRelocDiffs: name_check`, which the report path honours.

| project | units | symbols compared | unit skew | symbol skew | moved | up | down |
|---|---|---|---|---|---|---|---|
| dc3-decomp | 2224 | 48,344 | 0 | 0 | **2** | 2 | 0 |
| rb3-xenon | 3085 | 69,231 | 0 | 0 | **23** | 21 | **2 (see below)** |

Project measures:

| measure | dc3 before → after | rb3-xenon before → after |
|---|---|---|
| `matched_code` | 4,856,756 → **4,856,912** (+156) | 3,354,928 → **3,356,768** (+1,840) |
| `matched_code_percent` | 42.702670 → **42.704044** | 32.506813 → **32.524640** |
| `matched_functions` | 29,392 → 29,392 | 44,285 → 44,285 |
| `fuzzy_match_percent` | 53.884937 → 53.884937 | 48.282253 → 48.282253 |
| everything else | unchanged | unchanged |

### dc3 — 2 moved, both up

| unit | symbol | fuzzy | normalized | why |
|---|---|---|---|---|
| `system/net/curl/lib/hostip` | `Curl_resolv_unlock` | 99.871796 → **100.0** | 100 → 100 | the G36 REL14 is gone; the `beq` now reads its own displacement instead of `symbol+0`. +156 bytes of `matched_code` — the whole function. |
| `system/gesture/ArcDetector` | `?UpdateOverlay@ArcDetector@@QAAMPAVRndOverlay@@M@Z` | 71.931480 → **71.933334** | 73.62592 → 73.62778 | T5's DS-form site: target row `ld` → `lwa`, matching the base. Δ +0.00185 reproduces T5's Δ exactly (T5 quoted 71.83148 → 71.83334 from a single-symbol CLI diff; the report path's absolute is 0.1 higher, the delta is identical). |

### rb3-xenon — 21 up, 2 disclosed partial-credit rows down

The 21 upward rows are all the same shape: a function whose target body carried a
spurious REL14 that rendered a branch operand as `symbol+0`; with the record gone
the operand is the encoded displacement and the row matches. 15 of them reach
`fuzzy = 100`, and their sizes sum to exactly the +1,840 `matched_code`. **No
function on either game crosses `match_percent_normalized` into 100** (0 on dc3,
0 on rb3-xenon), so unlike T1's ruler deploy this one does not move the
`normalized == 100` selection population the gap-bug-hunt lane samples from.
The largest single move is +0.33334
(`??$_Copy_Construct@UBoneOp@CharSignalApplier@@…`, 99.666664 → 100). Full list:
`work/rb3x-report-ab.txt`, machine-readable in `work/rb3x-symbol-delta.json`.

The two downward rows are the only ones in the whole account and both need saying
plainly:

| unit | symbol | raw (`fuzzy`) | normalized |
|---|---|---|---|
| `default/HttpGet` | `?GetNextLine@?A0xaf4cfd2b@@YAPADPADPAH@Z` | 0.0 → 0.0 | 1.875 → **0.0** |
| `default/ProfileMgr` | `fn_82545AFC` | 0.0 → 0.0 | 0.71428573 → **0.0** |

Both are **unmatched in both arms** — raw match 0.0% before and after, 0 bytes of
`matched_code` either way, `matched_functions` unchanged. What moved is
`match_percent_normalized`, the arg-forgiving presentation metric: 15 of 800 and
5 of 700 diff-score points respectively (1.875% = 15/800, 0.714% = 5/700).

- `fn_82545AFC` is **explained mechanically**. It is `fn_<8 hex>`, so
  `is_funclet_like` accepts it and it is eligible for objdiff's funclet
  byte-signature pairing. `funclet_signature`
  (`objdiff-core/src/diff/mod.rs:840-867`) **zeroes the whole 4-byte instruction
  word at every relocation address inside the symbol**. In the BEFORE arm the two
  spurious REL14 records masked the two `beq` words, the masked signature
  collided with an unrelated base funclet, and the pair was formed — the report
  row carries `masked_equal: true`, objdiff's own disclosure that the identity
  rests on a masked byte signature. With the records gone the words are no longer
  masked, the signature no longer collides, and the spurious pairing disappears
  (`masked_equal` count 24,391 → 24,390, one lost, none gained). The BEFORE
  credit was manufactured by the splitter's own invented relocation.
- `?GetNextLine…` is **explained by class, not to the row**. The only input change
  to `HttpGet.obj` is the removal of 3 REL14 records (§3), and the effect
  reproduces at unit grain (a 2-unit shadow project gives the same 1.875 → 0.0),
  so causality is not in doubt. In the BEFORE arm its three branch rows are
  charged `diff_arg` because the operand renders as a relocation target name
  (`beq cr6, fn_827DC120` vs base `beq cr6, 0x90`), and `normalized` forgives
  arg-only differences — those three rows were its entire 1.875%. I could not
  reproduce the row-level accounting through `objdiff-cli diff`, which reports
  0.0/0.0 in **both** arms even with `-c functionRelocDiffs=name_check`: the
  oneshot path is a different ruler configuration (T1's side finding,
  `objdiff-cli/src/cmd/diff.rs:849`). Stating that gap rather than papering over
  it. The target symbol is a 32-byte fragment against a 152-byte base — a
  carving problem, not a scoring one.

**Zero unexplained movements. Zero downward movements in any admission-relevant
metric** (raw match, matched_code, matched_functions, symbols at 100). Two
downward movements in the arg-forgiving presentation metric, both on symbols that
match nothing in either arm, both traceable to credit the artifact created.

## 6. (d) The split still links — and the relink is the most informative thing here

dc3's `rule msvc_link` links **1,256 split target objects** alongside 968
compiled `src` objects (`build/373307D9/default.exe.rsp`), so this is an
in-pipeline check, not a synthetic one. Linker: the project's own
`build/compilers/X360/16.00.11886.00/link.exe` under `wibo`. Both arms were
linked from a shadow tree of symlinks; nothing was written into either project.

**Run 1 — the project's own link line, unmodified.** Both arms: exit 96, and the
diagnostics are **byte-identical** (`diff` of the two logs, modulo the output
path, is empty; 15,063 LNK lines each). The failure is pre-existing and unrelated
— `LNK1120: 51 unresolved externals` from our *source* objects (`createFilter`,
`lbl_830A1218`, a vtordisp thunk, …). **No `LNK2013`, no `LNK1223` in either
arm**: the linker parsed and fixed up all 1,256 split objects without a
malformed-relocation complaint.

**Run 2 — `/FORCE:UNRESOLVED` added, plus the two changed objects the real link
line does not carry** (`obj/system/gesture/ArcDetector.obj`,
`obj/system/net/curl/lib/hostip.obj`, prepended so `/FORCE:MULTIPLE` picks the
target copy). Both arms **link successfully, exit 0**, producing a 26,654,208-byte
image and a full `.map`. Diagnostics identical again (15,213 LNK lines, same
codes: 14,939 × LNK4006 multiply-defined, 125 × LNK4210, 113 × LNK2001,
35 × LNK2019, 1 × LNK4088 — all expected under `/FORCE`). The two `.map` files
are identical except the timestamp, the output path and the debug-directory size:
**symbol layout is unchanged.**

The two images differ in **28 bytes** (`work/link_image_bytediff.txt`): 2 in the
PE header (timestamp), 12 in `.rdata` (the embedded `…before.pdb` / `…after.pdb`
string, an artifact of my `/OUT:` names), and **14 in `.text`, forming 8
instruction words**:

| VA in image | before | after | site |
|---|---|---|---|
| 0x82542854 | `419a0528` | **`419a0010`** | hostip `Curl_resolv_unlock` |
| 0x82cdb8f0 | `42404e08` | **`42400234`** | nuiruntime `?NuipCameraReady` |
| 0x82cdb8f4 | `42404e04` | **`42400230`** | nuiruntime `?NuipCameraReady` |
| 0x82fa4f80 | `408201d8` | **`40820048`** | buildssa `?FindSetBit@…` |
| 0x82fa4f90 | `41980144` | **`4198ffe8`** | buildssa `?FindSetBit@…` |
| 0x82fa6a08 | `408200b8` | **`40820044`** | buildcfg `??$FindSetBitInArray@I@…` |
| 0x82fa6a18 | `4198002c` | **`4198ffe8`** | buildcfg `??$FindSetBitInArray@I@…` |
| 0x830746b8 | `e96b5566` | `e96b5568` | ArcDetector `?UpdateOverlay@…` (DS-form) |

**Rows 1–7 are the case for deploying T4, and they are stronger than the objdiff
account.** In each, the AFTER word is exactly the word in the split object — and
the split copies the XEX bytes verbatim for a `bc` (`write_coff` has no
`PpcRel14` arm in its section-data fixup, `xex.rs:2139`), so the AFTER image
carries the **retail instruction**. The BEFORE image does not: the linker
consumed the spurious REL14 record and rewrote the displacement. T2 flagged this
as a risk ("its `A` stays as the original `target − site` and the linker would
add it on top of its own computation") and left it unmeasured. It is now
measured, and it fires at 7 of dc3's 8 REL14 sites. The 8th
(qprocessing `.text+0x94`, `4200ffe8`, target = its own enclosing function) is
`4200ffe8` in **both** images — the linker's recomputation happened to coincide
with the encoded displacement, so removing the record changed nothing there. The
symbol is in both maps (`?QCcProcInitialize@MEC@@YAXXZ … qprocessing.obj`), so
this is a coincidence at a linked site, not an unlinked one.

**Row 8 answers T5's open question, and the answer is bad for T5 as landed.**
T5 wrote: *"If MSVC's REFLO is additive … the two defects were compensating at
this site … If REFLO replaces the field, the fix is link-neutral. Nobody has
relinked."* The relink says **additive**: the linked low half moves by exactly the
in-place byte, `0x5566 → 0x5568` (+2 = T5's `0x0002`). Consequences at that site:

- BEFORE: object word `e96b0000` + symbol `lbl_82F446EE` → linked `…5566`,
  XO = 2 → **`lwa`**, the retail instruction. Wrong object, right link — the
  DS-form zeroing and the 2-byte-off address decode cancelled.
- AFTER: object word `e96b0002` + the same symbol → linked `…5568`, XO = 0 →
  **`ld`**, at displacement + 2. Right object, **wrong link**.

The root cause is the one T5 found and left on the floor: the analysis side
decodes the DS-form EA as `hi<<16 | lo` and mints `lbl_82F446EE`, where the real
target is `sDefaultHoverTimer` at `0x82F446EC` (`hi<<16 | (lo & ~3)`). Until that
decode is fixed, the DS-form mask converts a right-linking wrong object into a
wrong-linking right object.

Scope check, so this is not overstated: `ArcDetector.obj`'s *target* object is not
in dc3's real link line (that unit is decompiled, so the `src` object is linked
instead) — I had to inject it to exercise the site. dc3's shipped link is
therefore unaffected either way, which run 1 already showed.

## 7. Recommendation to the integrator

**Split the deploy. Land T4 now; hold T5 for one more task.**

1. **DEPLOY the REL14 filter (T4, `f830e16`).** It is licensed by every leg of
   this account: staging proven faithful on 5,308 objects; the only object-level
   difference in all 194 changed objects is removed REL14 records; REFHI/REFLO +
   PAIR record shape is record-for-record identical to compiler form and
   unchanged by the patch; intra-function REL14 goes to 0 on both games under
   the naming-independent witness; per-symbol objdiff movement is 2 up on dc3 and
   21 up / 2 disclosed-partial-credit-down on rb3-xenon, with zero unexplained;
   the link is clean and, at 7 dc3 sites, **fixes a real corruption of the linked
   image**.
2. **HOLD the DS-form mask (T5, `b204ebd`) until the address decode is fixed.**
   Land it together with the `tracker.rs`/`cfa.rs` fix that makes the DS-form
   target `sDefaultHoverTimer` (`0x82F446EC`) instead of `lbl_82F446EE`, then
   relink and re-check that word — the check is cheap now, the harness for it is
   in `link/` in the run dir. Landing T5 alone trades an objdiff row worth
   +0.00185 fuzzy on one dc3 function for a linked instruction that is wrong.
   (If the integrator prefers to land both at once anyway, the deviation must be
   written down: dc3's shipped link does not include that object, so nothing in
   the current pipeline breaks — but the splitter would be knowingly emitting an
   object that mislinks.)
3. **Version bump, per repo convention (`287a322`: objects changed ⇒ bump).**
   `Cargo.toml` `1.11.0 → 1.12.0`, with the counts in the message: T4-only is
   dc3 5 objects / −8 REL14 and rb3-xenon 188 objects / −633 REL14 (the ArcDetector
   object drops out of dc3's count if T5 is held). Regenerate every consumer's
   `report.json` after the deploy — do not diff a number across the boundary.
4. **Sequencing with T1.** Deploy the splitter and the ruler in **separate**
   steps with separate parity accounts. This account is measured against the
   ruler the projects run today (05:56 binary); T1's is measured against today's
   object trees. Landing both at once makes both accounts unreadable.

## 8. Artifacts and how to re-derive

Run dir: `decomp-bench/archive/runs/2026-08-13-splitter-parity-t7/`

```
logs/dc3-ab.log, logs/rb3x-ab.log      harness output incl. the staging self-check
work/dc3-objdelta.txt, rb3x-objdelta.txt   t4_obj_ab_diff.py classification
work/{dc3,rb3x}-changed-objects.txt    COMPLETE per-object delta table (6 / 188)
work/{dc3,rb3x}-record-delta.json      every added/removed record, with words
work/shape.txt, work/shape2.txt        REFHI/REFLO/PAIR/REL14 shape census, 6 trees
work/{dc3,rb3x}-report-ab.txt          per-symbol objdiff A/B
work/{dc3,rb3x}-symbol-delta.json      the same, machine-readable
work/link_image_bytediff.txt           all 28 differing bytes of the linked images
work/coff_reloc_parity.py, t7_report_ab.py   the two tools
link/link-{before,after}.log           stock link line, both arms
link/link2-{before,after}.log/.map     forced link, both arms
reports/{dc3,rb3x}-{before,after}.json 4 full objdiff reports (gitignored payload)
```

Split trees (gitignored, ~1.2 GB, in the worktree):
`.worktrees/t7/scratch/{dc3-ab,rb3x-ab}/{new,old}/out/obj` — `new` = BEFORE
(deployed), `old` = AFTER (candidate).

Commands, in order: the two `scripts/xex_split_ab_compare.sh` invocations in §2;
`findings/scripts/t4_obj_ab_diff.py <before_obj> <after_obj>`;
`scripts/coff_reloc_parity.py shape <tree>…` and `… objdiff <before> <after>`;
`objdiff-cli report generate -p <shadow> -o <arm>.json` ×4;
`findings/scripts/t7_report_ab.py <before.json> <after.json>`; the two
`wibo …/link.exe /NOLOGO @<rsp>` runs.

## 9. Not done, on purpose

- No deploy. `target/release/dtk` mtime is unchanged; that step is the
  integrator's.
- No `objdiff-cli` rebuild and no ruler swap (T1's lane).
- No `report.json` regenerated in either project (hazard 5); the before arm is a
  report generated in-session, not a remembered number.
- rb3 (Wii/mwcceppc/ELF) and cea-decomp are untouched: this change is in the
  PPC-COFF writer, and rb3's objects come from the ELF writer (FINDING 4).
  cea-decomp is also dtk-split X360 and **is** in this change's blast radius by
  construction; it was not measured here and should be either measured or
  explicitly accepted before the deploy.
- The `tracker.rs` root-cause fix (T2/T4 §4) and the COMDAT keep-back rework it
  needs. Separate task, separate parity account.
