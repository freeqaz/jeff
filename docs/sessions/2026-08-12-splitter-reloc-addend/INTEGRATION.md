# INTEGRATION — splitter relocation campaign

Integrator readout, 2026-08-13. Branch **`jeff-integration`**, worktree
`/home/free/code/milohax/jeff/.worktrees/integration`, based on `main` = `8a42efb`.

**Verdict in one paragraph.** Six of seven workstreams land in full. T5's DS-form
code lands and is then **reverted**, on evidence, with its measurement and its
history kept. The integrated splitter is licensed to replace
`/home/free/code/milohax/jeff/target/release/dtk` — the parity account holds on
three projects and 8,983 objects, and a relink shows the change fixes a real
corruption of the linked image rather than only a scoring artifact — but the
binary was **NOT deployed in this session**, because the integrator may not land
on `main` and deploying a ruler whose source is not on `main` is silently
reversible by the next `cargo build` in the main checkout. Deploy after the merge;
the exact steps are in §8.

Nothing was pushed. `main` was not committed to in any repo. Deploy paths at the
end of this session: `jeff/target/release/dtk` still `2026-08-08 22:32:10`,
8,371,016 bytes; `objdiff/target/release/objdiff-cli` still `2026-08-12 05:56`.
Every build used `CARGO_TARGET_DIR=<this worktree>/target-scratch`.

---

## 1. What merged

All seven engineer branches were merged with `git merge --no-ff`, in dependency
order, each with a message saying what that workstream set out to do, what it
found, and what it deliberately did not do. **No cherry-pick, no squash, no
`--ff-only`** — the intermediate commits, including T2's ruled-out hypothesis and
T4's two false parity accounts, are the point.

| branch | commit | merge | what it contributes |
|---|---|---|---|
| `jeff-t3` | `50aa582` | `050eec3` | 3 regression tests, red before the fix |
| `jeff-t4` | `f830e16` | `9d6e0db` | **the REL14 emission rule (R1)** — the deployable fix |
| `jeff-t5` | `b204ebd` | `bf273b9` | DS-form mask — **code reverted, see §2** |
| `jeff-t7` | `3bf1c0c` | `0d1f9b1` | `scripts/coff_reloc_parity.py`, the record-level instrument |
| `jeff-t1` | `ca7543f` | `342a547` | ruler-parity findings + 2 analysis tools (evidence only) |
| `jeff-t2` | `3f8d8f6` | `c7f54fe` | REL14 root cause + 2 census scripts (evidence only) |
| `jeff-t6` | `1aebd75` | `bf96832` | self-reference census + `selfref_census.py` (evidence only) |

**Zero merge conflicts.** T3/T4/T5/T7 are a linear stack, so each merge added
exactly its own commit; T1/T2/T6 touch only `docs/sessions/…` paths that do not
exist on `main`. Nothing had to be resolved on the merits, and no engineer's text
was edited during a merge.

Three integrator commits follow the merges:

- `503afb5` — **commit the session record itself.** `git ls-files docs/sessions/`
  was empty for the whole campaign, so README.md, NOTES.md and four findings
  documents (T3, T4, T5, T7) existed only as untracked files in the main
  checkout. They are now in git, together with `t4_obj_ab_diff.py` and
  `t7_report_ab.py` and a `.gitignore` for the 667 MB of scratch. T1's and T2's
  committed copies were byte-compared against the main checkout's untracked ones
  first — identical, so nothing forked silently.
- `dbc887a` — **revert T5's code**, §2.
- `8b1b75a` — **version bump 1.11.0 → 1.12.0**, repo convention (`287a322`).

### The one thing that is NOT a conflict but will look like one

The main checkout still holds **untracked** copies of every path under
`docs/sessions/2026-08-12-splitter-reloc-addend/`. `git merge` refuses to
overwrite an untracked file, so merging this branch there will abort until those
are cleared. They are identical to what is committed here. T3 predicted this in
its process note; it is handled rather than rediscovered. See §8 step 1.

---

## 2. What did NOT land, and why: T5's DS-form mask

T5's **measurement** is correct, important, and kept. Its **code** is reverted.

What T5 got right, and it stands: `insn & 0xFFFF0000` in `write_coff`'s
`PpcAddr16Ha|PpcAddr16Lo` arm clears bits [1:0], which on a DS-form instruction
(primary opcode 58 `ld/ldu/lwa`, 62 `std/stdu`) are opcode extension, not
displacement. It **fires on dc3 retail** at `system/gesture/ArcDetector` `.text
+0x824` (VA `0x82E025AC`): `0xE96B46EE` `lwa` is emitted as `0xE96B0000` `ld`.
T5 also correctly retired FINDING 8's "never fired" evidence, which rested on a
grep pattern (`^\s+lwa\s`) that cannot match a dtk asm line — it returns 0 for
`lwz` and `stw` on dc3 too.

Why it is reverted: T5 flagged its own open question — *is MSVC's REFLO additive,
in which case the writer defect and a second defect one layer up were
compensating?* — and said nobody had relinked. T7 relinked. **I verified T7's two
linked images byte-for-byte myself rather than taking the readout's word for it:**

```
28 bytes differ between link2-before.exe and link2-after.exe.
At image file offset 0x0106f4b8:  before e96b5566   after e96b5568
```

The linked low half moves by exactly the in-place `0x0002`. **REFLO is additive.**
Decoding both against the retail instruction (`build/373307D9/asm/system/gesture/
ArcDetector.s:2704` — `/* 82E025AC … E9 6B 46 EE */ lwa r11, lbl_82F446EE@l(r11)`):

| arm | object word | + anchor `lo(0x82F446EE)` | linked field | XO | instruction |
|---|---|---|---|---|---|
| deployed | `e96b0000` | `0x0000 + 0x46EE` | `0x46EE` | 2 | **`lwa`** — retail |
| with T5 | `e96b0002` | `0x0002 + 0x46EE` | `0x46F0` | 0 | **`ld`** at disp + 2 |

The deployed splitter is right at link time only because two bugs cancel. The
root cause is the one T5 found and left on the floor: the analysis side decodes
the DS-form EA as `hi<<16 | lo` and mints `lbl_82F446EE`, where the real target is
`sDefaultHoverTimer` at `0x82F446EC` (`hi<<16 | (lo & ~3)`) — and that is baked
into dc3's checked-in `config/373307D9/symbols.txt`.

**The trade, stated so it can be argued with.** Holding costs one objdiff row on
one dc3 function (+0.00185 fuzzy on `?UpdateOverlay@ArcDetector@@…`, a row no
source can ever win because the ruler demands an instruction the retail game does
not contain). Landing costs a linked instruction that is a different opcode from
retail. The scope is symmetric and tiny — exactly **one** dc3 DS-form site has
XO ≠ 0, rb3-xenon has zero, and that object is not in dc3's shipped link line — so
neither effect is felt today. With the effects that close, the tie goes to not
knowingly emitting an object that mislinks.

T3's `ds_form_immediate_zeroing_must_preserve_xo_bits` therefore returns to
failing and is marked `#[ignore]` with the entire argument on the test, **not
deleted and not weakened** (per T3's own instruction). `cargo test --bin dtk --
--ignored ds_form` reproduces the red on demand; it does, and the output is in §4.

**Follow-up, one task not two:** fix the analysis-side DS-form address decode,
un-ignore the test, restore the revert, relink once and check the word at image
VA `0x830746b8`. The relink harness is in the T7 run dir.

---

## 3. Corrections to the returned readouts

Measurement overrules the briefs, including the ones the engineers wrote.

1. **T7's "explained by class, not to the row" for `?GetNextLine@…` is now
   measured to the row.** T7 could not interrogate it because the oneshot
   `objdiff-cli diff` path uses a different ruler (T1's side finding,
   `cmd/diff.rs:849`). Running it anyway on both arms and reading the *rows*
   rather than the percentages is decisive:

   | arm | non-insert row classes |
   |---|---|
   | before | 5 `equal`, **3 `diff_arg`** |
   | after | **8 `equal`** |

   The three rows are `beq cr6, fn_827DC120` / `beq cr6, fn_827DC120` /
   `ble cr6, fn_827DC0E0` against base `0x90` / `0x90` / `0x78`. Under the
   deployed splitter the target operand renders as a **relocation symbol name the
   splitter invented**; with the record gone it renders as the encoded branch
   destination. That is precisely the intended effect of the fix, and on this
   ruler the rows move *toward* agreement. The report path's `normalized`
   1.875 → 0.0 is the loss of arg-forgiveness credit that the invented symbol name
   was earning. The symbol matches **0 bytes in both arms** (raw, fuzzy and
   normalized all 0.0 on the diff path in both arms), so nothing
   admission-relevant moves. Residual gap, stated: the report's `name_check`
   ruler still cannot be interrogated at row level through the oneshot path.

2. **T7's `masked_equal` mechanism reproduces exactly.** Counted independently
   over my own reports: rows with `masked_equal: true` go **24,391 → 24,390**,
   one lost and none gained, and the lost one is exactly `fn_82545AFC`. Its
   `masked_equal: true` disappears in the after arm. The before-arm credit was
   manufactured by the splitter's own invented relocation, via
   `funclet_signature` zeroing the word at every relocation address. Note the
   project-level measure `masked_equal_functions` is 22,876 in **both** arms — a
   different counter from the per-row flag; do not use it to check this.

3. **cea-decomp is affected, and T7 was right to refuse to assume otherwise.**
   T7 listed it as an unmeasured project inside the blast radius. Measured here:
   3675/3675 staging verify, **2 objects change, −3 REL14 records**, same two XDK
   units as dc3 (`nuiruntime` `?NuipCameraReady@@YAHH@Z`, `qprocessing`
   `?QCcProcInitialize@MEC@@YAXXZ`), nothing else. Its score moves **not at all**:
   0 of 73,828 symbols, every project measure identical to six decimals. The gap
   is closed.

4. **T4's "183 objects / −626 records" for rb3-xenon is superseded by
   188 / −633**, as T7 said: T4's baseline arm ran on an already-converged
   symbols file. My run reproduces 188 / −633 from pristine per-arm config
   copies. This is a baseline difference, not a candidate difference.

5. **T7's dc3 count of 6 changed objects is 5 for the landed branch** — the sixth
   was ArcDetector, i.e. T5, which is held.

---

## 4. Verification re-run on the integrated tree

Every check below was re-run by me on `jeff-integration`, not inherited.

### 4.1 Build and tests

```
CARGO_TARGET_DIR=<worktree>/target-scratch cargo build --release   -> Finished, 0 errors
CARGO_TARGET_DIR=<worktree>/target-scratch cargo test  --bin dtk
    test result: ok. 163 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out
```

The 1 ignored is T5's test, §2. Its red still reproduces on demand:

```
$ cargo test --bin dtk -- --ignored ds_form
write_coff's REFHI/REFLO immediate zeroing corrupted 2 of 3 sites.
  +0x00: in 0xE96B0002 -> out 0xE96B0000, expected 0xE96B0002 (XO bits in=0x2 out=0x0 expected=0x2)
  +0x04: in 0xE96B004A -> out 0xE96B0000, expected 0xE96B0002 (XO bits in=0x2 out=0x0 expected=0x2)
test result: FAILED. 0 passed; 1 failed
```

T3's Shape-2 test is GREEN (T4 landed) and T4's two negative controls are green,
so "never emit REL14" — which would also satisfy T3's test — still cannot ship.

**`cargo test --lib` does not exist in this crate** (only `[[bin]] dtk`); T3's
correction to its own brief is confirmed and is now in the test module header.

### 4.2 A/B split, three projects, staging self-check FIRED on all three

Both arms staged from **separate pristine copies** of the project config and run
**once each**, which is the structural fix for T4's symbols-file-rewrite confound.
Arms are passed `--old <candidate> --new <deployed>` so that `--verify-against`
asks the falsifiable question (does the *deployed* binary reproduce the project?).

```
dc3-decomp   verify vs build/373307D9/obj:  identical 2223, different 0, missing 0
rb3-xenon    verify vs build/45410914/obj:  identical 3085, different 0, missing 0
cea-decomp   verify vs build/2011-07-28/obj: identical 3675, different 0, missing 0
```

That is **8,983 objects** hashed against the trees the projects actually score.
Hazard 6 is discharged: the staging is proven real, not assumed, and it also
retires "is the target tree stale?" for the target half of all three projects.

| project | objects | identical | changed | added | removed |
|---|---|---|---|---|---|
| dc3-decomp | 2223 | 2218 | **5** | 0 | 0 |
| rb3-xenon | 3085 | 2897 | **188** | 0 | 0 |
| cea-decomp | 3675 | 3673 | **2** | 0 | 0 |

Per-object classification (`t4_obj_ab_diff.py`), all three trees:

```
why:RELOC_REMOVED_REL14   5 / 188 / 2      (i.e. every changed object)
relocation record delta   -8 / -633 / -3   (0 added anywhere)
objects whose ONLY difference is not 'REL14 records removed':  0 / 0 / 0
```

Zero section-layout, zero section-data and zero symbol-table changes on any
project. dc3's 5 objects are `hostip`, `nuiruntime`, `qprocessing`, `buildcfg`,
`buildssa` — README §1.1's G36 plus T2's four fall-through/redundant sites.

### 4.3 Record level, naming-independent (`coff_reloc_parity.py shape`)

| tree | REFHI | REFLO | PAIR | PAIR disp = 0 | orphan PAIR | D-form imm = 0 | DS-form disp = 0 |
|---|---|---|---|---|---|---|---|
| dc3 before | 120,891 | 142,982 | 263,873 | 263,873 | 0 | 263,799/263,799 | 74/74 |
| dc3 after | 120,891 | 142,982 | 263,873 | 263,873 | 0 | 263,799/263,799 | 74/74 |
| rb3x before | 90,585 | 110,606 | 201,191 | 201,191 | 0 | 201,140/201,140 | 51/51 |
| rb3x after | 90,585 | 110,606 | 201,191 | 201,191 | 0 | 201,140/201,140 | 51/51 |

The REFHI/REFLO+PAIR shape is **identical between arms and unchanged by the
patch** — the fix touches only REL14, which is what it claims. (The DS-form XO
column is unchanged too, i.e. all 74 dc3 sites still carry XO = 0: that is the
defect T5 measured and this branch deliberately does not fix. See §2.)

| tree | REL14 | same-section | cross-section | W1 intra-fn | W2 intra-fn |
|---|---|---|---|---|---|
| dc3 before | 8 | 8 | 0 | 2 | 6 |
| dc3 after | **0** | 0 | 0 | **0** | **0** |
| rb3x before | 650 | 634 | 16 | 59 | 95 |
| rb3x after | **17** | 1 | 16 | **0** | 10 |

W1 = target symbol IS the enclosing function; W2 = the *encoded* destination lands
inside the enclosing function, which does not depend on symbol naming.
**Intra-function REL14 is 0 in both candidate trees under W1**, and the 16
load-bearing cross-section records survive as a set (16 → 16, 0 added). The 17th
survivor is T4's COMDAT-boundary case, kept deliberately and pinned by its own
negative control. W2's residual 10 is T7's documented classifier artifact — all 17
survivors target a symbol not defined in the emitting object, so their encoded
displacement is a pre-split value the linker overwrites. The MSVC compiler emits
**zero** REL14 in 2,193 objects across both games, so the candidate matches
compiler convention and the deployed binary does not.

### 4.4 objdiff report A/B — one ruler, per symbol

**Ruler: the deployed `objdiff-cli` (2026-08-12 05:56) for every arm.** T1 landed
nothing, so this is the ruler the projects use today. Four shadow projects of
symlinks: real `objdiff.json`, real `build/<id>/src`, real `icf_aliases.map`, only
`build/<id>/obj` varies. One `-o` path per arm — the report `.cache` sidecar does
not key on its inputs — and all six runs logged `Report cache: 0 hits`.

| project | units | symbols | unit skew | symbol skew | moved | fuzzy up | fuzzy down |
|---|---|---|---|---|---|---|---|
| dc3-decomp | 2224 | 48,344 | 0 | 0 | **1** | 1 | 0 |
| rb3-xenon | 3085 | 69,231 | 0 | 0 | **23** | 21 | 0 |
| cea-decomp | 3675 | 73,828 | 0 | 0 | **0** | 0 | 0 |

| measure | dc3 | rb3-xenon | cea |
|---|---|---|---|
| `matched_code` | 4,856,756 → **4,856,912** (+156) | 3,354,928 → **3,356,768** (+1,840) | 2,404 → 2,404 |
| `matched_code_percent` | 42.702670 → 42.704044 | 32.506813 → 32.524640 | unchanged |
| `matched_functions` | 29,392 → 29,392 | 44,285 → 44,285 | 57 → 57 |
| `fuzzy_match_percent` | unchanged | unchanged | unchanged |
| everything else | unchanged | unchanged | unchanged |

dc3's single move: `system/net/curl/lib/hostip` `Curl_resolv_unlock`
99.871796 → **100.0**, +156 bytes of `matched_code` — the whole function. That is
README §1.1's G36, the one row objdiff HEAD does *not* clear, i.e. the one row
this campaign's splitter change was actually convened for.

rb3-xenon: 21 up, of which 15 reach `fuzzy = 100`, their sizes summing to exactly
the +1,840. Largest single move +0.33334.

**Selection-population check.** `match_percent_normalized == 100` is the
gap-bug-hunt lane's sampling predicate. It moves by **+0 on both games**
(dc3 29,392 → 29,392; rb3-xenon 44,285 → 44,285). `fuzzy == 100` moves +1 and +15.
So unlike T1's *ruler* deploy — which T1 measured as moving 16 functions across
normalized into 100 — this splitter deploy does **not** disturb that population.

The only two downward movements anywhere are rb3-xenon
`?GetNextLine@?A0xaf4cfd2b@@YAPADPADPAH@Z` (normalized 1.875 → 0.0) and
`fn_82545AFC` (0.71428573 → 0.0). Both match **0 bytes in both arms**, contribute
0 to `matched_code` either way, and both are explained in §3.1 and §3.2 — one at
row level, one mechanically. **Zero unexplained movements. Zero downward movement
in any admission-relevant metric.**

### 4.5 The link check, and what I did and did not re-run

I did **not** re-run the `wibo` + `link.exe` relink; I did something cheaper that
makes T7's relink transfer exactly. Comparing my candidate dc3 objects against
T7's candidate objects, sha256:

```
IDENTICAL  system/net/curl/lib/hostip.obj      IDENTICAL  xdk/xgraphics/buildcfg.obj
IDENTICAL  xdk/nuiapi/nuiruntime.obj           IDENTICAL  xdk/xgraphics/buildssa.obj
IDENTICAL  xdk/nuiaudio/qprocessing.obj
DIFFERS    system/gesture/ArcDetector.obj      (T5 held)
```

and my ArcDetector.obj is byte-identical to the **deployed** binary's *and* to the
live project's. So the tree I am proposing to deploy is T7's relinked candidate
tree on the five REL14 objects and the deployed tree on ArcDetector. T7's relink
therefore transfers with one strictly-favourable change: the image would carry the
7 retail branch words **and** the retail `lwa`.

What that relink established, re-verified by me from the two images (§2):

- Both arms link with **byte-identical diagnostics** under dc3's own link line,
  15,063 LNK lines each, **no LNK2013 and no LNK1223** — the linker parses and
  fixes up all 1,256 split objects in both arms.
- Under `/FORCE:UNRESOLVED` both arms produce a 26,654,208-byte image with `.map`
  files identical modulo timestamp — symbol layout unchanged.
- The images differ in 28 bytes, of which **14 form 8 instruction words**. Seven
  are the REL14 sites, and in every one the *candidate's* word is the retail
  encoding while the *deployed* binary's image has been rewritten by the linker
  consuming the spurious record:

  | VA | deployed | candidate | site |
  |---|---|---|---|
  | 0x82542854 | `419a0528` | **`419a0010`** | hostip `Curl_resolv_unlock` |
  | 0x82cdb8f0 | `42404e08` | **`42400234`** | nuiruntime `?NuipCameraReady` |
  | 0x82cdb8f4 | `42404e04` | **`42400230`** | nuiruntime `?NuipCameraReady` |
  | 0x82fa4f80 | `408201d8` | **`40820048`** | buildssa `?FindSetBit@…` |
  | 0x82fa4f90 | `41980144` | **`4198ffe8`** | buildssa `?FindSetBit@…` |
  | 0x82fa6a08 | `408200b8` | **`40820044`** | buildcfg `??$FindSetBitInArray@I@…` |
  | 0x82fa6a18 | `4198002c` | **`4198ffe8`** | buildcfg `??$FindSetBitInArray@I@…` |

  This is the strongest single fact in the campaign and it was nobody's assigned
  task. T2 flagged it as a risk and left it unmeasured; T7 measured it. **T4 is
  not cosmetic — the deployed splitter corrupts the linked image at 7 dc3 sites.**

Honest scope: the relink is dc3-only (rb3-xenon has no link rule in the tree), it
needed `/FORCE` and two injected objects to exercise the sites, and the 8th dc3
REL14 site is identical in both images because the linker's recomputation happened
to coincide.

### 4.6 Version bump proved inert at the object level

Splitting dc3 with the 1.11.0 and 1.12.0 builds of *this same tree*:
**2223/2223 byte-identical, 0 changed.** The bump does rewrite
`build/<id>/config.json`, which records the dtk version.

---

## 5. Hazard ledger

| hazard | status |
|---|---|
| 1. building jeff = deploying to dc3 | Every build used a private `CARGO_TARGET_DIR`. `jeff/target/release/dtk` mtime `2026-08-08 22:32:10`, 8,371,016 bytes, **unchanged**. |
| 2. splitter change moves the ruler | Full before/after parity account on 3 projects, §4.2–4.4, every moved score explained. |
| 3. work in a worktree, never `main` | All work on `jeff-integration` in `.worktrees/integration`. `main` HEAD still `8a42efb`. No `git stash` anywhere. |
| 4. do not rebuild or re-split dc3 | Both projects split into scratch dirs under this worktree, against private config copies. `build/373307D9` and `build/45410914` were only ever READ; both projects' `symbols.txt` mtimes unchanged. |
| 5. `report.json` is not a baseline | No project `report.json` was read or written. Both arms of every comparison were generated in-session. |
| 6. the A/B harness once reported a false no-op | `--verify-against` used on all three projects and **fired**, 8,983 objects. |
| — objdiff-cli untouched | still `2026-08-12 05:56`, T1 deployed nothing. |

---

## 6. Known gaps — what this account does NOT cover

1. **`src/analysis/tracker.rs:503` is not fixed.** T2 root-caused the REL14 to an
   executor that walks past `function_end` against stale bounds. T4 landed the
   symptom fix in the writer for a measured reason (the COMDAT keep-back pass at
   `xex.rs:2012` reads these very records, so dropping them earlier re-enables
   COMDAT extraction and can separate a branch from its target). The same runaway
   walk still emits Rel24 and still pollutes `data_types`/`stores_to`/`hal_to`.
   That fix needs its own parity account.
2. **The DS-form defect is still live** in the emitted objects (74 dc3 sites at
   XO = 0, 1 of them wrong against retail), by decision, §2.
3. **The analysis-side DS-form address decode is wrong** (`lbl_82F446EE` should be
   `sDefaultHoverTimer` at `0x82F446EC`) and is baked into dc3's checked-in
   `symbols.txt`. Fixing it moves a project config file, which is its own blast
   radius.
4. **PpcRel14 still has no arm in the section-data fixup** for the 16
   cross-section survivors, so their in-place displacement is a stale pre-split
   value. The relink produced no LNK2013 in either arm, which is evidence but not
   proof that the linker is happy with all 16.
5. **The relink was not re-run on this exact binary** — it transfers by object
   identity, §4.5, which is tight but is a transfer.
6. **`objdiff-cli diff --format proto` ignores the project-level
   functionRelocDiffs** (T1's side finding, pre-existing, not caused here). Any
   consumer scoring through proto is on a different ruler than `report.json`.
7. **Four sibling worktree consumers** (`dc3-addrid-e0`, `dc3-bankv10-wt`,
   `dc3-vein1-wt`, `rb3-xenon-s5flat-wt`) point at the same dtk. They are the same
   two games, so they are covered by class, but each has its own build tree that
   will re-split. `ChimpsAtSea_Reach`, named in the harness header, is not present
   on this box and was not measured.

---

## 7. Deploy recommendation

**DEPLOY THE INTEGRATED SPLITTER — AFTER the branch is merged to `main`.**
Do not deploy from the unmerged branch.

The parity evidence licenses the swap. Every leg of README §5's bar is met:

- staging proven faithful on 8,983 objects across three projects, self-check
  fired;
- the only object-level difference in all 195 changed objects is removed REL14
  records, 0 added, 0 layout/data/symbol changes;
- REFHI/REFLO+PAIR record shape identical to compiler form and unchanged;
- intra-function REL14 → 0 on both games under a naming-independent witness;
- per-symbol movement 1 up / 21 up / 0, with **zero** unexplained and zero
  downward in any admission-relevant metric; the `normalized == 100` selection
  population does not move;
- the split still links, with identical diagnostics and no LNK2013/LNK1223, and
  at 7 dc3 sites the candidate **fixes a corruption of the linked image**;
- a fresh in-session baseline for the before arm, never a remembered number.

The reason to wait is not the evidence, it is reproducibility. The deployed
binary is the ruler for three projects. If it is built from a branch that is not
on `main`, then (a) nobody can reproduce the ruler from `main`, and (b) the next
`cargo build --release` in the jeff main checkout silently reverts it — moving
every score back with no one noticing. That failure mode is exactly the shape this
campaign exists to prevent. The integrator's standing rules forbid committing on
`main`, so the merge is a human's step and the deploy belongs immediately after
it.

Deploying **now** would also be defensible if the merge follows within the hour;
what is not defensible is deploying and leaving the branch unmerged.

**Do NOT land this and T1's objdiff-cli rebuild in one step.** T1's is a separate
deploy with a separate parity account, it moves rb3 (Wii) which this one cannot
touch, and it moves 16 functions across `normalized == 100` where this one moves
none. Landed together, neither account is readable afterwards.

---

## 8. Exact steps for the deploy

```bash
# 1. clear the untracked session-folder duplicates in the MAIN checkout
cd /home/free/code/milohax/jeff
git status --porcelain docs/sessions/   # expect '??' lines, identical content
rm -rf docs/sessions/2026-08-12-splitter-reloc-addend/{README.md,NOTES.md,findings}
#    (scratch/ is gitignored by the branch and can stay)

# 2. merge, --no-ff, real message
git merge --no-ff jeff-integration

# 3. build ONCE with the default target dir -- this IS the deploy
cargo build --release
./target/release/dtk --version          # expect: dtk 1.12.0 <merge sha>

# 4. regenerate every consumer's report.json; do not diff across the boundary
#    dc3-decomp, rb3-xenon, cea-decomp, and the four sibling worktrees
```

After step 3, `dtk --version` must read **1.12.0**. If it reads 1.11.0, the
deployed binary is not this work.

Anything holding a pre-deploy `report.json` number is on the old ruler. dc3's is
separately known stale (decomp-synth #158) for an unrelated reason.

---

## 9. Artifacts

Under `<this worktree>/scratch/` (gitignored, ~5 GB, delete after review):

- `dc3-ab/`, `rb3x-ab/`, `cea-ab/` — both arms' object trees per project;
  `new/out/obj` is the **deployed** arm, `old/out/obj` the **candidate**
- `report-{dc3,rb3x,cea}-{before,after}.json` — six full objdiff reports
- `{dc3,rb3x,cea}-symbol-delta.json` — machine-readable per-symbol deltas
- `getnextline-{before,after}.json` — the row-level diff behind §3.1
- `dtk-t4only`, `dtk-1.12.0` — the two candidate binaries
- `logs/` — every harness and report log, including the staging self-checks

T7's run dir (`decomp-bench/archive/runs/2026-08-13-splitter-parity-t7/`) holds
the two linked images used in §2 and §4.5; T7's own object trees are still in
`.worktrees/t7/scratch/` (~1.4 GB) and T5's in `.worktrees/t5/scratch/` (~4 GB).
