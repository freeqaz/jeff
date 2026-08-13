# Splitter loses the relocation addend on intra-function anchors

Session doc of record for the fix campaign. Written 2026-08-12 by the scribe from
the gap-bug-hunt reviewer's readout plus a code-reading pass over this repo.
Decomp-synth task #157 tracks the fix; #144 tracks the upstream-gap check that
gates it. Nothing in this document is a code change; §2 is candidate sites from
*reading*, not from running anything.

> **CORRECTION 2026-08-12 (validator, measured) — READ THIS FIRST.**
> **The premise of this document is 22/23 wrong.** The Shape-1 artifact is
> already fixed, in the RULER, not the splitter: objdiff `main` commit
> `4c38c31` (2026-08-12 06:03:38Z) adds `interior_self_reference()` in
> `objdiff-core/src/diff/code.rs`, written from this very evidence. The
> **deployed** `objdiff-cli` was built 2026-08-12 05:56 — seven minutes
> earlier — so the gap-bug-hunt measured a ruler that predates its own fix.
> Measured on all 23 rows with both binaries: deployed charges 23/23,
> objdiff HEAD charges **1/23** (G36 only). See `NOTES.md`, validator entry,
> FINDING 1.
>
> What survives as a real splitter defect is **Shape 2 only** (the
> intra-function REL14). Everything below about Shape 1 is accurate as
> *description* and obsolete as *motivation for a splitter change*.
> Individually-marked corrections follow inline. Nothing has been deleted.

Evidence provenance, used throughout:

- **MEASURED** — re-derived by the bug-hunt reviewer from raw COFF objects
  (`decomp-bench/archive/runs/2026-08-12-gap-bug-hunt/README.md` §4, with the
  parser at `.../work/review/coff.py` — 30 lines, the cheapest way to see the
  raw relocation records).
- **INFERRED BY CLASS** — mechanism proved on specific objects, extended to
  same-shaped rows without re-parsing each one.
- **CODE-READ** — a specific site in this repo whose code is consistent with the
  measurement; the causal chain has NOT been confirmed at runtime.
- **UNVERIFIED** — nobody has checked.

---

## 1. The defect

### 1.1 Statement

In dc3 TARGET objects produced by this splitter (`dtk xex split`), relocations
whose real target is an address *inside* the enclosing function are anchored on
the **enclosing function symbol** instead of a local `$LN`-style label at the
target address. PPC-COFF REFHI/REFLO carry no addend field — the addend is the
in-place 16-bit immediate, and the splitter zeroes it (deliberately, to match
compiler output convention). Result: the intra-function offset (e.g. `+0x48`)
exists nowhere in the emitted object. objdiff renders the relocated operand as
`function+0`, our compiler-produced object renders `$LN27` (a label AT the
right offset), and the diff charges rows that do not differ in control flow at
all.

> **CORRECTION (validator, measured).** "PPC-COFF REFHI/REFLO carry no addend
> field" is **false**. `IMAGE_REL_PPC_PAIR`'s `SymbolTableIndex` is, per the MS
> PE/COFF spec, a *displacement* rather than a symbol index — and this repo
> already documents that, at `src/util/xex.rs:2468-2471`. The correct statement
> is that MSVC never *uses* the channel: measured across all 989 dc3
> compiler-produced objects, **PAIR displacement = 0 in 342,386 of 342,386**
> REFHI/REFLO relocations, with a nonzero in-place immediate in 3. The
> compiler's convention is an anchor symbol whose *value* sits at the target
> address. The conclusion (don't carry the addend in PAIR) stands; the stated
> reason for it does not.

Two measured shapes:

- **Shape 1 — jump-table anchor (22 of the 23 artifact rows).** The
  `lis`/`addi` pair that materialises the base of an MSVC-PPC switch dispatch.
  objdiff types the relocated immediate `BranchDest`, which is what broke the
  `n_branch > 0` tier predicate — the opcode is not a branch.
- **Shape 2 — spurious REL14 on an intra-function conditional branch (1 row,
  G36 `Curl_resolv_unlock`).** The target object carries a REL14 relocation the
  compiler never emits on an intra-function `bc`; objdiff resolves the branch
  destination through the relocation (symbol+0 = function start) instead of
  from the encoded displacement, rendering a fake control-flow difference.

> **CORRECTION / SCOPE (validator, measured).** Both shape counts are
> *sample* counts from the 60-function bug hunt, not censuses, and the doc
> reads as if they were project-wide. Measured across whole trees:
>
> | tree | objects | self-ref REFHI/REFLO | distinct fns | REL14 | REL14 intra-fn |
> |---|---|---|---|---|---|
> | dc3 TARGET | 2223 | 350 | **154** | 8 | 2 |
> | dc3 OURS | 989 | 6 | 3 | **0** | 0 |
> | rb3-xenon TARGET | 3085 | 262 | **110** | **650** | **59** |
> | rb3-xenon OURS | 1204 | 20 | 10 | **0** | 0 |
>
> Shape 1's real dc3 population is 154 functions, not 22. Shape 2 is not "1
> row": it is 2 intra-function REL14 on dc3 and **59 on rb3-xenon**, and the
> MSVC compiler emits **zero** REL14 in 2,193 objects across both games — so
> every REL14 in a target object is splitter-originated. The self-ref counts
> include a legitimate address-of-own-entry subset (ours has one,
> `?CharTerminate@@YAXXZ`); a classifier is needed before quoting 154 as a
> defect count.
>
> `Shape 1 (22 of 23)` is however exactly the set that objdiff HEAD already
> clears — see the correction banner at the top.

### 1.2 Evidence

**MEASURED (high confidence):**

- G33 `?SongInfoAudioTypeToSym@@YA?AVSymbol@@W4SongInfoAudioType@@@Z`: in-place
  words at `fn+0x2c`/`fn+0x34` are `3d800000`/`398c0000` in BOTH objects —
  identical bytes, zero immediates. The relocations differ only in anchor:

  ```
  TARGET  off=0x2c type=0x10 (REFHI) -> ?SongInfoAudioTypeToSym@@…  (sym val 0x0)
          off=0x34 type=0x11 (REFLO) -> ?SongInfoAudioTypeToSym@@…  (sym val 0x0)
  OURS    off=0x2c type=0x10 (REFHI) -> $LN27                       (sym val 0x48)
          off=0x34 type=0x11 (REFLO) -> $LN27                       (sym val 0x48)
  ```

- **The settling case**, G24 `?HandleEventResponse@SaveLoadManager@@QAAXPA..`
  (unit `lazer/meta_ham/SaveLoadManager`): the target's byte jump table
  (`jumptable_820FDEF0`) and ours (`$T224728`) are **byte-identical** while the
  anchors differ by 0x164. A table is only meaningful against its anchor; equal
  tables force equal anchors, so OUR anchor is the faithful one and the
  target's `fn+0` attribution is the lossy one. (`fn+0` is also structurally
  impossible as a real anchor — offset 0 is the `cmplwi` range guard, not a
  case block.)
- G36 `Curl_resolv_unlock`: first 40 bytes byte-identical in both objects
  including the charged `beq` word `0x419a0010`; the target carries an extra
  `fn+0x24 type=0x7 (REL14) -> Curl_resolv_unlock` relocation ours does not.
- Mechanism independently reproduced on three objects: G33, G36, G24.

**INFERRED BY CLASS (strong estimate, not a census):** 23 of the 32
`C_branch_only` rows in the 60-function bug-hunt sample (G11 G12 G13 G15 G16
G17 G19 G20 G21 G24 G25 G26 G27 G28 G29 G33 G34 G35 G36 G37 G38 G39 G40) are
this artifact. Every affected row's *measurement* reproduced, but the reviewer
did **not** re-parse all 24 objects — 23-of-32 is proved-on-three plus
same-shape classification. Treat "23" as a strong estimate.

Do NOT rest on the G37/G38/G39 "base 0 is arithmetically impossible" argument —
it holds for unscaled `lbzx` tables but fails on `*4`-scaled ones (G21). The
byte-and-relocation identity is the load-bearing evidence.

**UNVERIFIED:**

- Whether rb3-xenon (the other X360 MSVC-PPC target this splitter produces;
  gap of 7,651 functions, 95.7% relocation-class residual) shows the same
  artifact. Same splitter, same object format — plausible, unmeasured.
- The full causal chain through this repo's code (§2 is code-read only).
- Whether the 16 upstream commits we are behind contain or affect a fix (§3 Q1
  narrows this substantially but does not close it).

### 1.3 Why this is worth a splitter change

The 9 branch rows that are NOT artifact carry 6 of the 8 genuine behavioural
bugs found in the 60-function sample — a 19% bug rate, the densest vein
measured anywhere in this gap. Removing the ~72% artifact converts
`C_branch_only` from a mostly-noise class into a near-pure bug detector. The
payoff is a working instrument, not tidier numbers. By the same mechanism it
should also retire most of rb3's 16 branch rows at zero source cost (INFERRED,
unmeasured).

> **CORRECTION (validator).** The rb3 sentence is **wrong**, and it was
> inherited from the readout (§4 "most of rb3's 16 branch rows"). `rb3` is the
> **Wii / mwcceppc / ELF** target — `objdiff.json` unit 0 is
> `build/SZBE69_B8/obj/App.o`. Its objects come from the ELF writer, which
> emits RELA with an explicit `r_addend` (`src/util/elf.rs:743`, verified), so
> the addend-less PPC-COFF encoding is not in that path and this fix cannot
> retire those rows. The affected sibling is **rb3-xenon**, measured above.
> §3 Q4 was right to flag this; §1.3 should not have asserted it.
>
> **CORRECTION (validator).** The "payoff" framing is also now wrong in cost:
> converting `branch_only` into a bug detector for dc3 costs an
> **objdiff-cli rebuild**, not a splitter change. See the top banner.

---

## 2. Where it plausibly lives in this codebase (candidate sites — verify, do not trust)

All line numbers at `main` = `8a42efb`. The XEX→PPC-COFF path is **fork-original
code**: `upstream/main` (encounter/decomp-toolkit) has no `src/util/xex.rs` and
no COFF writer at all (checked via `git ls-tree upstream/main src/util src/cmd`).

### 2.1 Anchor selection — why the function symbol wins

- `src/analysis/tracker.rs` `apply_relocations()` (fn at :795, decision at
  :835–:881). For each tracked relocation it resolves the target address to a
  symbol via `obj.symbols.for_relocation(...)`; if a symbol is found the reloc
  is recorded as `(symbol, addend = target − symbol.address)` (:860). A new
  `lbl_<addr>` label is created **only when no symbol covers the target**
  (:862–:880). An intra-function target is always covered by the sized function
  symbol, so the function anchor + nonzero addend wins and no label is ever
  created.
- `src/obj/symbols.rs` `for_relocation()` (:545–:576). Walks symbols at/below
  the target; an exact-address symbol wins (:564), else any sized symbol whose
  range contains the target (:568–:572) — i.e. the enclosing function. If a
  label existed at the exact address it would win; none is ever created for
  case-block bases.
- `src/analysis/cfa.rs` (~:300–:366). Creates `fn_*` function symbols and
  `jumptable_*` symbols for the **table data**, but no label at the case-block
  base / dispatch target inside the function — the address the `lis`/`addi`
  pair actually materialises.

So the in-memory ObjInfo very likely carries the correct information
(`function + 0x48`) all the way to the writer. CODE-READ, not confirmed at
runtime.

### 2.2 The lossy write — where the addend physically disappears

- `src/util/xex.rs` `write_coff()` (:1781). Two relevant places:
  - **Section-data fixup**, :2085–:2142. COFF relocations are additive (the
    in-place bytes are the addend). `Absolute` writes `reloc.addend` into the
    word (:2095–:2101 — ADDR32 addends SURVIVE). `PpcRel24` writes the
    `−offset_in_section` linker convention (:2103–:2121). **`PpcAddr16Ha` /
    `PpcAddr16Lo` zero the 16-bit immediate unconditionally** (:2123–:2138),
    with a comment saying "Zero the immediate to match compiler output
    (addend=0)". That convention is correct only when the anchor is a label at
    the target address; combined with the function-symbol anchor from §2.1 it
    destroys the offset. This is the most likely single point of loss.
    CODE-READ.
  - **Relocation records**, :2447–:2485 (and the COMDAT copy :2408–:2444) are
    written with `addend: 0`, which is fine per COFF (the addend lives in the
    section data) — the record itself is not the loss.
- Note `PpcRel14` has **no arm** in the data fixup match (falls through
  `_ => {}` at :2139), so a REL14's encoded displacement stays baked while a
  relocation record is still emitted — relevant to Shape 2 rendering.

### 2.3 Where the spurious REL14 could originate (Shape 2)

- `src/analysis/tracker.rs` `instruction_callback()` `StepResult::Branch`
  (:479–:511). A `bc` gets `Relocation::Rel14` only when the target is NOT
  inside the current function bounds (`is_function_addr`, :284, exclusive
  bounds `> start && < end`), with a special case rewriting `bc` to
  function-start as REL24 (:498–:504, "MSVC's linker doesn't accept REL14 in
  tail calls"). For G36 the charged relocation resolves to function start yet
  is REL14 — inconsistent with both paths as read. Candidate explanations to
  verify, not conclusions: function bounds were different at analysis time;
  the reloc came from the missed-branch reanalysis; or from a producer other
  than `instruction_callback`.
- Prior art in this repo, same neighbourhood, different defect: merged lane
  `fix/jumptable-internal-branch-targets` (merge `b381932`, commit `dde965c`
  "xex split: internal branch targets must not start functions") fixed internal
  branch targets *seeding functions*. Its tests may be reusable fixtures.

### 2.4 Carriers (probably faithful, check once)

- `src/util/split.rs` (:1426–:1437) copies relocations into split objects with
  `addend: o.addend` — verbatim carry. CODE-READ.
- `src/obj/relocations.rs` `to_coff()` (:108) is a pure kind→`IMAGE_REL_PPC_*`
  mapping; `ObjReloc.addend` is `i64` (:63).
- Contrast, and why GC/Wii is structurally immune: the ELF writer emits RELA
  with an explicit `r_addend: reloc.addend` (`src/util/elf.rs:743`). The same
  function-symbol-plus-addend anchor round-trips losslessly there. The defect
  is specific to the addend-less PPC-COFF encoding.
- If the fix synthesises labels: `write_coff` already emits local Unknown-kind
  symbols with `SymbolKind::Label` → `IMAGE_SYM_CLASS_LABEL` (:2308–:2318), and
  `.pdata` reconstruction already skips `lbl_*` names (:1911) — but interaction
  with COMDAT extraction, `is_auto_label` scope promotion (:2321), and pdata
  sizing-by-next-symbol (:1925–:1938 uses **every** symbol address, so a new
  label inside a function would shrink an inferred function size) must be
  checked deliberately.

---

## 3. Open questions a validator must settle BEFORE code is written

Each phrased to have a checkable answer.

> **VALIDATOR STATUS OF Q1–Q7 (2026-08-12).** Q1 **ANSWERED — not a port**
> (FINDING 6). Q2 **ANSWERED — rb3-xenon IS affected**, 262 self-ref relocs /
> 110 functions, 650 REL14 (59 intra) (FINDING 3). Q3 **ANSWERED for Shape 1
> by obsolescence** — objdiff HEAD already treats the target's `fn+0` anchor as
> equal to our `$LN` label, so no label synthesis is required for the dc3
> `branch_only` motive; the question stays live only if the splitter is changed
> for other reasons. Q4 **ANSWERED — ELF is immune** (`elf.rs:743` carries
> `r_addend`), and the rb3 claim it guarded is retracted (§1.3 correction).
> Q5 **OPEN — and it is now the whole campaign.** Q6 **still binds**, but on the
> objdiff rebuild rather than a splitter change. Q7 **ANSWERED by code**:
> `tracker.rs:860` records `(symbol_idx, target.address - symbol_address)`, so
> the addend reaches the writer and `xex.rs:2123-2138` is the loss point; §2.2
> is the right site.
>
> **Q8 (new, validator).** The `write_coff` immediate-zeroing is
> `insn & 0xFFFF0000`, which also clears the low TWO bits of a **DS-form**
> instruction (primary opcode 58 `ld/ldu/lwa`, 62 `std/stdu`) — where those bits
> are opcode extension, not displacement. dc3 target has 74 REFLO sites on a
> DS-form opcode, rb3-xenon 51, all now XO=0. Our own compiler objects prove the
> shape is real (`ArcDetector.obj`, three `lwa` = `0xe96b0002`, XO=2, at REFLO
> sites). Not proven to have fired on dc3 retail — `grep -rE '^\s+lwa\s'
> build/373307D9/asm/` is 0 across the whole disassembly. Latent writer defect;
> close it by construction, do not claim a measured corruption.

**Q1. Is the fix already in the 16 upstream commits we are behind?**
State as of this session (`git rev-list --left-right --count main...upstream/main`
= `269 16`; upstream tip `e4219e7` "Version 1.8.3", 2026-03-01). The 16:

```
e4219e7 Version 1.8.3                     6bef60c precommit hook
43d602b Warn+continue on missing REL target  af8595e extab w/ interleaved extabindex
2b39879 fmt & clippy                      6baa8a0 Version 1.8.2
89106d0 Clamp inferred jump table sizes to section size
46e6052 Fix extab splitting with -inline deferred
c4de1b4 Version 1.8.1                     06749b8 Reformat edition 2024
02b343f Fix advisories                    65fdf9b nightly clippy
8c77e49 vaddr support for REL section headers
0e8ea40 Rust edition 2024
aa635e1 Stricter function terminator checks in prologue detection (#135)
fdf1ed0 Split out dwarf printing (#134)
```

Because upstream has **no COFF writer**, the exact REFHI/REFLO fix cannot be a
straight port. But `89106d0` (jump-table size clamping) and `aa635e1` (function
bounds) touch shared analysis code that feeds anchor selection and could change
Shape-2 behaviour. Check: `git diff main...upstream/main -- src/analysis/` and
adjudicate each hunk; also confirm the task-#144 belief ("the 16 are splitter
correctness fixes") against this list — from subjects alone, roughly half are
version bumps and formatting. Porting still beats reinventing where it applies;
say plainly in the fix doc which commits were taken and which were irrelevant.

**Q2. Is rb3-xenon affected?** Check: run the readout's `coff.py` over a sample
of rb3-xenon TARGET objects; count (a) REFHI/REFLO relocations whose symbol is
a Function-class symbol and whose site is a `lis`/`addi` with zero immediate
materialising an address inside that same function, and (b) REL14 relocations
whose resolved target lies inside the source function. Nonzero counts = affected;
report the count, not a boolean.

**Q3. What is the correct emission — a local label, or the addend carried some
other way?** The compiler's own convention (measured on OUR objects) is: local
`$LN` label at the target offset, immediate zeroed. The alternative — bake the
offset into the REFHI/REFLO immediates as the additive addend — links correctly
but produces in-place bytes that differ from compiler output (`0x0048` vs
`0x0000`), which objdiff would then charge as a byte difference: it would move
the artifact, not remove it. Check: parse several compiler-produced objects with
`coff.py` and confirm (a) `$LN*` storage class (expect `IMAGE_SYM_CLASS_LABEL`),
(b) immediate always zero at REFHI/REFLO sites anchored on labels, (c) the
REFHI/REFLO + PAIR record layout around them, so the synthesized form is
record-for-record shaped like the compiler's. Also decide the label NAME: `$LN`
numbering is compiler-internal and unreproducible; objdiff comparability, not
name equality, is the bar — verify objdiff at the shipped settings treats
`differently-named label + same offset` as equal.

> **CORRECTION (validator, measured).** The shipped setting is
> **`functionRelocDiffs: "name_check"`** — in all three of dc3-decomp, rb3 and
> rb3-xenon (`objdiff.json` `options`). It is not `none`, and the repo-level
> CLAUDE.md wording "the shipped `functionRelocDiffs=none`" does not describe
> these targets. This matters: every tolerance in play here
> (`interior_self_reference`, `is_compiler_local_label`,
> `is_placeholder_symbol_name`) is NameCheck-gated, so under `none` they are
> irrelevant and under `name_address` they do not apply. Any label-synthesis
> design must state which NameCheck predicate forgives its chosen name — a
> synthesized `lbl_<addr>` is forgiven by `is_placeholder_symbol_name`, a `$`
> name by `is_compiler_local_label`; they are different code paths.

**Q4. What does upstream do for GameCube/Wii ELF, where addends DO exist?**
Answer from code (verify): ELF RELA carries `r_addend` explicitly
(`src/util/elf.rs:743`), so function-anchored intra-function relocs round-trip
losslessly and no label synthesis is needed there. Confirm no equivalent
artifact exists on a GC/Wii target (rb3 Wii branch rows are ELF-side — if the
same 16 rb3 branch rows are claimed retired by this fix, re-derive which object
format each row's target came from before claiming it).

**Q5. Where exactly does Shape 2's REL14 come from?** The tracker as read
should not emit a reloc for an intra-function `bc` (§2.3). Check: re-run
analysis on the unit containing `Curl_resolv_unlock` with tracker debug logging
and capture which producer inserts the `fn+0x24` relocation and what
`function_start`/`function_end` were at that moment. The fix for Shape 2 might
be a bounds fix, not a relocation-emission fix — do not conflate the two
shapes in one patch without this answer.

**Q6. What else moves?** Any anchor/label change can move scores project-wide
(the splitter is the ruler). Check: full A/B split (see §5) with a per-object,
per-symbol diff of the objdiff report; every moved score must be *explained*
(expected: `C_branch_only` artifact rows move toward/into agreement; nothing
else moves), not just tallied. `scripts/xex_split_ab_compare.sh` is the
harness; commits `8a42efb` and `1038ebc` hardened it after it reported a FALSE
no-op — read both before trusting a null result, and prove your staging is real.

**Q7. Does the in-memory reloc actually carry the addend to `write_coff`?**
§2.1–2.2 is code-read. Check with one debug print (or a unit test around
`write_coff`) on the G33 unit: assert the ObjInfo relocation at `fn+0x2c` is
`(function_symbol, addend 0x48)` before the writer runs. If it is NOT — the
loss is upstream of the writer and §2.2 is the wrong patch site.

---

## 4. Hazards (load-bearing — these silently ruin the work)

1. **BUILDING JEFF IS DEPLOYING TO DC3.** `dc3-decomp/configure.py:164` sets
   `config.dtk_path = ../jeff/target/release/dtk`. A bare
   `cargo build --release` in this repo REPLACES the splitter that dc3 (and
   rb3-xenon) use, with no review and no parity evidence. Same shape as the
   objdiff-cli symlink: it is the intended deploy path, which is exactly why
   you must not trip it by accident. **Always build with a private target
   dir:** `CARGO_TARGET_DIR=<your-worktree>/target-scratch cargo build
   --release`, and never write to `../jeff/target/release/dtk` (from the main
   checkout: `target/release/dtk`) until the integrator lands, with parity
   evidence, as an explicit deliberate step.
2. **Changing the splitter changes the TARGET objects, therefore every score in
   the project.** A splitter change is not like a source fix: it moves the
   ruler. Any adoption needs before/after parity evidence on real objects, and
   the direction of every moved score must be explained, not just tallied.
3. **Work in a git worktree of jeff, never on `main` directly.** Concurrent
   sessions use these repos. Never `git stash` in a shared checkout.
4. **Do not rebuild or re-split dc3.** Split into a SCRATCH output directory
   and compare objects there. dc3 `build/373307D9` is shared state and is
   separately known to be stale (decomp-synth task #158).
5. **`report.json` is not a trustworthy baseline** — rebuilding unmodified dc3
   source moves two known functions. If you need a baseline, build it, do not
   remember it.
6. The A/B harness `scripts/xex_split_ab_compare.sh` once reported a FALSE
   no-op; commits `8a42efb` and `1038ebc` hardened it. Read those commits
   before trusting it, and prove your staging is real (the harness now
   self-checks, but verify the check fired).

---

## 5. What "done" looks like

> **CORRECTION (validator).** This section describes the bar for replacing the
> **splitter**. After the measurement above, the dc3 `branch_only` motive is
> satisfied by replacing the **ruler** (`objdiff-cli`) instead — a different,
> smaller change that still moves every score and therefore still needs a full
> per-symbol parity account. The evidence bar below transfers verbatim to that
> deploy; substitute "objdiff-cli binary" for "splitter binary" and
> `objdiff/target/release/objdiff-cli` (symlinked from `~/.local/bin/objdiff-cli`)
> for `../jeff/target/release/dtk` in hazard 1. A splitter change is still
> required for Shape 2, and its bar is unchanged.

Evidence that **justifies** replacing the deployed splitter binary:

- Q1–Q5 and Q7 answered in writing in this folder, with commands and outputs.
- A fix built in a private `CARGO_TARGET_DIR`, from a worktree branch.
- A/B split of dc3 (and rb3-xenon, if Q2 says affected) into scratch output
  dirs via the hardened `xex_split_ab_compare.sh`, showing:
  - the G33/G36/G24 relocation records now match the compiler's form
    (label-anchored REFHI/REFLO + PAIR, zero immediates; no intra-function
    REL14) — verified with `coff.py`, not only with objdiff;
  - the ~23 artifact rows' `branch_only` charges disappear under the shipped
    objdiff settings;
  - **every** other moved score enumerated and explained, per-symbol — the
    expected explanation set is "artifact rows only"; unexplained movement is
    a stop, not a footnote;
  - the split still links (the REFHI/REFLO+PAIR and REL14-range constraints in
    §2 exist because the MSVC linker rejects malformed forms — LNK2013/LNK1223
    have bitten this writer before).
- A fresh dc3 baseline built in-session for the before arm (hazard 5).
- An explicit, deliberate deploy step by the integrator, recorded with the
  parity evidence and a version bump (repo convention: objects changed ⇒
  version bump, cf. `287a322`, `48e6941`).

Evidence that does **NOT** justify it:

- "The 23 rows went green" with no per-symbol account of everything else that
  moved. The rows going green is the *motive*; the parity account is the
  *license*.
- A null A/B from the harness without proof its staging was real (hazard 6).
- Byte-identical objects "except relocations" — the relocation records ARE the
  defect surface; record-level identity to compiler form is the bar there.
- Any comparison against remembered `report.json` numbers (hazard 5), or
  against the shared, known-stale `build/373307D9` tree (hazard 4).
- A green result built with the default target dir (hazard 1) — that means the
  deployed binary was already replaced before review, and the "before" arm is
  contaminated.

## Files

- This doc: `docs/sessions/2026-08-12-splitter-reloc-addend/README.md`
- Append-only phase log: [`NOTES.md`](NOTES.md)
- Reviewer readout (evidence of record):
  `decomp-bench/archive/runs/2026-08-12-gap-bug-hunt/README.md` §4
- Raw-record parser: `decomp-bench/archive/runs/2026-08-12-gap-bug-hunt/work/review/coff.py`
