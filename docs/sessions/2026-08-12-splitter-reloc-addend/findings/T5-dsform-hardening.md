# T5 — the DS-form XO corruption is not latent. It fired on dc3 retail, and it charges

Branch `jeff-t5` (off `jeff-t4`), worktree `.worktrees/t5`, commit `b204ebd`.
Measured on this box 2026-08-13 against jeff `main` = `8a42efb` + T3's tests + T4's
REL14 filter.

Deploy hazards first: every build used
`CARGO_TARGET_DIR=/home/free/code/milohax/jeff/.worktrees/t5/target-scratch`.
`target/release/dtk` is **still `2026-08-08 22:32:10`, 8371016 bytes** — the
splitter dc3 and rb3-xenon actually run was never written. Both games were split
into scratch dirs under the worktree against **private copies** of
`config/<id>/{config.yml,symbols.txt,splits.txt}`; the project trees were read
only. `objdiff-cli` was not rebuilt (still the deployed 05:56 binary). Nothing
merged, nothing pushed, `main` untouched.

---

## 0. Headline — the brief's premise is wrong in the direction that matters

The task brief, and NOTES FINDING 8 before it, said this was a **latent** writer
defect: "NOT proven to have fired on dc3 retail — grep for lwa over
`build/373307D9/asm/` returns 0 across the entire disassembly." It has fired.
dc3's disassembly contains **433 `lwa`, 137 `ldu` and 209 `stdu`**, one of them
at a REFLO site, and the object the splitter emits for it carries `ld` where the
retail XEX has `lwa`. objdiff charges the row today. So this is a **live silent
corruption of the ruler**, not construction-correctness, and §1 explains why
everyone measured zero.

rb3-xenon, the other half of the brief's question, **is clean**: 0 of its 51
DS-form REFLO sites carries a nonzero opcode extension, and a full A/B re-split
returns 3085 / 3085 byte-identical objects.

---

## 1. Why the "0 lwa on dc3" measurement was a false negative

`grep -rE '^\s+lwa\s' build/373307D9/asm/` cannot match anything in a dtk asm
file. The mnemonic does not start the line — it follows the byte comment:

```
/* 82272E70 00267C70  FB E1 FF F0 */	std r31, -0x10(r1)
```

so no line begins with whitespace-then-mnemonic. Run on dc3, the same pattern
returns **0 for `lwz` and 0 for `stw`** as well, which is the tell: it is a
broken pattern, not a measurement. The working pattern anchors on the comment
close:

```bash
grep -rhoE '\*/[[:space:]]+(lwa|lwau|ldu|stdu|ld|std)[[:space:]]' <asm-tree> | awk '{print $2}' | sort | uniq -c
```

This matters beyond T5: the asm tree is the campaign's **pre-`write_coff`
witness** (T6 §"Discriminator" — `write_asm` and `write_coff` are handed the same
immutable `split_objs`, and only `write_coff` clones and zeroes the data), so a
broken grep over it silently answers "the writer never fired" for any question
of this shape.

## 2. Corrected census

Whole asm tree — the original instruction words, before the writer's fixup:

| tree | files | `ld` | `ldu` | `lwa` | `std` | `stdu` | corruptible (`ldu`+`lwa`+`stdu`) |
|---|---|---|---|---|---|---|---|
| dc3 `build/373307D9/asm` | 33,031 | 27,713 | 137 | 433 | 31,369 | 209 | **779** |
| rb3-xenon `build/45410914/asm` | 3,085 | 21,128 | 51 | 377 | 24,374 | 81 | **509** |

Only sites carrying a REFHI/REFLO reach the arm in question. Restricting to
operands rendered `sym@l` / `sym@ha`:

| tree | `ld` | `lwa` | `std` | total | **XO != 0** |
|---|---|---|---|---|---|
| dc3 | 21 | **1** | 52 | **74** | **1** |
| rb3-xenon | 15 | 0 | 36 | **51** | **0** |

The totals **74** and **51** reproduce FINDING 8's census exactly, which is the
cross-check that the corrected grep is measuring the same population. What
FINDING 8 got wrong is the conclusion drawn from "all currently XO=0": that was
measured on the **emitted objects**, i.e. it was measuring the corruption
itself. Read on the input side, 1 of dc3's 74 is `lwa`.

## 3. The one live corruption

`dc3-decomp/build/373307D9/asm/system/gesture/ArcDetector.s:2704`, VA
`0x82E025AC`, inside `?UpdateOverlay@ArcDetector@@QAAMPAVRndOverlay@@M@Z`:

```
/* 82E02590 00DF6F90  3D 60 82 F4 */	lis r11, lbl_82F446EE@ha
...
/* 82E025AC 00DF6FAC  E9 6B 46 EE */	lwa r11, lbl_82F446EE@l(r11)
/* 82E025B0 00DF6FB0  F9 61 00 50 */	std r11, 0x50(r1)
/* 82E025C4 00DF6FC4  C8 01 00 50 */	lfd f0, 0x50(r1)
/* 82E025C8 00DF6FC8  FC 00 06 9C */	fcfid f0, f0
```

An `int` → `double` conversion — unambiguously code, not misdisassembled data.
`0xE96B46EE`: primary opcode 58, XO = 2 = `lwa`.

The emitted target object carries `0xE96B0000` (`ld`) at COMDAT section `/53`
offset `+0x824`. The two other `lwa` in that object (`/53` `+0x24`, `+0x12c`)
carry no relocation and were therefore untouched — the arm is the only thing
that changed the instruction.

Our own compiler object,
`build/373307D9/src/system/gesture/ArcDetector.obj`, has **three** DS-form
sites at REFLO relocations and **all three are `lwa`, `XO=2`, in-place
immediate 0** (`.text` `+0x24`, `+0x14c`, `+0x7bc` → `sDefaultHoverTimer`).
So the compiler's convention at a DS-form REFLO site is *zero displacement,
XO preserved* — which is exactly what the fix now emits, and the opposite of
what the writer emitted.

### It charges under the shipped ruler

`objdiff-cli diff -p . -u default/system/gesture/ArcDetector
'?UpdateOverlay@ArcDetector@@QAAMPAVRndOverlay@@M@Z' --format json
--include-instructions`, deployed binary, project `functionRelocDiffs:
name_check`, row **574**:

| arm | target side | base side | `match_type` |
|---|---|---|---|
| before | `ld r11, lbl_82F446EE, r11` | `lwa r11, sDefaultHoverTimer, r11` | **`replace`** |
| after | `lwa r11, lbl_82F446EE, r11` | `lwa r11, sDefaultHoverTimer, r11` | **`equal`** |

`fuzzy_match_percent` 71.83148 → 71.83334, `diff_score` 15211 → 15210 / 54000.
The before-arm number reproduces the real project run (71.83148) to five
decimals, so the scratch project used for the after-arm is a faithful stand-in.
The differing anchor names (`lbl_82F446EE` vs `sDefaultHoverTimer`) are forgiven
by a NameCheck tolerance, so what was being charged was purely the opcode.

The size of the move is small — one row on a 71.8% function. Its significance is
not the 0.002 points: it is that **no source could ever have won that row.** The
ruler was demanding an instruction the retail game does not contain.

## 4. The fix

`src/util/xex.rs`, `write_coff`'s section-data fixup, `PpcAddr16Ha |
PpcAddr16Lo` arm. `insn & 0xFFFF0000` becomes

```rust
let keep_mask = match insn >> 26 {
    58 | 62 => 0xFFFF0003, // DS-form: preserve XO [1:0]
    _       => 0xFFFF0000, // D-form: whole immediate
};
```

Primary 58 is `ld`/`ldu`/`lwa`, primary 62 is `std`/`stdu`; in both the
displacement is bits [15:2] and [1:0] are an opcode extension. The other
split-field encodings (DQ-form `lq`/`stq`, DS-form `lfdp`/`stfdp`) are not
implemented by the Xenon CPU, so 58/62 is the complete set here.

D-form keeps the full 16-bit clear. T3's fixture pins that with an `addi`
control (`0x398C0048 → 0x398C0000`) precisely so a "fix" cannot pass by deleting
the arm.

## 5. Tests

| arm | result |
|---|---|
| `jeff-t4` `f830e16` (baseline) | 163 passed, **1 failed** |
| `jeff-t5` `b204ebd` | **164 passed, 0 failed** |

The one failure that cleared is T3's
`ds_form_immediate_zeroing_must_preserve_xo_bits`; all three of T3's tests and
both of T4's negative controls are green. Command is `cargo test --bin dtk` —
`--lib` still does not exist in this crate (T3 §CORRECTION).

## 6. Object-level parity

Tool: T4's `findings/scripts/t4_obj_ab_diff.py`, which classifies every
difference by *what* differs (object set / section headers / section raw data /
symbol table / relocation records).

### dc3 — 1 object moved, and it is the intended one

| | value |
|---|---|
| objects | 2223 base / 2223 fix, 0 added, 0 removed |
| identical | **2222** |
| differ | **1** — `system/gesture/ArcDetector.obj`, class `SECTION_DATA` |
| relocation record delta | **{} — empty** |
| section layout / symbol table | **unchanged in every object** |

Determinism control (same fixed binary, two runs, separate config copies and
output dirs): **2223 / 2223 byte-identical**. So the 1-object delta is causal.

Every changed byte in that object, enumerated:

| file offset | base | fix | what |
|---|---|---|---|
| `0x3d6b` | `0x00` | `0x02` | the instruction: `0xE96B0000` (`ld`) → `0xE96B0002` (`lwa`) |
| `0x7a50`–`0x7a53` | `0xce9fdaca` | `0x932133fe` | symbol-table entry #122, an **aux section-definition record**, field offset 8..12 = `CheckSum`, for COMDAT section `/53` (`length=0x870 nreloc=197 selection=2`) |

Five bytes total: one instruction byte, plus the four-byte COMDAT checksum that
is *derived* from the section data the instruction lives in. Nothing else.

Because exactly one object changed and its only content change is one
instruction, **the project-wide score account is closed by construction**: no
other object can move a symbol, and within `ArcDetector.obj` only row 574 of
`UpdateOverlay` changes (§3). I did not regenerate a full `report.json` — the
object-level delta is a stronger statement than a report diff, and hazard 5 says
not to compare against a remembered one.

### rb3-xenon — provably inert, and measured inert

| | value |
|---|---|
| objects | 3085 / 3085 |
| identical | **3085 — byte-for-byte, the whole tree** |
| differ | **0** |

Predicted before the run from §2 (0 of 51 DS-form REFLO sites has XO != 0, and
the mask differs from the old one only on those bits), then measured. Both arms
were given their own pristine copy of `symbols.txt` and run **once each**, which
is T4's confound-1 rule; both copies converged to the same
`dd924cab…` hash afterwards, so the rewrite was deterministic and did not
confound the comparison.

## 7. NEW DEFECT, out of scope, flag not fix — the DS-form target ADDRESS is decoded wrong too

At the same site the splitter names the relocation target `lbl_82F446EE`. The
DS-form effective address is `hi<<16 | (lo & ~3)`:

```
lis r11, 0x82F4           ; ha
lwa r11, DS=0x46EC (r11)  ; the field is bits [15:2], not [15:0]
EA = 0x82F40000 + 0x46EC = 0x82F446EC
```

`0x82F446EC`, not `0x82F446EE`. The splitter read the whole low 16 bits
(`0x46EE`) as the displacement, i.e. it made the **same** [15:0]-vs-[15:2]
mistake on the analysis side that `write_coff` made on the writer side. The
damage is visible in dc3's checked-in config:

```
config/373307D9/symbols.txt:198199: sDefaultHoverTimer = .data:0x82F446EC; // type:object size:0x2
config/373307D9/symbols.txt:198200: lbl_82F446EE       = .data:0x82F446EE; // type:object size:0xA
```

`sDefaultHoverTimer` is `static int sDefaultHoverTimer = 600`
(`src/system/gesture/ArcDetector.cpp:11`) — **4 bytes**, recorded as `size:0x2`
and split two bytes in by a `lbl_` symbol that should not exist. The compiler's
own object anchors this site on `sDefaultHoverTimer`; the splitter anchors it
two bytes past it. That is an analysis-side (`tracker.rs` / `cfa.rs`) defect,
not a writer one, and it is **not** what T5 was asked to fix.

**Consequence the integrator must weigh, stated as an open question and not a
result.** If the MSVC linker treats REFLO as *additive* — which is what
`xex.rs`'s own comment at :2124-2129 asserts about COFF relocations generally —
then the two defects were **compensating** at this one site: `in-place 0x0000 +
lo(0x82F446EE) = 0x46EE` re-materialises `lwa` with the right displacement,
whereas after the fix `in-place 0x0002 + lo(0x82F446EE) = 0x46F0` yields `ld`
with the wrong one. If instead the linker *replaces* the field with `lo(S)`, the
fix is link-neutral and only the objdiff-visible bytes move. **Nobody has
relinked this tree**, in this task or in T2 (which left an equivalent REL14
`-offset_in_section` question open on the same grounds). Both questions want the
same experiment, and it should be one task:

1. fix the DS-form target-address decode on the analysis side (so
   `lbl_82F446EE` stops existing and `sDefaultHoverTimer` gets its 4 bytes back);
2. relink and check LNK2013/LNK1223 and the resulting instruction word, for
   REFLO-on-DS-form and for T2's `PpcRel14` fixup together.

Until then: the fix is measured correct against the **ruler**, which is what
moves every score in the project, and unproven against the **linker**, which
today nothing in the pipeline exercises.

## 8. What I did not do

- Did not touch `src/analysis/`. §7 is the reason it needs its own task.
- Did not add anything to `src/util/mod.rs` or to T3's `xex_reloc_tests.rs` —
  the test for this defect already lived there and now passes.
- Did not regenerate any `report.json`, did not rebuild `objdiff-cli`, did not
  write `target/release/dtk`, did not rebuild or re-split either project tree in
  place.

## 9. Reproduce

```bash
# corrected census (the load-bearing correction in §1)
grep -rhoE '\*/[[:space:]]+(lwa|lwau|ldu|stdu|ld|std)[[:space:]]' \
  <game>/build/<id>/asm | awk '{print $2}' | sort | uniq -c
grep -rnE '\*/[[:space:]]+(lwa|lwau|ldu|stdu)[[:space:]].*@(l|ha|h)\b' \
  <game>/build/<id>/asm      # -> the corrupted sites; dc3 has 1, rb3-xenon 0

# A/B, from the game's project root, with private config copies
<worktree>/scratch/bin/dtk-{base,fix} xex split <private-cfg>/config.yml <out-dir>
python3 findings/scripts/t4_obj_ab_diff.py <out-base>/obj <out-fix>/obj
```
