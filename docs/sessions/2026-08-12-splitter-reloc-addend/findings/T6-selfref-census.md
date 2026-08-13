# T6 — the self-reference census is a defect count of 332 / 148 (dc3) and 226 / 101 (rb3-xenon)

Date 2026-08-12. Tool: [`../tools/selfref_census.py`](../tools/selfref_census.py).
Read-only: no re-split, no cargo build, no write to any build tree or to
`target/release/dtk`. Everything below is first-hand from the shipped object and
asm trees; the command is at the end and reproduces the table in ~4 minutes.

## 1. Answer

| game | arm | objs | self-ref sites | fns | **real loss** | fns | **legitimate fn+0** | fns | unclassified | witness disagreement |
|---|---|---|---|---|---|---|---|---|---|---|
| dc3 | TARGET | 2223 | 350 | 154 | **332** | **148** | **18** | **6** | 0 | 0 |
| dc3 | OURS | 989 | 6 | 3 | 0 | 0 | 6 | 3 | 0 | 0 |
| rb3-xenon | TARGET | 3085 | 262 | 110 | **226** | **101** | **36** | **9** | 0 | 0 |
| rb3-xenon | OURS | 1204 | 20 | 10 | 0 | 0 | 20 | 10 | 0 | 0 |

The upper-bound columns (`self-ref sites` / `fns`) reproduce the validator's
FINDING 3 census **exactly, all four rows**, and the script exits non-zero if any
of them stops reproducing — a drifted object tree cannot be silently reported.
The real-loss and legitimate sets are disjoint per function on both games
(148 + 6 = 154; 101 + 9 = 110): no function mixes the two.

So the headline correction to the campaign's sizing:

- **dc3's Shape-1 defect is 148 functions, not 154 and not 22.** 6 of the 154 are
  legitimate address-of-own-entry and must not be counted or "fixed".
- **rb3-xenon's is 101 functions, not 110.**
- Every self-reference in a **compiler-produced** object on both games is
  legitimate. Ours has no addend loss to lose — as expected, since the loss is a
  property of the `write_coff` path.

Secondary, for campaign sizing: of the real-loss functions, **37 of 148 (dc3)**
and **21 of 101 (rb3-xenon)** are also present as function symbols in our own
object tree — i.e. that is the subset whose score can move today. The remainder
are in target-only units (`xdk/…`, `LIBCMT`, curl) that we do not compile.

## 2. Why the discriminator is sound

The addend is gone from the target `.obj` by construction (`write_coff`'s
`insn & 0xFFFF0000`, `src/util/xex.rs:2123-2138`), so nothing inside the object
can separate the classes. Two independent witnesses were used, and **both were
evaluated on every one of the 612 target sites**.

**W1 — the splitter's own in-memory ObjInfo, no re-split required.**
`split_write_obj_exe` (`src/cmd/xex.rs:2771`) builds `split_objs` **once** and
hands the same immutable slice to the `write_coff` loop (`:2790-2813`) and then
to the `write_asm` loop (`:2920-2945`); nothing mutates it in between. The asm
writer renders a relocation as `SYM+0xNNN@ha` (`src/util/asm.rs:357`), which is
exactly the `(symbol_idx, target.address - symbol_address)` pair recorded at
`src/analysis/tracker.rs:860`. **`build/<id>/asm/**.s` is therefore the
pre-`write_coff` ObjInfo addend, serialised to text, from the same invocation
that wrote `obj/**.obj`** (both are outputs of the one `dtk xex split` ninja edge
— `dc3-decomp/build.ninja` rule `split`). This is the evidence the task asked
for, obtained without rebuilding the splitter.

**W2 — the original retail immediate.** The byte comment on each asm line
(`/* 8289B36C 0088FD6C  3D 80 82 8A */`) carries the *original* instruction word;
`write_coff` zeroes the immediate only in its own output buffer. So the real
`@ha`/`@l` halves survive and the materialised address can be recomputed with no
reference to the anchor at all: REFHI must equal `((T + 0x8000) >> 16) & 0xFFFF`,
REFLO must equal `T & 0xFFFF`, for `T = fn_start + addend`. DS-form opcodes
(primary 58/62) are compared on the top 14 bits only, since their low two bits
are opcode extension (validator FINDING 8) — no site in either game needed that
path.

**Result: W1 and W2 agree on 612 / 612 target sites. Zero disagreements, zero
unclassified.** Every self-reference is also a clean REFHI+REFLO pair carrying
the same addend (dc3 166+166 loss / 9+9 legit; rb3-xenon 113+113 / 18+18), which
the script asserts.

For the OURS trees no asm exists and none is needed. MSVC's convention is an
anchor symbol whose *value* sits at the target address; the validator measured
the PAIR displacement zero in 342,386 of 342,386 REFHI/REFLO (FINDING 2). A
compiler self-reference with **both** addend channels zero — in-place immediate
and PAIR displacement — therefore references fn+0 exactly. All 26 of ours do.

### The two acceptance cases, measured

```
?HandleEventResponse@SaveLoadManager@@QAAXPAVHamProfile@@H@Z  (dc3 TARGET)
  fn+0x25c REFHI  addend 0x164  real_loss   lis  r12, "?HandleEventResponse…"+0x164@ha
  fn+0x264 REFLO  addend 0x164  real_loss   addi r12, r12, "?HandleEventResponse…"+0x164@l
  fn_va 0x8289b110; original words 3D80828A / 398CB274 -> 0x8289B274 = fn+0x164  (W2 agrees)

?CharTerminate@@YAXXZ  (dc3 OURS, and 3 more rb3-xenon OURS objects)
  fn+0xc  REFHI  legitimate   imm=0 and PAIR displacement=0 -> anchor value IS the target
  fn+0x14 REFLO  legitimate   idem
```

## 3. Instruction context is a *worse* discriminator — measured, not assumed

The task offered instruction context (switch dispatch feeds `lbzx/lhzx` + `add`
+ `mtctr` + `bctr`) as the fallback route. It was computed alongside as an
advisory tag, and it is wrong on 9 of dc3's 350 sites (2.6%):

| game | real_loss with dispatch context | legitimate with dispatch context |
|---|---|---|
| dc3 | 324 / 332 | 1 / 18 |
| rb3-xenon | 222 / 226 | 1 / 36 |

- The 8 dc3 real-loss sites **without** dispatch context are not jump tables at
  all: `_fsopen+0xF8`, `_wfsopen+0xF8`, `_UnwindNestedFrames+0x64` (twice) — an
  interior block address materialised and passed in a register
  (`addi r4, r10, _fsopen+0xF8@l`). Real addend loss, no `bctr` anywhere near.
  A context-only classifier would have called all 8 legitimate.
- The 1 legitimate site with dispatch context is `?SynthTerminate@@YAXXZ` on both
  games — an unrelated `mtctr`/`bctr` inside the 8-instruction window.

So: **do not classify these by opcode neighbourhood.** The addend witnesses are
exact; the context tag is reported only because the comparison is itself a
result.

## 4. Shape of the defect

| | dc3 | rb3-xenon |
|---|---|---|
| real-loss sites per function | 2 ×138, 4 ×5, 6 ×2, 8 ×3 | 2 ×93, 4 ×5, 6 ×2, 8 ×1 |
| distinct nonzero deltas | 110 | 85 |
| delta min / median / max | 0x14 / 0xec / 0x5278 | 0xc / 0x104 / 0x5274 |

The overwhelming mode is one HI/LO pair per function (138/148 and 93/101); the
multi-site functions are large dispatchers (`Curl_setopt`,
`XInput2InterpretBytecodes`, `D3DXShader::Compiler::ImportExpression` — 8 sites
= 4 tables each). Deltas span 0xc to 0x5278, so no "small offset" shortcut
exists: any fix has to carry the real value.

## 5. Two things found while building this that the campaign should know

**(a) rb3-xenon target `.obj` files are NOT pristine splitter output.** A
post-SPLIT ninja step runs `scripts/obj_target_symbol_renamer.py --batch
--apply`, rewriting `fn_<addr>` symbols in the objects to MSVC mangled names
from `scripts/target_symbol_map.json` (`rb3-xenon/configure.py:680-700`). 1822 of
3085 objects are rewritten after the split. The renamer matches on the symbol
**name** `fn_%08X`, not on the address, so the obj↔asm join has to go through
that map by name. Any A/B that diffs rb3-xenon objects must stage this step too,
or the "after" arm will differ from the "before" arm for a reason that has
nothing to do with the splitter.

**(b) The rb3-xenon asm VA column is not a reliable function address.** In
`build/45410914/asm/xdk/xmic/xmicapi.s` the `.fn fn_82C27048` block prints its
first instruction at `0x82C26F98` — 0xB0 below the address
`config/45410914/symbols.txt` gives for that same symbol — and the drift is not
uniform across the unit (the preceding block is also off by 0xB0, earlier ones
are not). 106 of 262 rb3-xenon sites needed the symbols.txt address instead. dc3
needed it on 0 of 350. The *addend text* is unaffected (it is an offset, not an
address), so W1 never depended on this; only W2 did, and using the asm column
produced 8 spurious disagreements before the fix. **This is unexplained and is
not covered by anything in the session doc — flagging it rather than sitting on
it.** It does not change any number in §1 (all 262 rb3-xenon sites classify with
both witnesses agreeing once the address comes from symbols.txt), but somebody
should find out why, because "the asm VA column is wrong on rb3-xenon" is a
claim with consequences beyond this task.

## 6. Provenance and its caveats

| tree | mtime range |
|---|---|
| dc3 `asm/` (2223 files) | 2026-08-10 07:04:56 → 07:04:58 |
| dc3 `obj/` (2223 files) | all ≤ 2026-08-10 07:04:58 except one |
| rb3-xenon `asm/` (3085) | 2026-08-12 00:46:32 → 00:46:34 |
| rb3-xenon `obj/` (3085) | ≤ 00:46:35 |

Two mtime anomalies, both explained and neither affecting the result:

- dc3 `build/373307D9/obj/system/rndobj/MetaMaterial.obj` carries a bogus
  **2030-01-01** mtime (deliberately touched by some other tool). It holds no
  self-reference site, so it is outside this census entirely.
- 1822 rb3-xenon objects are 1s newer than the newest `.s`. That is the symbol
  renamer of §5(a), which runs after the split — not a second split.

`obj/` files are written with `write_coff_if_changed`, so an `.obj` older than
the `.s` means "content unchanged", not "stale". The load-bearing evidence is
content, not timestamps: **all 612 sites found their exact instruction offset in
the asm, and the original immediate matched the ObjInfo addend at every one.** A
mismatched split would not survive that.

## 7. Reproduce

```bash
python3 docs/sessions/2026-08-12-splitter-reloc-addend/tools/selfref_census.py \
    --json <scratch>/selfref_sites.json
# exits 1 if any of the four upper-bound totals stops reproducing,
# if either acceptance case changes class, or if a HI/LO pair breaks.
```

Defaults locate `dc3-decomp` and `rb3-xenon` as sibling checkouts (works from the
main checkout and from a `.worktrees/` worktree); override with `--dc3` /
`--rb3-xenon` or `$DC3_ROOT` / `$RB3_XENON_ROOT`. `--verbose` prints every
unclassified or disagreeing site (currently none). The per-site JSON carries
`addend`, `fn_va`, `fn_va_source`, `orig_word`, the asm line, and
`dispatch_context` for each of the 638 sites.

The negative control was run: with `UPPER_BOUND` perturbed and a deliberately
wrong acceptance class injected, the script reports both and exits 1.
