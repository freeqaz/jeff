# jeff (freeqaz fork)

## freeqaz fork

This is a fork of [rjkiv/jeff](https://github.com/rjkiv/jeff), maintained as part of the
[milohax](https://github.com/milohax) Dance Central 3 / Rock Band 3 decompilation work. It
tracks rjkiv/jeff and layers on additional fixes and features needed for those projects.

Thematic summary of what has changed here since diverging from rjkiv/jeff (133 commits):

- **XEX/COFF split robustness** — numerous fixes to function-symbol bounds (oversized/undersized
  clamping, phantom-overlap pruning, funclet-truncation growth), jump-table handling (crash fixes,
  bounds inflation, absolute tables in `.rdata`), tail-block detection/merging, CRT/REL section
  handling, and a new `FindXboxVtables` MSVC C++ vtable-detection pass wired into the split/disasm
  pipelines, so `xex split` runs end-to-end on real RB3 retail XEX images.
- **CFA (control-flow-analysis) rewrite** — a multi-phase "vm2" rearchitecture (phases r1-r7)
  introducing a shadow/candidate pipeline with native opcode coverage, telemetry, and
  promotion/parity gates, eventually promoting the candidate/native path to default and replacing
  the legacy shadow VM.
- **CFA test suite** — ~20 hand-built CFA tests plus matching m2c/Ghidra decompiled reference
  output and disassembly fixtures, along with cutover/parity workflow scripts
  (`scripts/dc3_cfa_parity_smoke.sh`, `scripts/cfa_cutover_gate.sh`, `scripts/xex_info_mode_matrix.sh`).
- **DWARF/debug-info and linking fixes** — demangling, nested struct/enum support, enum-size
  accounting, ICF-merged symbol naming, and assorted DTK linking fixes (section merge, jump-table
  scoping, COFF symbol class fixes).
- **Misc hardening** — REL/RELs relocation edge cases, Wii Menu (BootStage) DOL loading support,
  clippy/cargo-deny cleanup, dependency bumps, and routine upstream version bumps (1.7.1 → 1.9.2).

The canonical push target for this fork is [freeqaz/jeff](https://github.com/freeqaz/jeff) (`main`).

> **This is a fork of [rjkiv/jeff](https://github.com/rjkiv/jeff)** with additional fixes and features for the [Dance Central 3 decomp](https://github.com/milohax/dc3-decomp). It stays in sync with upstream and is available as a drop-in replacement.

## Fork additions

**Xbox 360 linking pipeline** — Generate linkable COFF objects and produce a hybrid executable via `ninja link` (decomp `.obj` files where functions match, original object code elsewhere). Requires the Xbox 360 SDK linker under Wine.

**Tail block detection & merging** — The MSVC compiler sometimes places out-of-line code (loop exits, error paths) after the `.pdata`-reported function end. This fork detects these tail blocks and merges them back into their parent function, fixing false function boundaries that would otherwise break CFA analysis.

**Section merge for split objects** — When a translation unit has multiple fragments of the same section (e.g. `.pdata`), they are now merged into a single section in the output COFF rather than producing duplicate sections that the linker rejects.

**COFF symbol fixes** — `Unknown`+`Global` symbols (such as save/restore sled entry points like `__savegprlr_14`) now emit `IMAGE_SYM_CLASS_EXTERNAL` instead of `IMAGE_SYM_CLASS_LABEL`, and jump table symbols are emitted with `Global` scope so the linker can resolve cross-object references.

**Jump table analysis improvements** — Support for absolute jump tables in `.rdata` sections, fixes for jump table bounds inflation when the VM over-estimates table size, and crash fixes for edge cases in the jump table VM.

**CFA cutover workflow scripts** — Added repeatable DC3 parity/cutover checks:
- `scripts/dc3_cfa_parity_smoke.sh`: baseline/shadow/candidate split parity with optional strict candidate flags and optional shadow VM telemetry thresholds.
- `scripts/cfa_cutover_gate.sh`: consolidated legacy/default/native-VM2/candidate-strict `cfa_tests` gates plus default/strict DC3 parity runs.
  - Current default telemetry gate is strict zero-delta (`total_diffs=0`, `bridged_steps=0`) on sampled shadow runs.
- `scripts/xex_info_mode_matrix.sh`: real-XEX parser compatibility matrix across `legacy`/`shadow`/`candidate` modes.
- `scripts/xex_split_ab_compare.sh`: A/B a change against a real project's split output — runs `xex split` with two dtk binaries and reports units / objects byte-identical / objects changed, so "does this move output?" is measured rather than argued. Stages an isolated copy of the project config so a `symbols:` key is rewritten in the copy and never in the project tree, and takes both binaries as arguments so a shared `target/release/dtk` other work depends on is never overwritten.
  - Note: `scripts/xex_split_mode_matrix.sh` currently exits 2 on this checkout because `scripts/dc3_cfa_parity_smoke.sh` and `scripts/cfa_cutover_gate.sh` (documented above) are not present in the tree.

**Upstream sync** — Includes all upstream decomp-toolkit changes through v1.8.0 (DWARF dump improvements, `skip_cfa_ranges` config option, relocation fixes, and more).

---

Forked from and inspired by [encounter's GC/Wii decomp toolkit](https://github.com/encounter/decomp-toolkit), jeff is
a decomp-toolkit meant for disassembling Xbox 360 executables (xexes). It aims to assist potential Xbox 360 decompilation projects with
the same benefits that encounter's toolkit provides, including function boundary analysis, relocation restorations, splits, and integration
with other decompilation tools like [objdiff](https://github.com/encounter/objdiff) and
[decomp.me](https://decomp.me).

https://youtu.be/0OzXZGA1k3s

Much like the original GC/Wii decomp toolkit, jeff aims to automate as much of the decompilation setup process as possible,
allowing developers to spend less time configuring a project and more time focusing on what matters most in a decomp: matching code.

Jeff was originally created by [rjkiv](https://github.com/rjkiv) with the goal of starting up a [decomp for Dance Central 3](https://github.com/rjkiv/dc3-decomp),
but has the potential to work with several other Xbox 360 games.

**DISCLAIMER**: Although we genuinely tried our best to get jeff working with the pool of xexes we had to test with,
**we make absolutely zero guarantees that this will work out of the box with every last Xbox 360 game! Expect bugs!**

If you spot a bug or crash, please submit an issue, and we will try our best to help you through it.

For use in a new decompilation project, see [jeff-template](https://github.com/rjkiv/jeff-template), which provides a
project structure and build system that uses jeff under the hood.

## Features
- Can extract an exe from an xex using: `xex extract <xex location>`.
You supply the xex, and the underlying exe will be extracted to the same directory - it'll even have its original name the developers gave it!
- Can print out information about an xex using: `xex info <xex location>`.
This aims to replicate the behavior of the original xextool by xorloser.
- Can write down inferred splits, symbols, and COFFs from an xex using: `xex info <config.yml>`.
This is NOT meant to be run on its own, but rather part of a build system, such as the one in the dtk-template above.

## Known Issues/Hacks
- Xexes that were LZX compressed are not currently supported.
- Jump table detection works a lot differently for an Xex than it does a GC/Wii DOL.
There are multiple different kinds of jump table versions that MSVC likes to use, and the code that detects them is rather hacky.
The code checks for a specific sequence of known instructions and infers the jump table type from there.
This can result in some jump tables being "guessed" or missed during function detection.
- When parsing .map files, the last split of a section will not get added.
This is because during development, I found that the last split would sometimes conflict with the inferred boundaries of nearby objects/symbols, which would cause errors.
So, if you are using jeff and your game has a map, you will have to remember to manually add the last split of each of your exe's sections.
- Parsing/applying .pdb files currently has limited support.
- Trying to link the generated COFFs into a final exe and comparing sections of it against the original extracted exe (like what the GC/Wii toolkit does with elfs/dols)
is currently unsupported, as it was out of the initial scope of the project.
- Because this was forked from encounter's GC/Wii toolkit, there is naturally still a lot of loose GC/Wii tailored code in this codebase that needs removing/refactoring.

## Want to contribute?
Whether you want to add a new feature, or would like to fix one of the known issues, I would love your contribution!
Feel free to fork this repo and submit a PR containing your change. Every little improvement helps jeff become a better resource for the greater decomping community!

Although this is an Xbox 360 centric repo, feel free to join the [GC/Wii Decompilation Discord](https://discord.gg/hKx3FJJgrV) as well!

## Acknowledgements
- [encounter](https://github.com/encounter) - not only for his work on the original GC/Wii toolkit as well as several other decompilation tools, but for his constant help and guidance throughout jeff's creation process
- [The RB3 Decomp and its contributors](https://github.com/DarkRTA/rb3) - for providing additional guidance and suggestions throughout development
