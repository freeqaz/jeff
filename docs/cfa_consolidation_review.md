# CFA Consolidation Review

Date: 2026-02-21

## Context

The `cfa_fix` branch has been merged into `dev` and `main` on `fork/` (freeqaz/jeff). This document captures the current state of the codebase after 118 commits of CFA work, and outlines the next phase: auditing the tooling output, understanding what the work accomplished, and deciding what to simplify.

## What Was Built

The CFA work added ~11,100 net lines (+11,556 / -500) across `src/analysis/` and `src/util/` (split.rs + xex.rs), totaling ~15,500 lines in the affected files. It can be broken into three layers:

### Layer 1: Analysis Fixes (load-bearing)

These changes directly affect `dtk xex split` output for DC3.

| File | Change | Lines | Purpose |
|---|---|---|---|
| `vm.rs` | Stack-slot tracking (`stw`/`lwz` spill/reload) | ~80 | Recover values across MSVC register-pressure stack shuffles |
| `vm.rs` | Register-copy provenance preservation | ~20 | Preserve stack-slot provenance through `or rX, rY, rY` renames |
| `slices.rs` | `.pdata` tail-call guard | ~30 | Prioritize known function bounds over heuristic tail-call detection |
| `slices.rs` | Possible-blocks speculative pass | ~60 | Discover unreachable code (e.g., switch cases) inside known function ranges |
| `slices.rs` | Block discovery caps | ~40 | Prevent pathological growth (MAX_POSSIBLE_BLOCK_EXPLORES=512, MAX_TOTAL_BLOCKS=4096) |
| `slices.rs` | Epilogue sequence detection | ~50 | Detect `mtlr`/`addi`/`or` epilogue patterns for function boundary hints |
| `slices.rs` | `Stwux` prologue variant | ~5 | Xbox 360 debug builds use `stwux` in addition to `stwu` |
| `mod.rs` | `.rdata` absolute jump tables | ~10 | MSVC places absolute jump tables in `.rdata`, not `.text` |
| `mod.rs` | Jump table confidence classification | ~80 | Internal `High`/`Medium`/`Low` scoring replaces panic-on-unknown |
| `mod.rs` | Graceful truncation on invalid entries | ~20 | Break early instead of panic when table entry is out of bounds |
| `split.rs` | CRT initializer splitting | ~170 | Co-locate `.CRT$XCU` entries with their `??__E*` initializer functions |
| `split.rs` | COMDAT exclusions for CRT symbols | ~30 | Prevent linker `/OPT:REF` from stripping CRT initializers |
| `xex.rs` | `.CRT` -> `.CRT$XCU` section renaming | ~10 | MSVC expects `$XCU` suffix for CRT init arrays |
| `xex.rs` | REL24 addend preservation for COMDAT | ~40 | Correct branch displacement computation for COMDAT sections |
| `xex.rs` | `__unwind$` COMDAT marking | ~30 | Exception handler symbols get proper COMDAT sections |
| `xex.rs` | `lbl_*` symbol globalization | ~20 | Auto-generated labels need global scope for hybrid linking |
| `xex.rs` | Symbol class fixes (Global+Unknown -> EXTERNAL) | ~15 | Correct COFF symbol storage class for external references |

**Total: ~900 lines of changes that affect production output.**

### Layer 2: Pipeline Architecture (structural)

A phased pipeline abstraction and candidate engine, built to enable safe migration from the legacy code path.

| File | What it is | Lines |
|---|---|---|
| `pipeline.rs` | `CfaPipelineEngine` trait, `LegacyPipelineEngine`, `CandidatePipelineEngine`, digest/diff types | 1,283 |
| `cfa.rs` additions | `PipelineExecutionMode` enum, `detect_functions_candidate()`, `detect_functions_with_shadow_config()`, invariant validation | ~800 |

The Candidate engine reimplements seed discovery (with optional `strict_code_seeds` and `strict_symbol_size_seeds` filtering) but delegates slice exploration, finalization, and apply to the same `AnalyzerState` methods as Legacy. The two engines share 3 of 4 phase implementations.

`PipelineExecutionMode::Candidate` is now the default. Legacy is available via `DTK_CFA_PIPELINE_MODE=legacy` env var.

### Layer 3: Shadow Execution & VM2 (verification scaffolding)

Infrastructure that runs legacy and candidate in parallel, diffs their output, and auto-falls-back on mismatch. Used during development to prove parity.

| File | What it is | Lines |
|---|---|---|
| `vm2.rs` | Second value lattice (`ValueFact2 = {Value2, Provenance2, Confidence2}`), shadow native opcode handlers, legacy bridge, runtime shadow reporting | 2,151 |
| `cfa.rs` additions | Shadow gate config, env-var parsing, telemetry logging, fallback decision logic | ~470 |
| `pipeline.rs` additions | `PipelineDigest` diff/comparison infrastructure | ~330 |
| Shadow-specific tests | ~50 tests validating shadow parity behavior | ~2,480 |
| `scripts/` | `dc3_cfa_parity_smoke.sh`, `cfa_candidate_strict_soak.sh`, `cfa_cutover_gate.sh` | ~800 |

VM2 cannot replace the legacy VM — it has no branch resolution, jump table detection, or state splitting. It was designed as a shadow verifier. In the production path (`Candidate` mode), VM2 is never instantiated.

## Current Architecture

```
detect_functions()
  ├── Candidate (default) ──> candidate_seed_discovery() ──┐
  │                                                         │
  └── Legacy (env escape) ──> phase_seed_discovery() ──────┤
                                                            │
                              ┌─────────────────────────────┘
                              v
                    process_function_at()
                              │
                              v
                         VM::step()          <── the one working VM
                              │
                              v
                    phase_discover_remaining()
                              │
                              v
                    phase_finalize_and_validate()
```

Shadow mode (`PipelineExecutionMode::Shadow`) exists between Legacy and Candidate in the enum but is not the default. It runs both engines, diffs output, and picks one. This was the migration safety net.

## Fork Relationship

| Remote | Repository | Relationship |
|---|---|---|
| `origin` | rjkiv/jeff | Xbox 360 decomp toolkit. We forked from here. |
| `fork` | freeqaz/jeff | Our fork. 118 commits ahead, 15 behind rjkiv. |
| `upstream` | encounter/decomp-toolkit | Original GC/Wii toolkit. Not relevant for merge. |

Our fork merged `encounter/decomp-toolkit v1.8.0` early on, which brought in GC/Wii code that rjkiv subsequently deleted in their `c1b1d95` commit. This makes a naive `git merge` between our fork and rjkiv/jeff structurally incompatible on dozens of files.

Decision: staying on our own fork for now. Will coordinate with rjkiv before attempting any merge.

## Test Coverage

| Suite | Count | What it validates |
|---|---|---|
| `cfa.rs` | 28 | Shadow gate config parsing, pipeline mode selection, candidate/legacy parity |
| `cfa_tests.rs` | 20 | Real DC3 function snippets: jump table types, stack tracking, tail calls |
| `pipeline.rs` | 15 | Legacy/Candidate parity, seed refinement, shadow diff correctness |
| `vm2.rs` | 25 | Shadow native opcode handlers, legacy bridge, compare semantics |
| `vm.rs` | 6 | Stack-slot provenance, register-rename, jump table propagation |
| `mod.rs` | 13 | Jump table detection, confidence classification, graceful truncation |
| `slices.rs` | 7 | `.pdata` guard precedence, block discovery, epilogue detection |
| `xex.rs` | 5 | COFF output: symbol classes, COMDAT sections, section handling |
| `split.rs` | 4 | CRT initializer splitting, COMDAT exclusions |
| `tracker.rs` | 2 | Analysis tracking infrastructure |
| **Total** | **125** | |

Of these, ~50 tests (all of `vm2.rs`, shadow/pipeline/candidate tests in `cfa.rs` and `pipeline.rs`) validate shadow execution behavior specifically. The remaining ~75 test actual analysis correctness.

## Next Phase: Audit & Evaluate

### 1. Validate tooling output

Run a fresh `dtk xex split` on DC3 and compare against the build system's expectations. Identify:
- Functions with incorrect boundaries (wrong start/end)
- Missing or mis-sized jump tables
- Crashes or panics during analysis
- Symbols with wrong scope or storage class in COFF output

This is the ground truth for whether the CFA work is correct and complete.

### 2. Measure what changed

Quantify the difference between our fork's output and what rjkiv/jeff's `origin/main` would produce on the same binary. How many functions are affected? How many were broken before and work now? Are there any regressions?

### 3. Evaluate the layers

With audit data in hand, decide for each layer:

**Layer 1 (analysis fixes):** Are all the fixes correct? Are there remaining bugs to fix?

**Layer 2 (pipeline architecture):** The Candidate engine's seed discovery is the only behavioral difference from Legacy. Is the trait/engine abstraction worth its weight, or should the seed filtering logic be inlined into `AnalyzerState` directly?

**Layer 3 (shadow/VM2):** The shadow infrastructure proved parity during migration. Now that Candidate is the default, what is the ongoing value?
- VM2's type system (`ValueFact2` with provenance + confidence) is architecturally cleaner than the legacy VM's `GprValue`. If a future VM rewrite is planned, these types could serve as the starting point.
- The shadow execution pattern itself (run old and new in parallel, diff automatically) could be reused for future changes.
- Alternatively, the evidence is captured in docs and commit history, and the code could be removed to reduce maintenance surface.

### 4. Decide on simplification scope

Options range from minimal (remove only dead scripts) to maximal (remove VM2 + pipeline trait + shadow mode, inline Candidate seed logic into AnalyzerState). The audit results should inform which level of simplification is appropriate.

## Open Questions

- Are there DC3 functions that the current CFA gets wrong?
- Does the Candidate seed discovery actually produce different output from Legacy on DC3, or are the `strict_*` filters effectively unused?
- What is the ongoing maintenance cost of carrying VM2 and shadow infrastructure?
- Is a future VM rewrite (replacing `GprValue` with `ValueFact2`-style types in the production VM) on the roadmap, or was VM2 purely a verification tool?
- What would rjkiv want from a PR? The analysis fixes only? Or is the pipeline architecture interesting to them too?
