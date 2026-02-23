# CFA Cleanup Plan

Date: 2026-02-21

Based on a staff-level audit of `cfa_consolidation_review.md` against the actual codebase. All claims were verified against source; discrepancies are noted inline.

## Audit Summary

The consolidation review is **substantively accurate** — all 12 Layer 1 features exist and work, all architectural types/traits are present, fork relationship numbers are exact (118 ahead, 15 behind). Five material issues were found:

| Issue | Severity | Section |
|---|---|---|
| Test count is 145, not 116 (28 core `cfa.rs` tests omitted) | Factual error | [1](#1-fix-test-inventory) |
| `#[default]` on `Legacy` contradicts runtime default of `Candidate` | Latent bug | [2](#2-fix-default-inconsistency) |
| "Added ~9,100 lines" conflates added vs total | Misleading | [3](#3-clarify-line-counts) |
| Stack-slot tracking is ~80 lines, not ~180 | Overcount | [3](#3-clarify-line-counts) |
| Candidate vs Legacy behavioral difference on DC3 is unknown | Blocking question | [4](#4-run-candidate-vs-legacy-comparison) |

## Phase 1: Answer the Blocking Question

Everything else depends on this.

### 4. Run Candidate vs Legacy Comparison

Run `dtk xex split` on DC3 in both modes and diff the output:

```bash
# Candidate (current default)
DTK_CFA_PIPELINE_MODE=candidate dtk xex split <dc3.xex> /tmp/candidate_out/

# Legacy
DTK_CFA_PIPELINE_MODE=legacy dtk xex split <dc3.xex> /tmp/legacy_out/

# Diff
diff -rq /tmp/candidate_out/ /tmp/legacy_out/
```

**If output is identical:** Candidate seed discovery adds no behavioral value for DC3. The `strict_code_seeds` and `strict_symbol_size_seeds` filters are dead code paths for our use case. Proceed to Phase 2 with maximal simplification.

**If output differs:** Investigate which functions are affected. Determine whether Candidate's output is more correct (compare against known-good function boundaries). This changes the simplification calculus — the pipeline abstraction may be earning its keep.

## Phase 2: Code Fixes (independent of Phase 1 answer)

### 1. Fix Test Inventory

The consolidation review claims 116 tests. Actual count is **145**:

| Suite | Claimed | Actual | Notes |
|---|---|---|---|
| `cfa_tests.rs` | 20 | 20 | |
| `pipeline.rs` | 15 | 15 | |
| `vm2.rs` | 25 | 25 | |
| `vm.rs` | 3 | **6** | 3 uncounted |
| `xex.rs` | 5 | 5 | |
| `slices.rs` | 3 | **7** | 4 uncounted |
| `cfa.rs` | **omitted** | **28** | Core CFA tests entirely missing from inventory |
| `mod.rs` | **omitted** | **13** | Module-level tests missing |
| Other (`tracker`, `split`, `asm`, `disasm_tests`, `diff`, `toposort`, `relocations`, `addresses`, `dol`) | **omitted** | **26** | |
| **Total** | **116** | **145** | +29 |

Shadow-specific tests: 34 actual vs 31 claimed.

**Action:** Update `cfa_consolidation_review.md` test table to reflect actual counts.

### 2. Fix `#[default]` Inconsistency

Current state in `cfa.rs`:

```rust
// Line 158 — runtime constant
const DEFAULT_PIPELINE_EXECUTION_MODE: PipelineExecutionMode = PipelineExecutionMode::Candidate;

// Lines 160-166 — Rust derive
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub(crate) enum PipelineExecutionMode {
    #[default]
    Legacy,      // <-- #[default] says Legacy
    Shadow,
    Candidate,
}
```

The `detect_functions()` entry point uses the constant (Candidate wins at runtime), but any code calling `PipelineExecutionMode::default()` would silently get `Legacy`. This is a latent bug.

**Action:** Either:
- (a) Move `#[default]` to `Candidate` to match runtime intent, or
- (b) Remove the `Default` derive entirely since the explicit constant is the intended behavior

Option (b) is safer — it makes any accidental `.default()` call a compile error instead of a silent wrong answer.

### 3. Clarify Line Counts

The review says "added ~9,100 lines to `src/analysis/`" but the directory total is ~13,095. The word "added" implies a delta; the number is closer to the total. Same for util (~4,723 total vs ~2,700 claimed).

Individual feature counts have ±20% variance:

| Feature | Claimed | Actual | Direction |
|---|---|---|---|
| vm.rs stack-slot tracking | ~180 | ~80 | Overstated 2x |
| slices.rs possible-blocks | ~60 | ~111 | Understated 2x |
| slices.rs epilogue detection | ~50 | ~88 | Understated |
| split.rs CRT splitting | ~170 | ~143 | Slight overcount |
| All others | — | — | Within 20% |

The "~900 lines that affect production output" headline is approximately correct (individual items roughly sum to that), but the errors are offsetting.

**Action:** Update the review to use "total" instead of "added" (or compute actual deltas via `git diff --stat` against the pre-CFA base commit), and correct the stack-slot tracking count.

## Phase 3: Simplification (depends on Phase 1 answer)

### If Candidate == Legacy on DC3 (expected)

Full simplification. Remove everything that doesn't affect output:

| What to remove | Lines | Risk |
|---|---|---|
| `vm2.rs` entirely | 2,151 | None — never in production path |
| Shadow mode from `PipelineExecutionMode` enum | ~5 | None |
| `detect_functions_with_shadow_config()` and shadow gate types | ~470 | None |
| `PipelineDigest` diff infrastructure in `pipeline.rs` | ~330 | None |
| `CandidatePipelineEngine` struct + trait impl | ~160 | Low — inline seed logic |
| `CfaPipelineEngine` trait itself | ~25 | Low — only one impl remains |
| `LegacyPipelineEngine` struct (inline into `AnalyzerState`) | ~80 | Low |
| Shadow-specific tests (~34 tests) | ~2,480 | None |
| Scripts: `dc3_cfa_parity_smoke.sh`, `cfa_candidate_strict_soak.sh`, `cfa_cutover_gate.sh` | ~700 | None |
| **Total removable** | **~6,400** | |

What remains after removal:
- `pipeline.rs` shrinks to utility types (`SeedSource`, helper fns) — or gets folded into `cfa.rs`
- `cfa.rs` keeps `detect_functions()` calling seed discovery + slice exploration + finalize directly
- Layer 1 analysis fixes stay untouched (they're in `vm.rs`, `slices.rs`, `mod.rs`, `split.rs`, `xex.rs`)
- ~111 non-shadow tests stay

End state: **~6,700 lines removed**, leaving the production-relevant analysis at ~11,000 lines total (down from ~17,800).

### If Candidate != Legacy on DC3

Smaller simplification — keep the Candidate engine but remove Shadow:

| What to remove | Lines |
|---|---|
| `vm2.rs` entirely | 2,151 |
| Shadow mode + gate types | ~475 |
| Shadow-specific tests | ~2,480 |
| Scripts (shadow parity only) | ~700 |
| **Total removable** | **~5,800** |

Keep `CfaPipelineEngine` trait with both Legacy and Candidate impls as a useful abstraction for switching between them.

## Phase 4: Upstream Preparation

### What rjkiv Would Want

Given the structural git incompatibility (encounter v1.8.0 merge + rjkiv's `c1b1d95` deletion), a direct merge is impractical. Strategy:

1. **Cherry-pick Layer 1 fixes as individual PRs** — each one is self-contained:
   - `.pdata` tail-call guard (~30 lines)
   - Stack-slot tracking (~80 lines)
   - `Stwux` prologue variant (~1 line)
   - `.rdata` absolute jump tables (~10 lines)
   - Jump table confidence classification (~60 lines)
   - Block discovery caps (~40 lines)
   - Epilogue sequence detection (~90 lines)
   - Possible-blocks speculative pass (~110 lines)
   - CRT initializer splitting (~170 lines in `split.rs`)
   - REL24 addend preservation (~40 lines in `xex.rs`)
   - `__unwind$` COMDAT marking (~30 lines in `xex.rs`)
   - `.CRT` section renaming (~10 lines in `xex.rs`)
   - Symbol class fixes (~15 lines in `xex.rs`)

2. **Do not upstream Layer 2 or 3** — the pipeline abstraction and shadow infrastructure are internal migration tooling, not features rjkiv needs.

3. **Include tests with each PR** — the ~85 non-shadow tests map cleanly to Layer 1 features.

### Commit Naming

Name cherry-picked PRs to match rjkiv's style (check their recent commit messages for convention). Each PR should be one logical fix with its associated test(s).

## Open Questions

- [ ] Does Candidate produce different output from Legacy on DC3? *(Phase 1)*
- [ ] Is the `ValueFact2` type system worth preserving as a design reference for a future VM rewrite, or is the commit history sufficient? *(Inform Phase 3)*
- [ ] What is rjkiv's appetite for upstream PRs right now? *(Inform Phase 4 timing)*
