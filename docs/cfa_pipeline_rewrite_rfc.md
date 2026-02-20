# CFA Pipeline Rewrite RFC + Shadow Plan (B8)

## Status

- Date: 2026-02-20
- Owner: `cfa_fix`
- Phase: S1 complete, S2 shadow-gating baseline active
- Initial scaffold: `src/analysis/pipeline.rs`

Current implementation snapshot:
- Legacy analyzer routed through explicit phase methods in `AnalyzerState`.
- `analysis::pipeline` now exposes phase outputs and a run report model.
- Digest comparison now includes categorized diff entries and summary counters.
- Selected real-fixture shadow parity test is active with zero-diff gate.

## Problem statement

Current CFA flow in `src/analysis/cfa.rs` and `src/analysis/slices.rs` is effective but tightly coupled:

- discovery, slicing, jump-table resolution, and symbol application interleave state mutation,
- invariants are mostly implicit,
- side-by-side engine comparison is not yet a first-class workflow.

## Goals

1. Define strict phase boundaries and explicit phase I/O contracts.
2. Add deterministic shadow-comparison infrastructure for legacy vs rewritten pipeline.
3. Keep current behavior as baseline until parity is proven.

## Non-goals

1. No immediate replacement of legacy analyzer in this phase.
2. No public CLI changes.

## Proposed phase model

### P0: Seed discovery

Inputs:
- known functions (`.pdata`, symbols, imports)
- section metadata / skip ranges

Outputs:
- candidate function starts with provenance

### P1: Slice exploration

Inputs:
- candidate starts
- section bytes + relocations
- VM branch facts

Outputs:
- provisional function slices
- possible blocks
- jump-table references (unresolved)

### P2: Function finalization

Inputs:
- provisional slices
- known function map

Outputs:
- finalized function ranges
- tail-call/tail-block merge decisions

### P3: Symbol/materialization

Inputs:
- finalized function and jump-table map

Outputs:
- object symbol/section updates (apply step)

## Invariant contract

Pipeline output must satisfy:

1. Finalized functions are in code sections and non-overlapping.
2. Function ranges are in-bounds.
3. Jump tables are non-zero, in-bounds, and not in BSS.
4. Deterministic output for identical input object/config.

The legacy analyzer now exposes invariant validation so these checks can become shadow gates.

## Shadow execution design

### Digest format

Use a stable digest of:

- `functions: start -> end`
- `jump_tables: address -> size`

Diff categories:

1. missing/extra functions
2. function-end deltas
3. missing/extra jump tables
4. jump-table size deltas

### Comparison policy

1. Run legacy engine and candidate engine on same input.
2. Compute digests.
3. Categorize diffs and fail gate on unresolved categories.
4. Emit machine-readable diff summary for CI and docs tracking.

## Migration plan

### S0: baseline (done in this phase)

- Introduce deterministic digest/diff tests for legacy analyzer behavior.
- Add explicit invariant validation hook to analyzer lifecycle.

### S1: split interfaces (complete)

- Extract per-phase structs/interfaces from monolithic state mutations.
- Keep legacy implementation under these interfaces.

### S2: rewritten phase shadowing (baseline in progress)

- Implement rewritten phase components behind internal feature flags.
- Compare phase outputs (not only final outputs) for debugging.

### S3: rollout

- Candidate engine opt-in for selected corpora.
- Promote only after parity and stability gates hold across the golden corpus.

## Acceptance gates

1. Existing CFA suites remain green.
2. Invariant checks pass for analyzed outputs.
3. Shadow digest tests are deterministic.
4. No unresolved high-severity diffs in shadow CI corpus.

## Rollback

- Legacy analyzer remains default.
- Any shadow mismatch beyond threshold keeps candidate path disabled.

## Open risks

1. Phase extraction may expose hidden ordering dependencies.
2. Diff-noise from expected benign differences can mask real regressions.

Mitigation:
- enforce per-phase invariants,
- classify known-acceptable deltas explicitly,
- keep rollback to legacy immediate.
