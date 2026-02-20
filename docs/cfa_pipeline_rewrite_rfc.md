# CFA Pipeline Rewrite RFC + Shadow Plan (B8)

## Status

- Date: 2026-02-20
- Owner: `cfa_fix`
- Phase: S1 complete, S2 corpus-gated parity active, S2a checkpoint-diff prep complete, S2b runtime shadow routing active, S2c candidate seed/slice/finalization divergence active, S2d gated heuristic hook active
- Initial scaffold: `src/analysis/pipeline.rs`

Current implementation snapshot:
- Legacy analyzer routed through explicit phase methods in `AnalyzerState`.
- Candidate pipeline lane is now explicit via `CandidatePipelineEngine` (parity-mirrored stage).
- Candidate seed phase is now implemented directly in `CandidatePipelineEngine`.
- Candidate slice phase is now implemented directly in `CandidatePipelineEngine`.
- Candidate finalization phase is now implemented directly in `CandidatePipelineEngine`.
- Candidate config hook now exists (`CandidatePipelineConfig::strict_code_seeds`) for
  default-off seed refinement experiments.
  - Runtime toggle for strict seed refinement:
    - `DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS`
- `analysis::pipeline` now exposes phase outputs and a run report model.
- Digest comparison now includes categorized diff entries and summary counters.
- Full CFA fixture shadow parity gate is active with zero-diff totals and per-fixture reporting.
- Shadow corpus parity test now runs through candidate pipeline engine against baseline analyzer digest.
- Candidate seed parity test is active:
  - `analysis::pipeline::tests::candidate_seed_phase_matches_legacy_seed_phase`
- Candidate slice parity test is active:
  - `analysis::pipeline::tests::candidate_slice_phase_matches_legacy_slice_phase`
- Candidate finalization parity test is active:
  - `analysis::pipeline::tests::candidate_finalization_phase_matches_legacy_finalization_phase`
- Phase-level checkpoint diffing is now available via:
  - `PhaseCheckpointDigest`
  - `PhaseCheckpointDiffEntry` / `PhaseCheckpointDiffSummary`
  - `compare_phase_checkpoints`
- Runtime CFA shadow routing now consumes live pipeline deltas in
  `AnalyzerState::detect_functions_with_shadow_config`.
  - Dual pipeline reports are compared at runtime when shadow gates are enabled.
  - Any pipeline digest mismatch forces conservative fallback to legacy state.
  - Fallback path emits bounded checkpoint/digest delta entries for triage.
  - Runtime gate controls:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW`
    - `DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS`

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

### S2: rewritten phase shadowing (corpus gate active)

- Implement rewritten phase components behind internal feature flags.
- Compare phase outputs (not only final outputs) for debugging.

### S2a: Candidate phase spike prep (complete baseline)

- Add candidate phase spike scaffolds behind internal guardrails.
- Extend run-report comparison checkpoints so phase-level deltas can be surfaced before full digest mismatch.
- Keep legacy pipeline default until S2a delta categories are understood and documented.

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
