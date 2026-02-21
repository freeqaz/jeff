# CFA Rewrite Review

Date: 2026-02-20

Evidence reviewed:
- Current working deltas in `src/analysis/slices.rs` and `src/analysis/cfa_tests.rs`.
- Prior rewrite commits affecting the scoped files: `0db1919`, `dd8292f`, `d1297e4`, `778864c`, `5d3e858`.
- Related docs/assets: `docs/cfa_test_fixes.md`, `docs/cfa_test_audit.md`, `assets/tests/relative_bytes_jump_table_snippets.txt`.

## Objective Map

### 1) Function boundary fidelity
Goal: keep function bounds monotonic and faithful to known metadata while still discovering disconnected internal code.

Relevant deltas:
- Possible-blocks exploration pass extends analysis beyond initial reachability (`src/analysis/slices.rs:560`).
- New scan for unvisited code inside known function range (`src/analysis/slices.rs:603`).
- Jump-table inline-only block-end extension to avoid inflated bounds from external tables (`src/analysis/slices.rs:395`).

### 2) Jump-table sizing semantics
Goal: decode table entries with correct byte-width semantics and return actual consumed bytes.

Relevant deltas:
- Early break on invalid entry instead of hard failure (`src/analysis/mod.rs:254`).
- Return actual bytes read, not VM estimate (`src/analysis/mod.rs:268`).
- Guess-mode support for relative-byte and relative-short tables (`src/analysis/mod.rs:273`).
- Allow absolute tables in `.rdata` (`src/analysis/mod.rs:120`).

### 3) VM value provenance for MSVC stack shuffle
Goal: preserve value lineage across `stw/lwz` stack round-trips so bound checks survive register shuffles.

Relevant deltas:
- Stack-slot state (`src/analysis/vm.rs:157`).
- Stack store/load tracking (`src/analysis/vm.rs:862`, `src/analysis/vm.rs:869`).
- Comparison-range propagation back to stack slots (`src/analysis/vm.rs:965`).

### 4) Tail-call false-positive suppression
Goal: prioritize known function boundaries over heuristics when metadata is strong.

Relevant deltas:
- `.pdata` guard early-return in tail-call classifier (`src/analysis/slices.rs:847`).
- New direct regression tests for guard precedence and non-`.pdata` behavior (`src/analysis/slices.rs:1100`).

### 5) Generality vs pattern-specific brittleness
Goal: avoid assertions/pattern assumptions that turn ambiguous input into panics.

Current risks:
- Hard assert on `RelativeShortsTimes2` table type (`src/analysis/mod.rs:165`).
- VM still contains pattern-specific backward-look hacks for MSVC sequences (`src/analysis/vm.rs:882`).

## Rubric Evaluation

Scoring: 1 (poor) to 5 (strong).

| Area | Correctness | Generality | Failure Safety | Maintenance | Architecture Fit | Notes |
|---|---:|---:|---:|---:|---:|---|
| Function boundary fidelity | 4 | 3 | 4 | 3 | 4 | Strong improvements, but unvisited scan needs tighter guardrails to avoid accidental data-as-code seeding. |
| Jump-table sizing semantics | 5 | 4 | 4 | 4 | 5 | Most robust part of rewrite; semantics now match byte-accurate behavior and external table realities. |
| VM provenance for stack shuffle | 4 | 3 | 4 | 3 | 4 | Stack-slot tracking is a durable base; pattern hacks remain and should be gradually retired. |
| Tail-call suppression | 5 | 4 | 5 | 5 | 5 | `.pdata` precedence is a safe monotonic policy and now has direct regression coverage. |
| Generality vs brittleness | 3 | 2 | 2 | 2 | 3 | Remaining asserts/pattern assumptions are the main architectural liabilities. |

## Hunk-Level Adoption Matrix

| ID | Hunk | Decision | Evidence | Rationale | Next Action |
|---|---|---|---|---|---|
| H1 | `.pdata` tail-call guard | Adopt | `src/analysis/slices.rs:847`, tests at `src/analysis/slices.rs:1100` | Correctly prioritizes known bounds; directly prevents false tail-calls. | Keep as policy; keep tests mandatory. |
| H2 | Tail-call guard precedence tests | Adopt | `src/analysis/slices.rs:1138` | Locks behavior to metadata-first ordering and preserves non-`.pdata` heuristic path. | Keep and run in PR CI alongside `cfa_tests`. |
| H3 | Jump-table invalid-entry graceful truncation | Adopt | `src/analysis/mod.rs:254` | Converts crash/panic class into bounded truncation. | Keep current behavior; add one relocation-external truncation test. |
| H4 | Actual-size return + inline-only block growth | Adopt | `src/analysis/mod.rs:268`, `src/analysis/slices.rs:395` | Prevents function-bound inflation from external data tables. | Keep invariant; document in code comment as non-negotiable rule. |
| H5 | `.rdata` support for absolute tables | Adopt | `src/analysis/mod.rs:120` | Required for Xbox/MSVC reality; strict `bctr+4` assumptions are invalid. | Keep; add one cross-section negative test (data table masquerade). |
| H6 | Relative-table guess-mode support | Adopt with modification | `src/analysis/mod.rs:273` | Valuable fallback, but currently confidence-unscored and can overfit bytes. | Add confidence scoring and negative fixtures before broadening use. |
| H7 | Possible-blocks speculative pass | Adopt with modification | `src/analysis/slices.rs:560` | Solves unreachable-switch patterns; may overgrow without explicit budget/limits. | Add scan budget metrics and per-function cap. |
| H8 | Unvisited code range scan | Defer | `src/analysis/slices.rs:603` | Powerful for `.pdata`-covered detached blocks but higher false-positive/perf risk if unconstrained. | Gate behind confidence checks and add negative tests first. |
| H9 | Hard assert on `RelativeShortsTimes2` | Reject | `src/analysis/mod.rs:165` | Panic-based failure mode is brittle for real-world compiler variants. | Replace assert with graceful unsupported-path return + debug telemetry. |
| H10 | Simplifications that remove stack/value tracking robustness | Reject | `src/analysis/vm.rs:862`, `src/analysis/vm.rs:965` | Would regress MSVC stack-shuffle handling; test 19 class depends on this behavior. | Preserve stack tracking core; refactor only behind regression tests. |
| H11 | Strict invariant “absolute table must be `bctr+4`” (proposed upstream style) | Reject | Contradicted by `src/analysis/mod.rs:120` and `src/analysis/slices.rs:395` | Breaks valid external `.rdata` absolute tables. | Keep inline-only rule for block growth, not table validity. |
| H12 | Pattern documentation blocks/snippets in tests/assets | Adopt | `src/analysis/cfa_tests.rs:136`, `assets/tests/relative_bytes_jump_table_snippets.txt` | Low risk, high maintainability, improves onboarding/debug speed. | Keep synchronized with detector behavior changes. |

## Meta-Objective for This Branch

1. Preserve known bounds (`.pdata`, known symbols) over heuristics.
2. Prefer conservative, monotonic analysis over brittle pattern assertions.
3. Keep concerns separated:
- VM extracts value/provenance.
- Table reader decodes entries with bounds-safe truncation.
- CFA slicing grows control flow with bounded speculative passes.
4. Encode ambiguous compiler patterns as confidence layers, not invariants.

## Prioritized Backlog (Implementation-Ready)

### B1) Remove panic on `RelativeShortsTimes2`
- Hypothesis: Replacing assertion with graceful fallback improves robustness without reducing current coverage.
- Test additions required: Add unit tests in `src/analysis/mod.rs` for `RelativeShortsTimes2` in both known-size and guess-mode paths; ensure no panic and deterministic empty/truncated output.
- Acceptance criteria: `cargo test cfa_tests` stays green; new tests pass; no panic on crafted inputs.
- Rollback/failure signal: New behavior causes missed entries on existing relative-short cases or changes `jump_table_references` for tests 11-18.

### B2) Add confidence scoring for guessed jump tables
- Hypothesis: Confidence-gated acceptance reduces false positives from data-like byte runs.
- Test additions required: Positive fixtures from `assets/tests/relative_bytes_jump_table_snippets.txt`; negative fixtures containing non-table data arrays.
- Acceptance criteria: Existing 20 CFA tests unchanged; negative fixtures rejected unless confidence threshold met.
- Rollback/failure signal: Drop in detected jump tables for known positive tests.

### B3) Bound speculative growth passes
- Hypothesis: Per-function exploration budget prevents pathological scans while preserving current wins.
- Test additions required: Synthetic long-function with sparse code islands and dense data; ensure bounded runtime and stable output.
- Acceptance criteria: No regression in current tests; deterministic cap behavior logged.
- Rollback/failure signal: Missed known blocks in test 19-style scenarios.

### B4) Tighten unvisited-code seeding policy
- Hypothesis: Requiring additional evidence (e.g., predecessor relationship or prologue/epilogue hints) lowers false discovery.
- Test additions required: Positive detached helper case and negative embedded-data case.
- Acceptance criteria: Detached helper discovered when `.pdata` bounds exist; embedded-data case not converted into blocks.
- Rollback/failure signal: Function end under-approximation on current detached-block tests.

### B5) Consolidate VM stack provenance and retire pattern hacks gradually
- Hypothesis: General stack provenance can subsume special-case backward windows.
- Test additions required: Expand test 19 family with instruction-gap and register-rename variants.
- Acceptance criteria: New variants pass without relying on exact 3/4-instruction lookback forms.
- Rollback/failure signal: Reintroduction of missing jump-table detection in stack-shuffle sequences.

### B6) Keep docs/tests synchronized with branch policy
- Hypothesis: Explicit policy docs reduce accidental regression toward brittle invariants.
- Test additions required: N/A (doc-only); add checklist item in PR template.
- Acceptance criteria: `docs/cfa_test_fixes.md` and this review reflect actual test state after each CFA behavior change.
- Rollback/failure signal: Divergence between documented and observed pass/fail expectations.

## Strategic Rewrite Recommendation (VM + CFA)

### Is a full rewrite critical?
- Yes, long term. VM/CFA correctness is a foundational dependency for symbolization, function boundaries, and safe split generation.
- No, immediate full rewrite is not the highest-leverage next step. Current branch can materially improve reliability with targeted hardening (B1-B6) first.
- Recommended posture: **Defer full rewrites**, but explicitly plan and scope them now so we do not accumulate ad-hoc complexity.

### Full VM Rewrite Recommendation
- Decision: **Defer, but plan as a deliberate project after B1-B6 stability work**.
- Why defer now:
  - Current VM already has viable provenance primitives (`stack_slots`, range propagation) and can be strengthened incrementally.
  - Immediate risk reduction comes faster from removing panics, adding confidence gating, and tightening speculative growth.
- Why still important:
  - Pattern-specific lookback hacks in `src/analysis/vm.rs` are a maintainability ceiling and will keep breaking on new compiler variants.
- Rewrite target state:
  - Domain-driven abstract interpreter with first-class provenance (register + stack + memory slot lineage).
  - No mandatory dependence on fixed instruction-window hacks.
  - Explicit confidence/uncertainty on derived values used by jump-table detection.
- Trigger criteria to start full VM rewrite:
  - New compiler patterns repeatedly require bespoke lookback logic.
  - >2 consecutive regression cycles tied to provenance loss across stack/memory indirections.
  - Inability to express needed value relations without adding ad-hoc instruction-pattern exceptions.

### Full CFA Rewrite Recommendation
- Decision: **Defer full rewrite; continue staged architectural extraction**.
- Why defer now:
  - Current CFA structure is already compatible with the branch meta-objective (VM extraction, table decoding, slice growth separation).
  - Large rewrites now would increase delivery risk before current behavior is hardened and baselined.
- Why still important:
  - Speculative growth and unvisited seeding need stronger policy boundaries and may eventually benefit from cleaner pipeline boundaries.
- Rewrite target state:
  - Explicit multi-phase pipeline:
    1. VM value/provenance extraction.
    2. Jump-table/table-bound decoding with confidence outputs.
    3. CFG growth with bounded policies and monotonic merge semantics.
  - Per-phase invariants and structured confidence handoff, replacing implicit cross-phase assumptions.
- Trigger criteria to start full CFA rewrite:
  - Persistent false-positive/false-negative tension that cannot be solved with bounded heuristics.
  - Performance instability from speculative passes despite caps.
  - Repeated boundary regressions caused by phase coupling.

### Rewrite Safety Requirements (both projects)
- Treat both rewrites as high-blast-radius changes and gate behind:
  - Golden corpus parity (`cargo test cfa_tests` + expanded negative/variant suites).
  - Deterministic no-panic/no-assert behavior on malformed/ambiguous inputs.
  - Side-by-side comparison mode for old vs new engines during rollout.
  - Clear rollback switch to legacy path until parity is proven.

## Strategic Backlog Additions

### B7) VM Rewrite RFC + Spike
- Hypothesis: A domain/provenance-first VM design can remove pattern hacks while improving generality.
- Test additions required: Baseline corpus for stack-shuffle variants and relocation/memory-indirection cases.
- Acceptance criteria: Design RFC includes data model, transfer functions, uncertainty propagation, migration plan, and parity test plan.
- Rollback/failure signal: Spike cannot exceed current behavior on existing stack-shuffle and jump-table suites.

### B8) CFA Pipeline Rewrite RFC + Shadow Execution Plan
- Hypothesis: A strict phase-separated CFA pipeline reduces coupling regressions and improves maintainability.
- Test additions required: Phase-level invariants and shadow-run diff tests against current analyzer.
- Acceptance criteria: RFC defines phase interfaces, confidence contracts, bounded growth policies, and rollout/rollback controls.
- Rollback/failure signal: Shadow mode shows unresolved boundary/jump-table deltas on core corpus after planned parity milestones.

### B7/B8 Kickoff Artifacts (2026-02-20)
- VM rewrite RFC: `docs/cfa_vm_rewrite_rfc.md`
- Pipeline rewrite + shadow RFC: `docs/cfa_pipeline_rewrite_rfc.md`
- Code scaffolding merged for rollout gates:
  - CFA invariant validation hook: `AnalyzerState::validate_invariants` in `src/analysis/cfa.rs`
  - Shadow digest determinism/diff tests in `src/analysis/cfa.rs` test module
  - Additional VM relocation/memory-indirection baseline in `src/analysis/vm.rs` tests

## 2026-02-20 Implementation Update

Implemented in this branch:

- **B1 complete**: Removed the `RelativeShortsTimes2` hard assert in `src/analysis/mod.rs`.
  - Unsupported/truncated conditions now return conservative empty/truncated results with debug telemetry (no panic path).
  - Added tests for known-size, guess-mode, and external-relative-base handling.

- **B2 complete**: Added internal guess confidence classification for jump tables in `src/analysis/mod.rs`.
  - Internal types: `JumpTableConfidence`, `JumpTableGuessMeta` plus reason flags.
  - Policy: `High` accepts; `Medium` requires structural corroborator; `Low` rejects.
  - Added positive and negative confidence-gating tests.

- **B3 complete**: Added speculative growth budgets in `src/analysis/slices.rs`.
  - `MAX_POSSIBLE_BLOCK_EXPLORES_PER_FUNCTION`
  - `MAX_TOTAL_DISCOVERED_BLOCKS_PER_FUNCTION`
  - Cap hits now terminate conservatively and do not panic.

- **B4 complete**: Tightened unvisited seeding in `src/analysis/slices.rs`.
  - Requires corroborator:
    - inside known `.pdata` range, or
    - adjacent to proven block-gap boundary, or
    - prologue/epilogue signal.
  - Added counters/logging for rejected seeds and cap hits.
  - Added positive detached-helper and negative embedded-data tests.

- **B5 partial/targeted complete**: Hardened VM provenance without rewrite in `src/analysis/vm.rs`.
  - Preserved stack-slot model.
  - Added register-copy provenance refinement so stack origin survives rename (`or` copy path).
  - Added instruction-gap and register-rename VM tests.

- **B7 in progress (RFC + baseline complete)**:
- **B7 in progress (M2 shadow-bridge baseline active)**:
  - Added decision-complete VM rewrite RFC (`docs/cfa_vm_rewrite_rfc.md`).
  - Added VM baseline test for relative jump-table base propagation through `lbzx + rlwinm + add + bctr`.
  - Added VM2 parallel model scaffold in code (`src/analysis/vm2.rs`) with value/provenance/confidence primitives (no behavior switch yet).
  - Added VM2 legacy-shadow bridge (`Vm2::from_legacy_vm`) and mapping for:
    - value kinds (`Const`, `Address`, `Range`, `IndexedLoad`, comparison tags),
    - provenance (`Reg`, `StackSlot`, legacy memory forms),
    - CTR/LR + stack-slot snapshots.
  - Added VM2 shadow parity tests:
    - `analysis::vm2::tests::vm2_from_legacy_vm_maps_core_value_and_provenance`
    - `analysis::vm2::tests::vm2_shadow_tracks_relative_jump_table_from_legacy_vm_execution`
  - Added structured VM shadow-diff report model:
    - `VmShadowDiffReport`, `VmShadowDiffEntry`, `VmShadowDiffSummary`
    - typed location/kind categories for CI-style parity diagnosis
  - Added VM shadow-diff tests:
    - `analysis::vm2::tests::vm2_shadow_diff_report_is_empty_for_exact_legacy_mapping`
    - `analysis::vm2::tests::vm2_shadow_diff_report_categorizes_mismatch_types`

- **B8 in progress (RFC + shadow scaffolding complete)**:
  - Added decision-complete pipeline/shadow RFC (`docs/cfa_pipeline_rewrite_rfc.md`).
  - Added explicit analyzer invariant validation (`AnalyzerState::validate_invariants`) and wired it into `detect_functions`.
  - Added shadow digest/diff determinism tests for legacy analyzer behavior.
  - Added initial pipeline interface scaffold (`src/analysis/pipeline.rs`) including legacy engine wrapper and digest/diff model.
  - Split legacy analyzer flow into explicit phase methods:
    - `phase_seed_discovery`
    - `phase_slice_seeded_functions`
    - `phase_discover_remaining_functions`
    - `phase_finalize_and_validate`
  - Expanded pipeline contracts with phase outputs (`seed`, `slice`, `finalize`, `apply`) and run report support.
  - Added structured digest diff categorization (`function presence/end`, `jump-table presence/size`) and summary model.
  - Expanded to full real-fixture shadow corpus parity gate with aggregate reporting:
    - `ShadowCorpusReport` / `ShadowCorpusFixtureReport` (test harness)
    - `analysis::pipeline::tests::shadow_corpus_full_fixtures_match_legacy_pipeline_digest`

Validation run:
- `cargo test cfa_tests`
- `cargo test analysis::slices::tests::tail_call`
- `cargo test analysis::tests::`
- `cargo test analysis::vm::tests::`
- `cargo test analysis::pipeline::tests::`
- `cargo test analysis::vm2::tests::`
- `cargo test util::xex::tests::`

## Current Status Snapshot (2026-02-20)

- Branch: `cfa_fix`
- Version: `1.9.2`
- Working tree: roadmap execution active (`R2 complete`, `R3 complete`, `R4 complete`, `R5 complete`, `R6 prep complete`, `R7 tranche-1 complete`)
- Dev branch delta: only one version-bump commit (`1.9.1`) remains on `dev`, superseded by `1.9.2` here

Current observed test state on this branch:

- `cargo test cfa_tests` -> 20 passed
- `cargo test analysis::slices::tests::tail_call` -> 3 passed
- `cargo test analysis::vm::tests::` -> 3 passed
- `cargo test analysis::vm2::tests::` -> 23 passed
- `cargo test test_negative_jump_table_fixtures_are_rejected` -> 1 passed
- `cargo test analysis::pipeline::tests::` -> 15 passed
- `cargo test util::xex::tests::` -> 5 passed

Open technical debt (non-blocking for this branch state):

- Legacy VM pattern-specific hacks still present, though now partially insulated by stack-slot provenance and new regression tests

## 2026-02-20 Phase A/B Follow-Up (Robustness Execution Loop)

- **Phase A complete**: triaged warning backlog in `src/util/*` and `src/obj/*`.
  - Removed stale imports/variables and unreachable warning sites.
  - Added targeted `#[allow(dead_code)]` markers for intentionally retained split helpers in `src/util/split.rs`.
  - Result: `cargo check --tests --message-format short` reduced from 39 warnings to 4 (remaining warnings are in `src/analysis/*` only).

- **DC3 split stability check complete**:
  - Rebuilt release `dtk` and ran:
    - `~/code/milohax/jeff/target/release/dtk xex split config/373307D9/config.yml /tmp/dc3-split-smoke2`
  - Result: split completed successfully (`exit=0`), confirming split pipeline is operational for `dc3-decomp`.
  - Revalidated after concurrent COFF/COMDAT linking edits:
    - `~/code/milohax/jeff/target/release/dtk xex split config/373307D9/config.yml /tmp/dc3-split-smoke3` -> `exit=0`

- **Phase B complete**: added shared negative jump-table fixtures and unit coverage.
  - New asset: `assets/tests/jump_table_negative_snippets.txt`
  - New test: `analysis::tests::test_negative_jump_table_fixtures_are_rejected`
  - Coverage includes:
    - absolute single-entry non-corroborated candidate,
    - absolute `.rdata` data-array candidate,
    - relative-bytes unaligned candidate,
    - relative-shorts out-of-bounds candidate.

- **Phase C complete**: expanded shadow gates for pipeline + VM2 parity diagnostics.
  - Full CFA fixture corpus parity gate in pipeline tests with aggregate mismatch reporting.
  - Structured VM shadow-diff report for legacy-vs-VM2 comparisons with typed categories.
  - Added regression tests for zero-diff parity and category-specific mismatch reporting.

- **Phase D complete**: VM corpus harness + phase checkpoint scaffolding + fallback-prep hooks.
  - VM corpus shadow harness runs across selected fixtures (`1, 4, 8, 12, 19`) and full CFA fixture corpus with zero-diff gates.
  - Added aggregate VM corpus report types:
    - `VmCorpusShadowFixtureResult`
    - `VmCorpusShadowReport`
  - Added pipeline phase-level checkpoint digest/diff model:
    - `PhaseCheckpointDigest`
    - `PhaseCheckpointDiffEntry` / `PhaseCheckpointDiffSummary`
  - Added fallback decision scaffolding in CFA:
    - candidate shadow gate config constants and threshold evaluation,
    - structured fallback decision model and legacy-selection helper.
  - Added fallback regression tests validating:
    - VM threshold fallback trigger,
    - phase checkpoint threshold fallback trigger,
    - digest-preserving fallback selection.

- **Phase D+ complete**: live pipeline shadow comparison wired into runtime fallback path.
  - `AnalyzerState::detect_functions_with_shadow_config` now runs dual pipeline reports when
    shadow gates are enabled and computes:
    - phase checkpoint deltas from `compare_phase_checkpoints(...)`
    - final digest deltas from `PipelineDigest::diff_summary(...)`
  - Fallback routing is now driven by live measured deltas, not only synthetic test injection.
  - Conservative guardrail: any final digest mismatch adds `PipelineDigestMismatch` fallback reason.
  - Shadow gate env controls now supported for real-XEX parity runs:
    - `DTK_CFA_ENABLE_VM2_SHADOW` (`true/false`, `1/0`, etc.)
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW`
    - `DTK_CFA_MAX_VM_SHADOW_DELTAS`
    - `DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS`
    - `DTK_CFA_VM_SHADOW_MAX_FUNCTIONS`
    - `DTK_CFA_VM_SHADOW_MAX_STEPS`
  - Env-gated validation pass:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 cargo test cfa_tests`
    - Result: `20/20` passing with runtime shadow path enabled.

- **Phase E2 partial complete (R7 VM metric wiring)**: VM shadow delta metric now measured at runtime.
  - Added bounded runtime VM shadow sampling API in `analysis::vm2`:
    - `runtime_vm_shadow_summary(...)`
    - `VmRuntimeShadowConfig`
  - `AnalyzerState::detect_functions_with_shadow_config` now computes `vm_shadow_deltas` from
    sampled seed-function linear VM steps when VM shadow gating is enabled.
  - Added regression tests:
    - `analysis::vm2::tests::runtime_vm_shadow_summary_is_zero_for_legacy_mapped_candidate`
    - `analysis::vm2::tests::runtime_vm_shadow_summary_respects_zero_limits`
    - `analysis::cfa::tests::test_detect_functions_with_shadow_config_vm_gate_uses_runtime_vm_shadow_deltas`
  - Env-gated VM shadow smoke:
    - `DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=4 DTK_CFA_VM_SHADOW_MAX_STEPS=64 cargo test cfa_tests`
    - Result: `20/20` passing.
  - Real-XEX smoke with both shadow gates enabled:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-shadow-<timestamp>`
    - Result: `rc=0`, `4448` files, `2223` `.obj`.

- **Phase E2b complete (R7 telemetry)**: structured fallback mismatch logging is now active.
  - On fallback, CFA now logs bounded detail entries for:
    - phase checkpoint deltas (`PhaseCheckpointDiffEntry`)
    - pipeline digest deltas (`PipelineDiffEntry`)
  - Logging is capped (`MAX_LOGGED_SHADOW_DELTA_ENTRIES`) to avoid noisy/expensive dumps.

- **Phase E2c complete (R7 VM runtime diagnostics)**: runtime VM shadow now reports sampling coverage.
  - Added `VmRuntimeShadowReport` and `runtime_vm_shadow_report(...)` in `analysis::vm2`.
  - CFA VM-shadow logging now includes:
    - requested/sampled function counts
    - sampled step count
    - categorized diff totals
  - Added regression:
    - `analysis::vm2::tests::runtime_vm_shadow_report_tracks_sampling_counts`
  - Real-XEX smoke with strict candidate seed gate and runtime shadow reporting:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-vmreport-<timestamp>`
    - Result: `rc=0`, `4448` files, `2223` `.obj`.

- **Phase E2d complete (R7 VM per-function diagnostics)**: runtime VM shadow now reports function-level deltas.
  - Added `VmRuntimeShadowFunctionReport` in `analysis::vm2`.
  - `VmRuntimeShadowReport` now includes `function_reports` + `functions_with_diffs()`.
  - CFA fallback logging now emits bounded mismatched-function summaries
    (start address, categorized diff counts, sampled step count).
  - Added regressions:
    - `analysis::vm2::tests::runtime_vm_shadow_report_skips_non_code_functions`
    - updated `analysis::vm2::tests::runtime_vm_shadow_report_tracks_sampling_counts`

- **Phase E2e complete (R7 native VM2 shadow scaffold)**: runtime VM shadow can now execute VM2 natively with safe bridging.
  - Added `runtime_vm_shadow_report_with_mode(..., native_vm2)` in `analysis::vm2`.
  - Added initial native opcode handling (`addis`, `addi`/`addic`/`addic.`, `ori`, no-op branch/illegal cases),
    including relocation-aware value synthesis where available.
  - Unsupported opcodes bridge VM2 state from legacy VM for deterministic fallback-safe shadowing.
  - Runtime reports now include native/bridged step counters:
    - total: `VmRuntimeShadowReport::{native_steps, bridged_steps}`
    - per-function: `VmRuntimeShadowFunctionReport::{native_steps, bridged_steps}`
  - Added runtime gate:
    - `DTK_CFA_VM_SHADOW_NATIVE_VM2`
  - Added regression:
    - `analysis::vm2::tests::runtime_vm_shadow_report_native_mode_tracks_native_and_bridged_steps`
  - Env-gated test pass:
    - `DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_VM_SHADOW_NATIVE_VM2=1 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=4 DTK_CFA_VM_SHADOW_MAX_STEPS=64 cargo test cfa_tests`
    - Result: `20/20` passing.
  - Real-XEX smoke with native VM2 shadow gate:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_VM_SHADOW_NATIVE_VM2=1 DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-vm2native-<timestamp>`
    - Result: `rc=0`, `4448` files, `2223` `.obj`.
    - Same-commit rerun deterministic (no non-trivial diffs excluding `config.json`/`dep`).

- **Phase E2f complete (R7 digest hardening)**: pipeline digest diffs now include per-function state class.
  - Added `PipelineDiffKind::FunctionState` and `PipelineDiffSummary::function_state`.
  - `PipelineDigest::from_state(...)` now captures function state classification
    (`Function` / `NonFunction` / `Unfinalized` / `Unanalyzed`) in addition to end addresses.
  - Added regression:
    - `analysis::pipeline::tests::pipeline_digest_diff_reports_function_state_deltas`
  - Real-XEX smoke with strict candidate gates and native VM2 shadow remains stable:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_VM_SHADOW_NATIVE_VM2=1 DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1 DTK_CFA_CANDIDATE_STRICT_SYMBOL_SIZE_SEEDS=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-digeststate-<timestamp>`
    - Result: `rc=0`, `4448` files, `2223` `.obj`, no non-trivial diffs vs strict-symbol baseline.

- **Phase E2g complete (R7 fallback summary logging)**: fallback logs now include categorized summaries.
  - CFA fallback path now logs:
    - phase checkpoint summary counts (`seed_count`, `processed_seed_count`, `function_count`, `jump_table_count`)
    - pipeline digest summary counts (`function_presence`, `function_end`, `function_state`, `jump_table_presence`, `jump_table_size`)
  - Existing bounded per-entry logging remains unchanged for deep triage.

- **Phase E2h complete (R7 native VM2 opcode expansion)**: runtime native shadow now covers more arithmetic/control state ops.
  - Expanded native VM2 handling in `analysis::vm2::Vm2::step_shadow_native`:
    - `add` (parity-safe value forms),
    - `subf` / `subfc`,
    - `subfic`,
    - `or` (non-register-copy form; register-copy form intentionally bridges),
    - `mtspr` / `mfspr`.
  - Value-confidence synthesis for native facts now mirrors legacy mapping semantics for
    `Top`/`Range`/`IndexedLoad`/`CompareTag` classes.
  - Added regressions:
    - `analysis::vm2::tests::runtime_vm_shadow_report_native_mode_handles_arithmetic_and_spr_ops`
    - `analysis::vm2::tests::runtime_vm_shadow_report_native_mode_bridges_or_register_copy`

- **Phase E1g complete (R6 cutover mode scaffold)**: CFA now has explicit execution-mode routing for staged default migration.
  - Added `PipelineExecutionMode` in `analysis::cfa` with env control:
    - `DTK_CFA_PIPELINE_MODE=legacy|shadow|candidate` (`auto` aliases `shadow`)
  - Default remains conservative (`legacy`).
  - `shadow` mode forces candidate-vs-legacy comparison path for rollout soak.
  - `candidate` mode enables direct candidate-lane execution for controlled opt-in trials.
  - Added regressions:
    - `analysis::cfa::tests::test_parse_pipeline_execution_mode_accepts_common_values`
    - `analysis::cfa::tests::test_parse_pipeline_execution_mode_rejects_invalid_values`
    - `analysis::cfa::tests::test_detect_functions_candidate_mode_runs_without_shadow`

- **Phase E1 complete (R6 kickoff)**: explicit candidate pipeline lane created.
  - Added `analysis::pipeline::CandidatePipelineEngine` as a separate engine type.
  - Runtime shadow now compares `LegacyPipelineEngine` vs `CandidatePipelineEngine`.
  - Added candidate-vs-legacy digest parity test:
    - `analysis::pipeline::tests::candidate_pipeline_run_matches_legacy_pipeline_digest`
  - Full fixture shadow corpus parity test remains green with candidate lane active.

- **Phase E1b complete (R6 first true divergence)**: candidate seed phase now has independent implementation.
  - `CandidatePipelineEngine::phase_seed_discovery` now runs a candidate-owned seed pass
    (known functions, symbol starts, section starts) instead of calling
    `AnalyzerState::phase_seed_discovery`.
  - Added parity regression:
    - `analysis::pipeline::tests::candidate_seed_phase_matches_legacy_seed_phase`
  - Candidate-vs-legacy digest parity remains clean across full fixture shadow corpus.

- **Phase E1c complete (R6 slice divergence)**: candidate slice phase now has independent implementation.
  - `CandidatePipelineEngine::phase_slice_exploration` now runs candidate-owned seeded slicing
    (calls `process_function_at` per seed with known-function end checks) instead of calling
    `AnalyzerState::phase_slice_seeded_functions`.
  - Added parity regression:
    - `analysis::pipeline::tests::candidate_slice_phase_matches_legacy_slice_phase`
  - Full corpus shadow parity remains zero-delta with both shadow gates enabled.
  - Included concurrent active-dev COFF relocation-site addend sanitization in `src/util/xex.rs`;
    validated with:
    - `cargo test util::xex::tests::` (`5/5`)
    - real-XEX split smoke with both shadow gates enabled (`rc=0`, `4448` files, `2223` `.obj`).

- **Phase E1d complete (R6 finalization divergence)**: candidate finalization phase now has independent implementation.
  - `CandidatePipelineEngine::phase_finalization` now runs candidate-owned finalization
    (calls `phase_discover_remaining_functions` + `phase_finalize_and_validate`) instead of
    the prior parity-mirrored method body.
  - Added parity regression:
    - `analysis::pipeline::tests::candidate_finalization_phase_matches_legacy_finalization_phase`
  - Full corpus shadow parity remains zero-delta with both shadow gates enabled.
  - Real-XEX smoke with both shadow gates after finalization divergence:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-finalization-<timestamp>`
    - Result: `rc=0`, `4448` files, `2223` `.obj`.

- **Phase E1e complete (R6 gated heuristic hook)**: candidate seed refinement gate introduced.
  - Added `CandidatePipelineConfig { strict_code_seeds }` (default `false`).
  - Candidate seed phase now supports strict mode that drops seeds not in code sections.
  - Runtime gate:
    - `DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS`
  - Added regression:
    - `analysis::pipeline::tests::candidate_seed_phase_strict_code_filter_drops_non_code_function_symbol`
  - Default behavior remains parity-preserving (strict mode off in runtime path).
  - Real-XEX smoke with both shadow gates remains stable after hook addition:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-strictseed-<timestamp>`
    - Result: `rc=0`, `4448` files, `2223` `.obj`.
  - Strict-gate runtime smoke:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-candidate-strict-env-<timestamp>`
    - Result: `rc=0`, `4448` files, `2223` `.obj`.

- **Phase E1f complete (R6 gated symbol-size refinement)**: candidate seed refinement can now drop unknown-size symbol seeds.
  - Added `CandidatePipelineConfig { strict_symbol_size_seeds }` (default `false`).
  - Runtime gate:
    - `DTK_CFA_CANDIDATE_STRICT_SYMBOL_SIZE_SEEDS`
  - Added regression:
    - `analysis::pipeline::tests::candidate_seed_phase_strict_symbol_size_filter_drops_unknown_size_symbols`
  - Strict-symbol runtime smoke:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_VM_SHADOW_NATIVE_VM2=1 DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1 DTK_CFA_CANDIDATE_STRICT_SYMBOL_SIZE_SEEDS=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-symbolsize-<timestamp>`
    - Result: `rc=0`, `4448` files, `2223` `.obj`.
    - Compared to same-commit strict-code baseline, no non-trivial file deltas (`config.json`/`dep` excluded).

- **Phase E validation complete**: real-XEX parity smoke on external corpora.
  - Built release `dtk` from current branch and ran real DC3 split flow to `/tmp`:
    - `dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-<timestamp>`
    - Result: `status=0`, generated `2223` split `.obj` files.
  - Re-ran the same DC3 split into a second `/tmp` target and compared outputs:
    - Both runs produced `4448` total files and `2223` `.obj` files.
    - `diff -qr` reported only expected run-specific deltas in `config.json` and `dep`.
    - Excluding those files, tree diff is empty; `.obj` SHA256 manifests match exactly (`2223/2223`).
  - Verified parser compatibility on multiple real XEX files from executable library:
    - `dc3/9.16.12 (Final Debug)/ham_xbox_r.xex`
    - `dc1/TU0/default.xex`
    - `gh2/360 TU0 Strum Limit Fix/default.xex`
  - Result: `dtk xex info` succeeded for all sampled titles.
  - Shadow-gated DC3 split rerun after `R7 E2d` and split COMDAT guardrail updates:
    - `DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_CANDIDATE_STRICT_CODE_SEEDS=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-e2d-<timestamp>`
    - Result: `status=0`, `4448` total files, `2223` `.obj` files.
    - Compared to earlier `vmreport` baseline:
      - only `config.json`, `dep`, `obj/xdk/LIBCMT/crtgpr.obj`, and `obj/xdk/LIBCMT/crtfpr.obj` differed.
      - CRT object deltas align with current COMDAT fall-through handling for `__savegprlr*`/`__restgprlr*` and `__savefpr*`/`__restfpr*`.
    - Determinism check (same commit, second run):
      - no non-trivial diffs (`config.json`/`dep` excluded).
  - Latest debug parity run status (current branch tip):
    - Tracker duplicate-relocation panic in `src/analysis/tracker.rs` is fixed (now trace + continue in debug/release).
    - New regression test: `analysis::tracker::tests::test_process_data_tolerates_existing_source_relocation`.
    - Baseline debug run:
      - `target/debug/dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-baseline-r9-<timestamp>`
      - Result: `status=0`, `4448` total files, `2223` `.obj` files.
    - Shadow debug run:
      - `DTK_CFA_PIPELINE_MODE=shadow DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_VM_SHADOW_NATIVE_VM2=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 target/debug/dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-shadow-r9-<timestamp>`
      - Result: `status=0`, `4448` total files, `2223` `.obj` files.
    - Candidate debug run:
      - `DTK_CFA_PIPELINE_MODE=candidate DTK_CFA_ENABLE_PIPELINE_SHADOW=1 DTK_CFA_ENABLE_VM2_SHADOW=1 DTK_CFA_VM_SHADOW_NATIVE_VM2=1 DTK_CFA_MAX_PHASE_CHECKPOINT_DELTAS=0 DTK_CFA_MAX_VM_SHADOW_DELTAS=0 DTK_CFA_VM_SHADOW_MAX_FUNCTIONS=8 DTK_CFA_VM_SHADOW_MAX_STEPS=64 target/debug/dtk xex split config/373307D9/config.yml /tmp/jeff-parity-dc3-candidate-r9-<timestamp>`
      - Result: `status=0`, `4448` total files, `2223` `.obj` files.
    - Baseline vs shadow diff:
      - only `config.json` and `dep` differ; no other output-tree deltas.
    - Baseline vs candidate diff:
      - only `config.json` and `dep` differ; no other output-tree deltas.
    - Post native-VM2 jump-table opcode tranche validation (`cmp*`, `rlwinm/rlwnm`, `lwzx/lbzx/lhzx`, relative-base `add`):
      - `target/debug/dtk` baseline vs candidate rerun (`r10b`) returned `BASE_RC=0`, `CAND_RC=0`.
      - Both runs produced `4448` files and `2223` `.obj`; only `config.json` + `dep` differed.
      - Added native parity tests:
        - `analysis::vm2::tests::vm2_step_shadow_native_handles_relative_jump_table_sequence`
        - `analysis::vm2::tests::vm2_step_shadow_native_handles_lwzx_and_lhzx_parity`
    - Scripted workflow smoke:
      - Added `scripts/dc3_cfa_parity_smoke.sh` for one-command `baseline`/`shadow`/`candidate` parity checks.
      - Supports strict candidate rehearsal flags:
        - `--strict-code-seeds`
        - `--strict-symbol-size`
      - Added `scripts/cfa_cutover_gate.sh` for consolidated cutover gating:
        - baseline/shadow/native-VM2 `cfa_tests`
        - default + strict DC3 parity runs
      - `scripts/dc3_cfa_parity_smoke.sh --no-build --run-id r11-smoke` -> `PASS`
      - `baseline_rc=0`, `shadow_rc=0`, `candidate_rc=0`; non-trivial diff counts `0`.
      - Post stack-provenance OR native handling rerun:
        - `scripts/dc3_cfa_parity_smoke.sh --no-build --run-id r12-stackor` -> `PASS`
        - `baseline_rc=0`, `shadow_rc=0`, `candidate_rc=0`; non-trivial diff counts `0`.
      - Post native stack-store (`stw`) handling rerun:
        - `scripts/dc3_cfa_parity_smoke.sh --no-build --run-id r13-stw` -> `PASS`
        - `baseline_rc=0`, `shadow_rc=0`, `candidate_rc=0`; non-trivial diff counts `0`.
      - Post native stack-load (`lwz`) + revision-tracked slot provenance rerun:
        - `scripts/dc3_cfa_parity_smoke.sh --no-build --run-id r14-lwz` -> `PASS`
        - `baseline_rc=0`, `shadow_rc=0`, `candidate_rc=0`; non-trivial diff counts `0`.
      - Post strict-gate rehearsal rerun:
        - `scripts/dc3_cfa_parity_smoke.sh --no-build --strict-code-seeds --strict-symbol-size --run-id r15-strict` -> `PASS`
        - `baseline_rc=0`, `shadow_rc=0`, `candidate_rc=0`; non-trivial diff counts `0`.
      - Consolidated cutover gate rerun:
        - `scripts/cfa_cutover_gate.sh --no-build --run-id-prefix r16-cutover` -> `PASS`
        - baseline/shadow/native-VM2 `cfa_tests` all `20/20`, then default + strict parity both passed.
      - Post full register-copy OR handling consolidated gate rerun:
        - `scripts/cfa_cutover_gate.sh --no-build --run-id-prefix r18-postor` -> `PASS`
        - baseline/shadow/native-VM2 `cfa_tests` all `20/20`, then default + strict parity both passed.
      - Post full register-copy OR native handling rerun:
        - `scripts/dc3_cfa_parity_smoke.sh --no-build --run-id r17-orfull` -> `PASS`
        - `baseline_rc=0`, `shadow_rc=0`, `candidate_rc=0`; non-trivial diff counts `0`.
  - Parser smoke remains healthy:
    - `dtk xex info` succeeds on:
      - `/home/free/code/milohax/dc3-decomp/orig/373307D9/default.xex`
      - `/home/free/code/milohax/milo-executable-library/dc1/TU0/default.xex`
      - `/home/free/code/milohax/milo-executable-library/gh2/360 TU0 Strum Limit Fix/default.xex`
    - Revalidated on current branch tip (`r19`) with debug `dtk`:
      - `/home/free/code/milohax/dc3-decomp/orig/373307D9/default.xex`
      - `/home/free/code/milohax/milo-executable-library/dc3/9.16.12 (Final Debug)/ham_xbox_r.xex`
      - `/home/free/code/milohax/milo-executable-library/dc1/TU0/default.xex`
      - `/home/free/code/milohax/milo-executable-library/gh2/360 TU0 Strum Limit Fix/default.xex`
      - all `xex info` calls returned `status=0`.

#### Useful XEX Links (Local Workspace)

- `dc3-decomp` split source:
  - `/home/free/code/milohax/dc3-decomp/orig/373307D9/default.xex`
- Executable-library parity samples:
  - `/home/free/code/milohax/milo-executable-library/dc3/9.16.12 (Final Debug)/ham_xbox_r.xex`
  - `/home/free/code/milohax/milo-executable-library/dc1/TU0/default.xex`
  - `/home/free/code/milohax/milo-executable-library/gh2/360 TU0 Strum Limit Fix/default.xex`

### Next Phase Queue

1. **R6 rollout prep (cutover scaffold utilization)**:
   - Run `DTK_CFA_PIPELINE_MODE=shadow` soak across fixture + real-XEX workflows.
   - Use `scripts/dc3_cfa_parity_smoke.sh` as the standard DC3 regression/parity harness.
   - Start controlled `DTK_CFA_PIPELINE_MODE=candidate` opt-in checks on bounded corpora.
   - Keep default at `legacy` until parity + stability gates are met.
2. **R7 native VM2 coverage continuation**:
   - Extend native handling past tranche-1 (`cmp*`, `rlwinm/rlwnm`, `lwzx/lbzx/lhzx`, relative-base `add`) into selective branch-fact paths.
   - Preserve deterministic bridge fallback for any provenance-sensitive gaps.
3. **Real-XEX workflow promotion**:
   - Run `legacy`/`shadow`/`candidate` split comparisons on DC3 and sample executable-library XEX files.
   - Keep parity checks strict (exclude only `config.json`/`dep`) before default-mode promotion.

### Immediate Execution Plan (Kickoff: 2026-02-20, updated post-Phase D)

1. **Sprint F1 (cutover rehearsal)**:
   - Validate `legacy` vs `shadow` vs `candidate` mode behavior on corpus + real-XEX samples.
2. **Sprint F2 (native coverage growth)**:
   - Land the next native VM2 branch-fact/provenance tranche with bridge-safe tests and coverage metrics.
3. **Sprint F3 (real-world stability gate)**:
   - Expand real-XEX mode parity evidence (`legacy`/`shadow`/`candidate`) and document promotion criteria.

Exit criteria for next implementation pass:

- Candidate execution-mode routing is validated on real workloads.
- Native VM2 shadow coverage improves without increasing unresolved diff counts.
- Real-XEX parity evidence is maintained across `legacy`/`shadow`/`candidate` (excluding `config.json`/`dep` run artifacts).
