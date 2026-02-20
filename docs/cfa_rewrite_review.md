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
- Working tree: roadmap execution active (`R2 complete`, `R3 complete`, `R4 complete`, `R5 complete`, `R6 prep complete`, `R7 prep complete`)
- Dev branch delta: only one version-bump commit (`1.9.1`) remains on `dev`, superseded by `1.9.2` here

Current observed test state on this branch:

- `cargo test cfa_tests` -> 20 passed
- `cargo test analysis::slices::tests::tail_call` -> 3 passed
- `cargo test analysis::vm::tests::` -> 3 passed
- `cargo test analysis::vm2::tests::` -> 9 passed
- `cargo test test_negative_jump_table_fixtures_are_rejected` -> 1 passed
- `cargo test analysis::pipeline::tests::` -> 8 passed
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

- **Phase E1 complete (R6 kickoff)**: explicit candidate pipeline lane created.
  - Added `analysis::pipeline::CandidatePipelineEngine` as a separate engine type.
  - Runtime shadow now compares `LegacyPipelineEngine` vs `CandidatePipelineEngine`.
  - Added candidate-vs-legacy digest parity test:
    - `analysis::pipeline::tests::candidate_pipeline_run_matches_legacy_pipeline_digest`
  - Full fixture shadow corpus parity test remains green with candidate lane active.

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

#### Useful XEX Links (Local Workspace)

- `dc3-decomp` split source:
  - `/home/free/code/milohax/dc3-decomp/orig/373307D9/default.xex`
- Executable-library parity samples:
  - `/home/free/code/milohax/milo-executable-library/dc3/9.16.12 (Final Debug)/ham_xbox_r.xex`
  - `/home/free/code/milohax/milo-executable-library/dc1/TU0/default.xex`
  - `/home/free/code/milohax/milo-executable-library/gh2/360 TU0 Strum Limit Fix/default.xex`

### Next Phase Queue

1. **R6 implementation: candidate phase component spikes (B8)**:
   - Implement first true candidate phase divergence (seed or slice stage) inside `CandidatePipelineEngine`.
   - Keep legacy analyzer default unless checkpoint + digest parity remain clean.
2. **R7 implementation: operational fallback routing (B7/B8)**:
   - Replace mapped-legacy VM shadow baseline with true VM2-executed runtime deltas.
   - Emit structured mismatch logs with actionable fixture-level summaries.
3. **Real-XEX parity proof loop**:
   - Run shadow parity against real XEX workflows in `~/code/milohax/dc3-decomp` and the executables repo.
   - Track unresolved deltas as blockers for candidate-path rollout.

### Immediate Execution Plan (Kickoff: 2026-02-20, updated post-Phase D)

1. **Sprint E1 (R6 implementation)**:
   - Implement first candidate phase path(s) and compare against legacy using checkpoint + digest summaries.
2. **Sprint E2 (R7 integration)**:
   - Bind fallback hooks to candidate path output deltas for automatic legacy routing on threshold breach.
3. **Sprint E3 (external parity evidence)**:
   - Run real-XEX parity checks in `dc3-decomp` and executables repo, then document unresolved deltas.

Exit criteria for next implementation pass:

- Candidate phase path produces measurable checkpoint/digest parity reports.
- Fallback hooks are exercised by real candidate deltas (not only synthetic tests).
- Real-XEX parity evidence is documented with concrete pass/fail fixtures.
