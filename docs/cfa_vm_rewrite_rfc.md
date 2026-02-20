# CFA VM Rewrite RFC (B7)

## Status

- Date: 2026-02-20
- Owner: `cfa_fix`
- Phase: M1 complete, M2a corpus shadow harness complete, M3 guardrail prep active
- Initial scaffold: `src/analysis/vm2.rs`

Current implementation snapshot:
- VM2 now supports shadow ingestion from legacy VM state (`Vm2::from_legacy_vm`).
- Legacy-to-VM2 mapping covers constant/address/range/compare/indexed-load facts.
- Legacy provenance is mapped into VM2 provenance (`register`, `stack slot`, legacy memory forms).
- New VM2 parity tests include relative jump-table propagation from real legacy VM execution.
- Structured VM shadow diff reporting is available via `VmShadowDiffReport::from_legacy_pair`.
- VM corpus shadow reporting now includes:
  - `VmCorpusShadowFixtureResult`
  - `VmCorpusShadowReport`
- Zero-diff gates now run for:
  - selected fixture subset (`1, 4, 8, 12, 19`)
  - full CFA fixture corpus

## Why this rewrite exists

Current VM behavior in `src/analysis/vm.rs` is effective but brittle in key paths:

- Stack provenance relies on mixed mechanisms (stack slots + local pattern hacks).
- Jump-table inference couples value tracking, control-flow branching, and table-type mutation.
- Uncertainty is represented implicitly (`Unknown`), limiting diagnosability and controlled fallback.

The rewrite goal is to preserve behavior while making semantics explicit and composable.

## Goals

1. Make value/provenance tracking explicit and architecture-neutral at the transfer-function layer.
2. Replace pattern-only heuristics with data-flow facts plus confidence metadata.
3. Keep legacy VM available during rollout; parity must be proven before switching.

## Non-goals

1. No immediate removal of legacy VM in this phase.
2. No CLI changes.
3. No broad CFA architecture rewrite inside this RFC (handled by B8).

## Proposed VM2 Model

### Value lattice

`Value2`:

- `Top` (unknown/unbounded)
- `Const(u64)`
- `Address(RelocationTarget)`
- `Range { min, max, step }`
- `IndexedLoad { table_kind, table_addr, max_offset, rel_base }`
- `CompareTag { crf }`

### Provenance

`Provenance2`:

- `Reg(u8, rev)`
- `StackSlot(i16, rev)`
- `Memory(RelocationTarget, rev)`
- `Derived(Vec<Provenance2>)`
- `None`

Every `Value2` carried by a register includes provenance. Stack-slot updates are first-class transfer effects (not post-hoc hacks).

### Confidence

`Confidence2` (internal only):

- `High`
- `Medium`
- `Low`

Confidence is attached to derived indexed-load and branch-target facts. Consumers (jump-table decoder/CFA) decide acceptance thresholds.

## Transfer-function requirements

1. `stw/lwz` stack flows:
   - `stw rS, off(r1)` writes value+provenance to `StackSlot(off)`.
   - `lwz rD, off(r1)` reads from `StackSlot(off)` when present.
2. `cmp*/bc*` range narrowing:
   - branch splits produce deterministic left/right narrowed values.
   - narrowed values propagate back to source provenance (register + stack slot).
3. indexed loads and relative tables:
   - `lwzx/lbzx/lhzx` construct `IndexedLoad`.
   - `rlwinm` type transition must be explicit (`RelativeBytes -> RelativeBytesTimes4`, `RelativeShorts -> RelativeShortsTimes2`).
   - `add base + indexed` must preserve table addr and set relative base.
4. `bctr` target export:
   - export structured jump-table target with confidence and size semantics.

## Migration plan

### M0: Baseline (done in this phase)

- Keep legacy VM as source of truth.
- Add regression tests for stack-shuffle and indexed-load provenance paths.

### M1: VM2 skeleton (complete)

- Introduce VM2 types + transfer dispatch in parallel module.
- No CFA integration yet; test-only execution.

### M2: Shadow execution (structured diff baseline active)

- Run legacy VM and VM2 side-by-side on selected corpus.
- Compare emitted branch/jump-table facts and range outcomes.

### M2a: Corpus parity harness (complete)

- Add reusable VM shadow harness over CFA fixture corpus paths.
- Emit aggregate `VmShadowDiffSummary` plus per-fixture mismatch reports.
- Gate policy:
  - `value/provenance/confidence/presence` deltas must be explicitly categorized.
  - unresolved deltas above threshold keep VM2 disabled for adoption.

### M3a: Guardrail prep (baseline complete)

- Added candidate shadow threshold config and decision model in CFA.
- Added fallback-selection helper that preserves legacy result on threshold breach.
- Added regression tests for VM/phase threshold triggers and digest-preserving fallback behavior.

### M3: Controlled adoption

- Opt-in internal switch for VM2 in CFA.
- Keep automatic rollback to legacy VM on mismatch thresholds.

## Acceptance gates

1. Existing suites remain green:
   - `cargo test cfa_tests`
   - `cargo test analysis::vm::tests::`
2. VM2 shadow parity thresholds:
   - no unresolved deltas on jump-table type/address/size for golden corpus.
   - no regressions on stack-slot provenance tests.
3. No new panic/assert-only failure paths.

## Rollback plan

- Legacy VM remains default until parity thresholds are met.
- Any unresolved parity delta or crash automatically disables VM2 path for that run.

## Risks

1. Over-constraining value lattice could lose pragmatic coverage for odd compiler patterns.
2. Under-constraining confidence could reintroduce false positives.

Mitigation: keep parity corpus + negative fixtures as hard gates before defaulting to VM2.
