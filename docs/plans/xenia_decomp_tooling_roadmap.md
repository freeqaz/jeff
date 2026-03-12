# Xenia + Decomp Tooling Roadmap (High-ROI First, GDB Stub Included)

## Summary

This plan prioritizes tooling work that most directly improves `dc3-decomp` bring-up velocity and regression diagnosis in Xenia.

Principles:
- Ship the highest-value, lowest-risk tooling first.
- Prefer scriptable/headless workflows over manual debugging.
- Use telemetry/parity as the default loop.
- Add interactive debugging (GDB stub) in phases only when the earlier tooling is no longer enough.

This is a cross-repo plan (`xenia`, `dc3-decomp`, `jeff`) but is tracked here because it directly supports decomp progress.

## Progress Update (2026-02-24)

Implemented in `xenia` since this roadmap was written:

- Phase 1 (High-ROI tooling): implemented
  - `tools/dc3_guest_disasm.py`
    - symbolized guest disasm around `PC/LR/CTR`
    - supports `--xenia-log` crash tuple extraction
    - supports XEX (auto-decompress), PE (`default.exe`), and raw-image disasm
  - `tools/dc3_runtime_telemetry_diff.py` extended
    - symbolized unresolved/hot-loop output
    - function-grouped summaries (caller, target, caller->target pairs)
    - aggregate "top divergent functions" ranking
  - `tools/dc3_runtime_parity_gate.sh` integration
    - `DC3_PARITY_SYMBOLIZE=1`
    - emits symbolized telemetry diff + crash disasm artifacts
    - emits failure artifacts on nonzero exit via `EXIT` trap

- Phase 2 (Structured runtime debugging): implemented
  - `tools/dc3_trace_on_break.sh`
    - repeatable headless `--break_on_instruction` workflow
    - captures log, telemetry, optional function trace data, crash/break disasm artifacts
  - `tools/dc3_crash_signature_triage.py`
    - auto-labels common DC3/Xenia crash signatures from headless logs
    - parity gate emits per-run triage artifacts (`orig/decomp`)

- Phase 3 (Decomp-oriented runtime oracle): partially implemented
  - parity gate now emits an explicit milestone contract verdict (`PASS/WARN/FAIL`) with configurable policy
  - parity gate prints CRT-vs-milestone triage summary to support constructor-impact prioritization
  - structured telemetry milestone emission already existed; tooling-side contract enforcement is now in place
  - tooling/probe payoff validated: a constructor regression was traced to a relink-induced CRT slot drift (`CRT[69]`) rather than generic CRT failure, using runtime CRT logs + fresh `default.map`

- Phase 4 (GDB Stub track): protocol groundwork started
  - `tools/dc3_gdb_rsp_mvp_mock.py` (standalone crash-snapshot-backed RSP mock server)
  - `tools/dc3_gdb_rsp_snapshot_bridge.sh` (snapshot/log -> RSP mock launch + GDB attach workflow)
  - Xenia-side structured crash snapshot artifact support (`--dc3_crash_snapshot_path`) added to reduce log-parsing dependency
  - Supports a minimal Phase-A-like command subset for client compatibility experiments:
    `?`, `qSupported`, `qAttached`, `g`, `m`, `c`, `s`, `Z0`, `z0`, basic thread packets
  - Purpose: de-risk packet/encoding behavior before in-process Xenia integration
  - In-process headless MVP integration now added (`xenia-headless`, Linux-only for now):
    - new cvars: `--dc3_gdb_rsp_stub`, `--dc3_gdb_rsp_host`, `--dc3_gdb_rsp_port`, `--dc3_gdb_rsp_break_on_connect`
    - packet subset wired to `cpu::Processor` debugger APIs (`Pause`, `Continue`, `StepGuestInstruction`, guest breakpoints)
    - supports Phase A core packets plus target XML (`qXfer:features:read:target.xml`)
    - status: compiles and links (`xenia-headless`), plus real in-process GDB attach smoke on Linux headless for handshake + thread list + register snapshot fallback + memory reads
    - current limitation: this headless build lacks a stack walker, so live pause/step/software-breakpoint paths are disabled (graceful fallback mode) and guest `pc` is not available in fallback snapshots

Cross-cutting lesson from current debugging:
- Treat hardcoded guest globals/CRT slot indices as build-volatile.
- Prefer `default.map` (fresh build) for constructor/global probes; `symbols.txt` may lag relinks and can mislead object-address debugging.
- Keep invasive runtime probes opt-in (example: `ReadCacheStream` step override) so diagnostic shims do not become the cause of parser/checksum failures.
- Add decomp-build freshness checks to the runtime debugging loop when symptoms look like "symbol corruption":
  stale object + partial relink mismatches (or bad literal relocations) can manifest as bad string-literal references in linked code (example: `Rnd::SetupFont` ctor1/arg2 literal resolving to non-string data instead of `"font"`), which is not a Xenia hash-table bug.

Recent decomp bring-up impact (2026-02-24):
- Fixed a relinked `gConditional` sentinel stopgap address in `dc3_hack_pack` (fresh `default.map` label lookup), which restored non-empty `gSystemConfig` parsing in current decomp runs.

Next recommended coding step remains Phase 4 / GDB Stub Phase A (MVP) hardening:
- enable stack-walker-backed live stop/step/breakpoint paths in a build/config where debugger pause APIs are available, then validate `c/s/Z0` end-to-end
- done: packet framing/checksum/hex helpers were extracted into reusable Xenia-side protocol helpers (`src/xenia/debug/dc3_gdb_rsp_protocol.h`)
- next: move the live in-process listener implementation itself (not just packet helpers) into reusable guest-stub plumbing beyond `emulator_headless.cc`

## Current Baseline (Locked)

- DC3 NUI/XBC resolver + guest override path is cut over and validated.
- Xenia has DC3 parity + JSON telemetry tooling (`dc3_runtime_parity_gate`, `dc3_runtime_telemetry_diff`).
- Linux x64 JIT PPC smoke suite is green (`1481/1481` loaded tests passed).
- `xb gentests` now supports native PPC binutils detection with VMX128 capability probing and fallback.

## Goals

1. Make decomp regressions diagnosable in minutes, not hours.
2. Turn Xenia into a reliable differential runtime oracle for original vs decomp XEXs.
3. Improve symbolized crash/hotloop insight without requiring interactive debugging.
4. Add an incremental GDB remote stub path only after the scriptable workflow is strong.

## Phase 1: High-ROI Tooling (Implement First)

### 1. Symbolized Guest Crash/Disasm Helper

Add a tool to dump symbolized PPC disassembly around guest crash addresses (`PC/LR/CTR`) using available symbols and XEX/ELF extracts.

Deliverables:
- `xenia/tools/dc3_guest_disasm.py` (or similar)
- Inputs:
  - guest addresses (`--pc`, `--lr`, optional `--ctr`)
  - XEX/PE or extracted PPC image
  - symbol sources (`symbols.txt`, manifest, `nm` output)
- Outputs:
  - nearest symbol names
  - disasm window around each address
  - raw words + annotated branch targets

Why this helps now:
- Faster crash-path triage than manual `objdump`/hex work.
- Directly useful for current decomp boot failures (data-as-code, bad return/LR paths).

Acceptance:
- Can symbolize and disassemble a known DC3 crash tuple from current logs.

### 2. Telemetry Diff Symbolization + Ranking

Extend `xenia/tools/dc3_runtime_telemetry_diff.py` to produce symbolized ranked summaries.

Add:
- symbolization of `guest_pc`, `callsite_pc`, unresolved targets
- grouping by symbol/function instead of only raw addresses
- "top divergent functions" summary
- optional original/decomp side-by-side disasm links/output snippets

Why this helps now:
- Makes parity diffs actionable for `dc3-decomp` and `jeff` prioritization.
- Reduces time spent mapping telemetry addresses back to code.

Acceptance:
- Given telemetry + symbols, tool prints a ranked symbolized report (hot loops, unresolved stubs, divergence).

### 3. Parity Gate Integration (Symbolized Failure Artifacts)

Wire the two tools above into `xenia/tools/dc3_runtime_parity_gate.sh`.

Add:
- optional `DC3_PARITY_SYMBOLIZE=1`
- on failure, emit:
  - symbolized hot loop summary
  - symbolized unresolved-call summary
  - crash disasm around last known `PC/LR`

Why this helps now:
- One-command parity run produces useful investigation artifacts immediately.

Acceptance:
- A failing decomp parity run emits symbolized artifacts without manual follow-up.

## Phase 2: Structured Runtime Debugging (Still Easy/High Value)

### 4. Trace-on-Break Headless Workflow

Create a repeatable headless debugging mode that combines:
- `--break_on_instruction`
- existing x64 tracers (`x64_tracers`)
- DC3 runtime telemetry
- symbolized dump helper

Deliverables:
- `xenia/tools/dc3_trace_on_break.sh`
- documented recipe for "stop at guest PC X, enable trace, resume"

Why this helps:
- Gives reproducible traces around a known failure point without GUI debugger interaction.
- Good middle ground before a GDB remote stub.

Acceptance:
- Can produce a targeted instruction trace around a configured DC3 crash/bad loop address.

### 5. Crash Signature Library + Automatic Triage

Add a small catalog of known DC3 crash signatures:
- data-as-code (`PC` in non-`.text`)
- invalid stack / bad LR restore patterns
- thunk/IAT null cases
- common CRT/init trap loops

Wire into parity/telemetry tooling for auto-labeling failures.

Why this helps:
- Speeds repeated debugging during active decomp churn.
- Makes concurrent work easier to triage.

Acceptance:
- Current known decomp failures get auto-labeled in parity output.

## Phase 3: Decomp-Oriented Runtime Oracle Improvements

### 6. Runtime Milestone Contract (Original vs Decomp)

Define a small explicit milestone set for DC3 bring-up and emit them as structured telemetry:
- boot/init milestones
- thread start milestones
- renderer milestones (e.g. near `DxRnd::Present` / `D3DDevice_Swap`)
- major subsystem init milestones

Then compare original vs decomp milestone progression in parity runs.

Why this helps:
- Converts "it boots farther" into measurable progress.
- Lets us rank decomp changes by actual runtime impact.

Acceptance:
- Parity gate outputs milestone diff summary with pass/warn/fail policy.

### 7. Constructor / CRT Impact Triage Loop

Correlate:
- CRT sanitizer activity
- telemetry divergence
- milestone progression changes

Goal:
- prioritize `dc3-decomp` / `jeff` fixes that unblock boot progression fastest.

Why this helps:
- Stops spending time on low-impact decomp cleanup while runtime blockers remain.

Acceptance:
- At least one decomp/jeff task gets reprioritized from telemetry evidence.

## Phase 4: GDB Stub Track (Phased, Only After Earlier Tooling Is Strong)

This is valuable, but not the first thing to build.
We should use the prior phases to reduce how often interactive debugging is required.

### GDB Stub Phase A (MVP Read/Break/Continue)

Goal:
- Minimal GDB remote serial protocol (RSP) server for guest PPC state.

Scope:
- single-thread-first
- stop/continue
- read registers / read memory
- software breakpoints (guest address)
- attach on demand (debug cvar)

Likely commands:
- `?`, `g`, `m`, `c`, `s`, `Z0`, `z0`, `qSupported`, `qAttached`

Integration points in Xenia:
- `xe::cpu::Processor` pause/resume and stepping
- `xe::cpu::Breakpoint`
- thread debug state capture (`ThreadDebugInfo`)

Non-goals:
- watchpoints
- non-stop mode
- polished thread handling
- symbol server integration

Value:
- Interactive investigation of hard-to-localize control-flow bugs.

Risk:
- Medium; protocol glue is straightforward, but stop/step semantics over JIT can be tricky.

Acceptance:
- `powerpc-none-eabi-gdb` can connect, set a guest breakpoint, continue, and inspect regs/memory on hit.

### GDB Stub Phase B (Usable for Real DC3 JIT Debugging)

Goal:
- Make the stub robust enough for actual decomp debugging sessions.

Add:
- thread enumeration and selection (`Hg`, `qfThreadInfo`, `qsThreadInfo`, etc.)
- better stop reasons / signal mapping
- reliable stepping across JIT blocks and branch/return transitions
- basic symbol load workflow docs (how to use `symbols.txt` / generated symbols)

Value:
- Enables targeted interactive debugging when telemetry points to a narrow failing path.

Risk:
- High relative to Phase A because JIT stepping/thread behavior can get subtle.

Acceptance:
- Can step across a suspected bad return/LR restore path in a DC3 decomp run and inspect guest state reliably.

### GDB Stub Phase C (Quality-of-Life / Advanced)

Add:
- watchpoints (if practical)
- mixed guest/host debugging aids
- better JIT mapping visibility
- optional integration with parity/telemetry artifacts (auto-break at divergence PC)

This phase is optional and should only be pursued if we are using Phase B frequently.

## Phase 5: Long-Term "Awesome Xenia for Decomp" Enhancements

### 8. JIT Introspection Artifacts

Generate reproducible per-function JIT dumps:
- PPC -> HIR -> x64 snippets
- tied to guest function address / symbol

Why:
- Helps backend debugging and decomp parity issues tied to translation quality.

### 9. Differential Runtime Trace Mode (Original vs Decomp)

Structured event stream designed for direct diffing:
- callsite-level events
- function enter/exit summaries
- selected memory/IO events

Why:
- Strong runtime oracle for decomp correctness beyond current parity summaries.

### 10. Decomp Support Manifest Expansion

Expand the decomp-generated manifest consumed by Xenia to include:
- richer semantic symbols
- known temporary shims
- versioned schema and compatibility metadata

Why:
- Reduces friction and stale glue during rapid decomp iteration.

## Implementation Order (Concrete)

1. `xenia`: symbolized guest crash/disasm helper
2. `xenia`: telemetry diff symbolization/ranking
3. `xenia`: parity gate symbolized failure artifacts
4. `xenia`: trace-on-break headless workflow script/docs
5. `xenia`: crash signature catalog + auto-labeling
6. `xenia`: milestone telemetry + parity comparison
7. `xenia` + `dc3-decomp` + `jeff`: constructor/CRT impact triage loop
8. `xenia`: GDB stub Phase A (MVP)
9. `xenia`: GDB stub Phase B (usable)
10. `xenia`: optional GDB stub Phase C + advanced trace/JIT tooling

## Validation Gates

Keep running:
- `xenia/tools/dc3_nui_cutover_gate.sh`
- `xenia/tools/dc3_runtime_parity_gate.sh`
- `xenia-core-tests "[dc3_nui_patch_resolver]"`
- `xenia-cpu-ppc-tests` smoke (`1481/1481` current baseline)

New checks to add as phases land:
- telemetry diff symbolization smoke
- crash-disasm helper smoke against known DC3 crash addresses
- parity gate failure artifact generation smoke
- GDB stub Phase A connect/break/register-read smoke

## Notes / Constraints

- Native `powerpc-none-eabi-*` tools are useful for analysis, but current assembler lacks `-mvmx128`, so Xenia PPC test asset generation still needs bundled Xenia binutils fallback.
- `powerpc-none-eabi-run` is GNU `psim`; it does not attach to Xenia guest execution.
- The highest leverage for decomp remains automation + telemetry + symbolized postmortem tooling; GDB stub is valuable but should be phased in after those foundations are strong.
