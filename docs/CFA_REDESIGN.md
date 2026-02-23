# CFA Redesign: Functional Architecture

## Problem

`AnalyzerState` is a god object with 8 fields serving three roles:
- **Configuration** (immutable inputs): `skip_ranges`, `known_symbols`, `known_sections`, `sda_bases`
- **Working state** (mutable during analysis): `functions`, `jump_tables`
- **Post-processing bookkeeping**: `merged_tail_blocks`, `extended_functions`

All phase methods take `&mut self` and freely read/write every field. The `AnalysisPass` trait also takes `&mut AnalyzerState`, so external passes can touch anything.

## Design

Replace the god object with typed structs and standalone phase functions.

### Types

```rust
/// Immutable inputs — configured before CFA starts
pub struct CfaConfig {
    pub skip_ranges: BTreeMap<SectionAddress, SectionAddress>,
    pub known_symbols: BTreeMap<SectionAddress, Vec<ObjSymbol>>,
    pub known_sections: BTreeMap<SectionIndex, String>,
    pub sda_bases: Option<(u32, u32)>,
}

/// Final output — consumed by Tracker, apply, etc.
pub struct CfaResult {
    pub functions: BTreeMap<SectionAddress, FunctionInfo>,
    pub jump_tables: BTreeMap<SectionAddress, u32>,
    pub merged_tail_blocks: Vec<SectionAddress>,
    pub extended_functions: Vec<SectionAddress>,
}
```

### Phase Functions

```rust
// Phase 1: pure — config in, seeds out
fn discover_seeds(obj: &ObjInfo, config: &CfaConfig) -> BTreeMap<SectionAddress, FunctionInfo>;

// Phase 2: takes mutable working set, runs fixed-point to convergence
fn analyze_functions(
    obj: &ObjInfo,
    config: &CfaConfig,
    functions: &mut BTreeMap<SectionAddress, FunctionInfo>,
) -> Result<BTreeMap<SectionAddress, u32>>; // returns jump_tables

// Phase 3: post-processing, consumes working set into final result
fn finalize(
    obj: &ObjInfo,
    functions: BTreeMap<SectionAddress, FunctionInfo>,
    jump_tables: BTreeMap<SectionAddress, u32>,
) -> Result<CfaResult>;

// Phase 4: applies result to ObjInfo (symbol creation, size updates)
pub fn apply_cfa(obj: &mut ObjInfo, result: &CfaResult, config: &CfaConfig) -> Result<()>;

/// Top-level orchestrator
pub fn run_cfa(obj: &ObjInfo, config: CfaConfig) -> Result<CfaResult> {
    let mut functions = discover_seeds(obj, &config);
    let jump_tables = analyze_functions(obj, &config, &mut functions)?;
    finalize(obj, functions, jump_tables)
}
```

### Design Properties

1. **Ownership flows linearly**: `functions` map moves from `discover_seeds` → mutable borrow in `analyze_functions` → moved into `finalize` → packaged into `CfaResult`.
2. **Config is immutable** during analysis — can't accidentally modify it.
3. **Fixed-point circularity is explicit** — `analyze_functions` takes `&mut functions` because that's genuinely what it does.
4. **Bookkeeping is local** — `merged_tail_blocks`/`extended_functions` are created inside `finalize()`, not persistent state.
5. **`AnalysisPass` trait** becomes `fn execute(config: &mut CfaConfig, obj: &ObjInfo)` — passes only configure, never touch working state or results.
6. **Tracker gets `&CfaResult`** — clean read-only dependency.

### Call Site (xex.rs)

```rust
let config = CfaConfig { skip_ranges, known_symbols, .. };
FindSaveRestSledsXbox::execute(&mut config, &obj)?;
let result = run_cfa(&obj, config)?;
apply_cfa(&mut obj, &result, &config)?;

let mut tracker = Tracker::new(&obj);
tracker.process(&obj)?;
tracker.apply(&mut obj, true)?;
```

## Migration Plan

### Step 1: Define new types alongside old
- Add `CfaConfig` and `CfaResult` structs to cfa.rs
- Keep `AnalyzerState` untouched for now

### Step 2: Extract phase functions
- Move `phase_seed_discovery` → standalone `discover_seeds(obj, config)`
- Move fixed-point loop (`process_functions`, `finalize_functions`, `detect_new_functions`) → standalone `analyze_functions(obj, config, &mut functions)`
- Move `merge_tail_blocks` + `validate_invariants` → standalone `finalize(obj, functions, jump_tables)`
- Move `apply()` → standalone `apply_cfa(obj, result, config)`

Each extraction is mechanical: change `&mut self` to explicit params, replace `self.functions` with `functions`, `self.skip_ranges` with `config.skip_ranges`, etc.

### Step 3: Add `run_cfa` orchestrator
- Wire the phase functions together
- Add `pub type AnalyzerState = ...` temporary alias if needed

### Step 4: Update call sites
- `xex.rs`: Replace `AnalyzerState::default()` + `state.detect_functions()` + `state.apply()` with `run_cfa()` + `apply_cfa()`
- `pass.rs`: Update `AnalysisPass` trait to take `&mut CfaConfig`
- `cfa_tests.rs`: Update test setup

### Step 5: Remove `AnalyzerState`
- Delete the struct
- Remove any temporary aliases

### Helper functions that move out of `impl AnalyzerState`
These become standalone functions taking explicit params:
- `try_add_function(obj, config, functions, address)`
- `in_skipped_range(config, address) -> bool`
- `first_unbounded_function(functions) -> Option<SectionAddress>`
- `process_function(obj, config, functions, start) -> Result<Option<FunctionSlices>>`
- `process_function_at(obj, config, functions, jump_tables, addr) -> Result<bool>`
- `process_functions(obj, config, functions) -> Result<()>`
- `finalize_functions(obj, functions, finalize) -> Result<bool>`
- `detect_new_functions(obj, config, functions) -> Result<bool>`
- `skip_alignment(config, section, addr) -> SectionAddress`
- `check_tail_block(section, gap_start, gap_end, prev_start, prev_end) -> Option<SectionAddress>` (already `Self::`, no `&self`)

### Verification
1. `cargo build` — compiles cleanly
2. `cargo test` — all 89 tests pass
3. `dtk xex split` on DC3 — byte-identical output
