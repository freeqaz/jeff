# CFA (Control Flow Analysis) - Working Doc

## Project Context

**jeff** is a fork of [encounter's decomp-toolkit (dtk)](https://github.com/encounter/decomp-toolkit),
adapted for Xbox 360 (PowerPC Xenon / MSVC) executables instead of GC/Wii (PowerPC / GCC).

### Repository Layout
- **Repo**: `~/code/milohax/jeff/`
- **Remotes**:
  - `origin` = `rjkiv/jeff` (the fork, jeff's main repo)
  - `fork` = `freeqaz/jeff` (collaborator fork)
  - `upstream` = `encounter/decomp-toolkit` (original dtk -- NOT our main)
- **Branches**:
  - `main` - jeff's main branch (origin/main)
  - `cfa_tests` - CFA unit test work: 20 test cases for jump table detection (diverged from main)
  - `dev` - Production work: tail block merging, jump table fixes, COFF linking fixes (diverged from main independently of cfa_tests)
- **Key difference**: `dev` has important CFA fixes NOT in `cfa_tests`:
  - `0db1919` Fix crash when VM over-estimates jump table size (graceful break on unresolvable entries)
  - `dd8292f` Fix function bounds inflation from over-estimated jump tables
  - `d1297e4` Allow absolute jump tables in `.rdata` sections (Xbox puts them there, not `.text`)
  - `626b4a0` Detect and merge tail blocks in XEX function analysis
  - `40a9383` Preserve global-scope symbols when merging tail blocks

### Test Data Locations
- **Unit tests**: `assets/tests/cfa_tests.yml` (20 test cases, hex-encoded PPC function bytes + jump table bytes)
- **Dance Central 3 (primary test target)**:
  - Debug XEX: `~/code/milohax/dc3-decomp/orig/373307D9/debug.xex`
  - Release XEX: `~/code/milohax/dc3-decomp/orig/373307D9/default.xex`
  - Map file: `~/code/milohax/dc3-decomp/orig/373307D9/ham_xbox_r.map`
  - Extracted exe: `~/code/milohax/dc3-decomp/orig/373307D9/ham_xbox_r.exe`
- **Other XEX files**: `~/code/milohax/` contains other repos/games that may have XEXs

### Running Tests
```bash
# Run CFA unit tests (from repo root)
cargo test cfa_tests

# Run a specific test
cargo test cfa_tests::test_jump_table_absolute_1
```

### Quick Reference: Test Cases

| Test | Name | JT Type | Source Game | Status |
|------|------|---------|------------|--------|
| 0 | `test_super_basic_cfa` | None | Synthetic | Pass |
| 1 | `test_jump_table_absolute_1` | Absolute (inline .text) | Unknown | Fail (panic) |
| 2 | `test_jump_table_absolute_2` | Absolute (inline .text) | Unknown | Fail (over-count) |
| 3 | `test_jump_table_absolute_3` | Absolute (inline .text) | Unknown | Fail (wrong end) |
| 4 | `test_jump_table_relative_bytes_1` | RelativeBytes | Minecraft TU2 | Pass |
| 5 | `test_jump_table_relative_bytes_2` | RelativeBytes | Sonic Unleashed | Pass |
| 6 | `test_jump_table_relative_bytes_3` | RelativeBytes | Gamepad Debug | Pass |
| 7 | `test_jump_table_relative_bytes_4` | RelativeBytes | Gamepad Debug | Pass |
| 8 | `test_jump_table_relative_bytes_5` | RelativeBytes | TBRB | Fail (wrong end) |
| 9 | `test_jump_table_relative_bytes_6` | RelativeBytes | TBRB | Pass |
| 10 | `test_jump_table_relative_bytes_7` | RelativeBytes | TBRB | Fail (wrong end) |
| 11 | `test_jump_table_relative_shorts_1` | RelativeShorts | Unknown | Fail (2x size) |
| 12 | `test_jump_table_relative_shorts_2` | RelativeShorts | Unknown | Fail (2x size) |
| 13 | `test_jump_table_relative_shorts_3` | RelativeShorts | Unknown | Fail (wrong end) |
| 14 | `test_jump_table_relative_shorts_4` | RelativeShorts | Unknown | Fail (wrong end) |
| 15 | `test_jump_table_relative_shorts_5` | RelativeShorts | Unknown | Fail (2x size) |
| 16 | `test_jump_table_relative_shorts_6` | RelativeShorts | Unknown | Fail (2x size) |
| 17 | `test_jump_table_relative_shorts_7` | RelativeShorts | Unknown | Fail (2x size) |
| 18 | `test_jump_table_relative_shorts_8` | RelativeShorts | Unknown | Fail (2x size) |
| 19 | `test_jump_table_absolute_stack_meme` | Absolute (stack spill) | Unknown | Fail (no JT detected) |

---

## What is CFA in jeff?

CFA is the core analysis engine that takes raw PowerPC (Xenon) machine code from Xbox 360 executables and
automatically discovers **function boundaries**, **basic blocks**, **jump tables**, and **tail calls**.
This is the hardest and most critical piece of the entire disassembly pipeline -- if CFA gets function
boundaries wrong, everything downstream (splits, relocations, objdiff integration) breaks.

---

## The Problem: MSVC vs GCC Code Generation

Xbox 360 executables are compiled by MSVC for PowerPC (Xenon). Unlike GCC-compiled GC/Wii DOLs that
dtk was originally built for, MSVC generates significantly different code patterns:

### Different Prologue/Epilogue Conventions
MSVC uses `mfspr r12, LR` / `stw r12, -0x8(r1)` instead of the GCC `mflr r0` / `stw r0, 0x4(r1)`
pattern. Save/restore register intrinsics (`__savegprlr`, `__restgprlr`, `__savefpr`, etc.) are used
via `bl` calls rather than inline saves. Detected by `FindSaveRestSledsXbox` in `pass.rs`.

### Different Jump Table Formats
GCC almost exclusively uses absolute `lwzx`-based jump tables. MSVC uses at least 5 different types:
1. **Absolute** (`lwzx`): Table entries are full 32-bit addresses, in `.text` (GC/Wii) or `.rdata` (Xbox)
2. **RelativeBytes** (`lbzx`): 1-byte offsets from a base address, stored in `.rdata`
3. **RelativeBytesTimes4** (`lbzx` + `rlwinm`): Same as above but offsets are multiplied by 4
4. **RelativeShorts** (`lhzx`): 2-byte offsets from a base address, stored in `.rdata`
5. **RelativeShortsTimes2** (`lhzx` + `rlwinm`): Same as above but offsets are multiplied by 2

### Known Function Boundaries from .pdata
XEX files contain `.pdata` (exception data) sections that provide known function start/end addresses.
This is a huge advantage that GC/Wii DOLs don't have. See [.pdata Format](#pdata-exception-data-format)
section below for the exact binary layout.

### Stack Spill Patterns
MSVC sometimes stores a register to the stack and reloads it later into a different register before
using it for a jump table index. The VM needs to track these to correctly detect the jump table.

### Absolute Jump Tables Can Be in .rdata
Unlike GC/Wii where they're always inline in `.text`, Xbox MSVC can place absolute jump tables in
read-only data sections. Fixed on `dev` branch (commit `d1297e4`), but **broken on `cfa_tests`** branch
because `is_valid_jump_table_addr()` in `mod.rs` only allows `ObjSectionKind::Code` for absolute tables.

---

## Architecture

### Key Files

- **`src/analysis/cfa.rs`** - Top-level orchestrator. `AnalyzerState` holds discovered functions, jump
  tables, symbols. Drives the iterative function discovery loop: seed -> process -> gap-detect -> finalize.
- **`src/analysis/vm.rs`** - PowerPC virtual machine. Tracks GPR values (constants, addresses, ranges,
  `LoadIndexed` results), condition registers, LR/CTR. Jump table detection happens here -- when `bctr`
  is hit, VM checks CTR for `LoadIndexed` value. Also contains `JumpTableType` enum and `GprValue` enum.
- **`src/analysis/slices.rs`** - `FunctionSlices` manages basic blocks, branches, and tail call analysis
  for a single function. The `analyze()` method runs the executor and builds the CFG. The
  `instruction_callback()` handles `StepResult` variants from the VM.
- **`src/analysis/executor.rs`** - Instruction executor that drives the VM through basic blocks.
- **`src/analysis/pass.rs`** - Analysis passes (save/restore register intrinsic sled detection).
- **`src/analysis/mod.rs`** - Shared utilities: `disassemble()`, `read_u32()`, `get_jump_table_entries()`,
  `uniq_jump_table_entries()`, `skip_alignment()`, `is_valid_jump_table_addr()`.
- **`src/analysis/cfa_tests.rs`** - Unit tests (only on `cfa_tests` branch).
- **`assets/tests/cfa_tests.yml`** - Test data: hex-encoded function bytes and jump table bytes per test.

### How CFA Works (High Level)

1. **Seed functions** from `.pdata` (known boundaries), symbols, and section starts
2. **Process each function**: Run the VM from the function start, following branches, building basic blocks
3. **Jump table detection**: When VM hits `bctr`, check if CTR holds a `LoadIndexed` value. If so,
   read the jump table entries and add them as branch targets
4. **Tail call resolution**: When an unconditional branch goes to an unknown address, determine if it's
   a tail call (to another function) or just an internal branch. Uses heuristics: zero padding before
   target, prologue scanning, known function boundaries, recursive CFA on the target
5. **Gap detection**: After all known functions are processed, scan for gaps between function boundaries
   and try to find new functions in those gaps
6. **Finalization**: Resolve remaining ambiguous blocks, verify all blocks have known ends

### How Jump Table Detection Works (Detail)

The VM tracks register values through instruction execution. The typical MSVC absolute jump table pattern:

```
cmplwi  rX, N          ; Compare index against max (sets CR, VM tracks Range{0..N})
bgt     default_case   ; Branch if out of bounds (VM splits: false branch has Range{0..N})
lis     rY, addr@ha    ; Load high half of table address
addi    rY, rY, addr@l ; Load low half (VM now has Constant address)
rlwinm  rZ, rX, 2, 0, 29  ; Multiply index by 4 (VM has Range with step)
lwzx    rW, rY, rZ    ; Load from table (VM produces LoadIndexed{Absolute, addr, size})
mtctr   rW             ; Move to CTR
bctr                   ; Branch to table entry -> StepResult::Jump(JumpTable{...})
```

For relative tables, the pattern uses `lbzx`/`lhzx` instead of `lwzx`, and there's an `add` to
combine the loaded offset with a base address. The `rlwinm` after the load (if present) indicates
a multiply-by-4 or multiply-by-2 variant.

**Important**: `rlwinm` can come BEFORE or AFTER the load instruction -- both orderings exist in MSVC
output. There must be an `rlwinm` between `bgt`/`l*zx` or between `l*zx`/`bctr`.

### Concrete Assembly Examples by Jump Table Type

#### Absolute (inline .text) -- Test 1, `FUN_82086990`
```asm
; JT at 0x820869FC, 4 entries (test expects 4, stored as 16 bytes)
cmplwi  r11, 0          ; 2B0B0000 - bounds check (N=0, but table has entries)
beq     default_case    ; 419A00B8
...
lis     r12, 0x8208      ; 3D808208 - load high half of JT address
addi    r12, r12, 0x69FC ; 398C69FC - load low half -> VM: Constant(0x820869FC)
rlwinm  r0, r10, 2, 0, 29 ; 5540103A - multiply index by 4 -> VM: Range{step=4}
lwzx    r0, r12, r0     ; 7C0C002E - load from JT -> VM: LoadIndexed{Absolute, 0x820869FC, ...}
mtctr   r0              ; 7C0903A6
bctr                    ; 4E800420 -> StepResult::Jump(JumpTable{Absolute, ...})
; Table entries follow inline (in .text):
; 0x820869FC: 82086A40 82086A0C 82086A14 82086A28
```

#### RelativeBytes -- Test 4, `FUN_822C4618` (Minecraft TU2)
```asm
; JT at 0x82000B18 in .rdata, 105 entries (1-byte offsets)
cmplwi  r3, 0x6E        ; 2C03006E - compare index against 110 (0x6E)
bgt     default_case    ; 41800016C
...
lis     r12, 0x8200      ; 3D808200 - load high half of JT address
addi    r12, r12, 0x0B18 ; 398C0B18 - JT address in .rdata -> VM: Constant(0x82000B18)
rlwinm  r0, r0, 2, 0, 29 ; 5400103A - multiply index by 4 (rlwinm BEFORE load)
                         ;            -> VM: Range{min=0, max=0x1B8, step=4}
lis     r12, 0x822C      ; 3D80822C - load high half of base address
nop                      ; 60000000
addi    r12, r12, 0x468C ; 398C468C - base address for relative offsets
lbzx    r12, r12, r0    ; 7C0C58AE - load 1-byte offset from JT
                         ;   -> VM: LoadIndexed{RelativeBytes(None), 0x82000B18, ...}
; add combines loaded offset with base address:
add     r12, r12, <base> ;          -> VM: LoadIndexed{RelativeBytes(Some(0x822C468C)), ...}
mtctr   r12             ; 7D8903A6
bctr                    ; 4E800420
; JT entries in .rdata: 02 00 4A 04 4A 4A ... (1-byte offsets from base)
```

#### RelativeShorts -- Test 11, `FUN_8222C138`
```asm
; JT at 0x82020EC8 in .rdata, 14 entries (2-byte offsets)
; Tests expect 14, but jump_table_references stores 28 (14 * 2 bytes) -> 2x bug
cmplwi  r0, 0x0D        ; comparison sets up bounds
...
lis     r12, 0x8202      ; 3D808202 - load high half of JT address
addi    r12, r12, 0x0EC8 ; 398C0EC8 - JT address in .rdata
rlwinm  r0, r0, 1, 0, 30 ; 5540083C - multiply index by 2 (shift left 1, rlwinm BEFORE load)
                          ;           -> VM: Range{step=2}
lhzx    r0, r12, r0     ; 7C0C022E - load 2-byte offset from JT
                         ;   -> VM: LoadIndexed{RelativeShorts(None), 0x82020EC8, ...}
lis     r12, 0x8223      ; 3D808223 - load high half of base address
addi    r12, r12, 0xC1E0 ; 398CC1E0 - base address
add     r12, r12, r0    ; 7D8C0214 -> VM: LoadIndexed{RelativeShorts(Some(0x8223C1E0)), ...}
mtctr   r12             ; 7D8903A6
bctr                    ; 4E800420
; JT entries in .rdata: 0000 008C 0320 0370 ... (2-byte big-endian offsets from base)
```

#### Stack Spill Pattern -- Test 19, `FUN_82185B60`
```asm
; This is the "stack meme" - register value crosses a stack round-trip
; JT at 0x82185BE8 (inline .text), 0x169 entries expected
lbz     r5, 0x84(r1)    ; load arg from stack
lwz     r4, 0x7C(r1)    ; load another arg
stw     r5, 0x50(r1)    ; STORE r5 to stack offset 0x50
lwz     r6, 0x50(r1)    ; RELOAD from 0x50 into r6 (different register!)
                        ; VM loses track here -- r6 is now Unknown
addi    r6, r6, -0x28   ; adjust
stw     r5, 0x50(r1)    ; store again
lwz     r4, 0x50(r1)    ; reload for bounds check
cmplwi  r4, 0x168       ; bounds check
bgt     default_case
; ... rlwinm, lwzx, mtctr, bctr sequence
; The backward-look hack in vm.rs:857-918 tries to recover r4's value by
; checking if the lwz at the reload matches a previous lwz+cmplwi+bgt pattern
```

### Key Data Structures

**`GprValue` enum** (`vm.rs:54-72`):
- `Unknown` -- GPR value not tracked
- `Constant(u64)` -- known constant (u64 for 64-bit Xenon; dtk uses u32)
- `Address(RelocationTarget)` -- known relocated address
- `ComparisonResult(u8)` -- result of a comparison (tracks which CR field)
- `Range { min: u64, max: u64, step: u64 }` -- value is within a bounded range
- `LoadIndexed { jump_table_type: JumpTableType, jump_table_address: RelocationTarget, max_offset: Option<NonZeroU32> }` -- value loaded from a jump table

**`Gpr` struct** (`vm.rs:74-86`):
- `value: GprValue` -- current tracked value
- `hi_addr: Option<SectionAddress>` -- address of instruction that loaded high half
- `lo_addr: Option<SectionAddress>` -- address of instruction that loaded low half
- `source: GprSource` -- tracks where this value came from (for register spill recovery)
- `version: usize` -- incremented on every write, used to detect stale source references

**`GprSource` / `GprSourceLocation`** (`vm.rs:24-51`):
- `GprSourceLocation::Unknown` -- source unknown
- `GprSourceLocation::Register(usize)` -- value came from another register
- `GprSourceLocation::Stack(usize)` -- value came from stack offset
- `GprSourceLocation::Memory(usize)` -- value came from memory address
- `GprSourceLocation::MemoryOffset { address, offset_register }` -- indexed memory access
- `GprSource` wraps `kind: GprSourceLocation` + `version: usize` for staleness checking

**`BranchTarget::JumpTable`** (`vm.rs:171-176`):
- `{ jump_table_type: JumpTableType, jump_table_address: RelocationTarget, size: Option<NonZeroU32> }`
- `size` is in **bytes** (same units as `jump_table_references`)

**`FunctionSlices`** (`slices.rs:22-35`):
- `blocks: BTreeMap<SectionAddress, Option<SectionAddress>>` -- basic block start -> end
- `branches: BTreeMap<SectionAddress, Vec<SectionAddress>>` -- branch source -> targets
- `function_references: BTreeSet<SectionAddress>` -- discovered function call targets
- `jump_table_references: BTreeMap<SectionAddress, u32>` -- jump table addr -> **byte size**
  (NOT entry count). For bytes: byte_size == entry_count. For shorts: byte_size == entry_count * 2.
  For absolute: byte_size == entry_count * 4.
- `possible_blocks: BTreeMap<SectionAddress, Box<VM>>` -- ambiguous targets (tail call or block?)
- `prologue` / `epilogue` -- detected prologue/epilogue addresses (if any)

**`AnalyzerState`** (`cfa.rs:117-124`):
- `sda_bases: Option<(u32, u32)>` -- SDA/SDA2 base addresses (from entry point analysis)
- `functions: BTreeMap<SectionAddress, FunctionInfo>` -- all discovered functions
- `jump_tables: BTreeMap<SectionAddress, u32>` -- all discovered jump tables (addr -> byte size)
- `known_symbols: BTreeMap<SectionAddress, Vec<ObjSymbol>>` -- symbols to inject (e.g., sled labels)
- `known_sections: BTreeMap<SectionIndex, String>` -- section renames
- On `dev` branch, also has: `skip_ranges`, `merged_tail_blocks`, `extended_functions`

**`FunctionInfo`** (`cfa.rs:94-115`):
- `analyzed: bool` -- whether this function has been processed
- `end: Option<SectionAddress>` -- function end address (from .pdata or CFA)
- `slices: Option<FunctionSlices>` -- the analyzed CFG (None if not yet analyzed or not a function)

### dtk vs jeff: What Changed

dtk (the upstream GC/Wii toolkit, verified via `git show upstream/main:src/analysis/vm.rs`) has a
simpler model:
- **`GprValue::LoadIndexed`**: `{ address: RelocationTarget, max_offset: Option<NonZeroU32> }` --
  no `JumpTableType` field, no `jump_table_type` / `jump_table_address` distinction
- **Only `Lwzx`**: The `Lbzx`/`Lhzx` opcodes have no handler; a commented-out `is_indexed_load_op()`
  function lists them but is never called
- **`GprValue::Constant(u32)`**: Uses `u32`, not `u64` -- sufficient for 32-bit GC/Wii
- **No `GprSource`**: The `Gpr` struct only has `{ value, hi_addr, lo_addr }` -- no source tracking,
  no version field. This means dtk cannot recover values across register copies/spills
- **Jump tables always in `.text`**: No `.rdata` section handling
- **Uses `ppc750cl` crate** for instruction decoding (GC/Wii); jeff uses `powerpc` crate with
  `Extensions::xenon()` for Xenon-specific instructions
- **All VM unit tests commented out** in upstream (lines 773-888)

jeff added:
- `JumpTableType` enum (5 variants: `Absolute`, `RelativeBytes(Option<RelocationTarget>)`,
  `RelativeBytesTimes4(...)`, `RelativeShorts(...)`, `RelativeShortsTimes2(...)`)
- `Lbzx` / `Lhzx` handlers in the VM with bounds-check awareness (`vm.rs:760-800`)
- `rlwinm` multiply detection for Times4/Times2 variants (`vm.rs:594-633`)
- `GprSource` / `GprSourceLocation` for register provenance tracking (`vm.rs:24-51`)
- `Gpr.version` field for staleness detection across register writes (`vm.rs:85`)
- `.rdata` jump table support (on `dev` branch via `is_valid_jump_table_addr()`)
- Stack spill backward-look hacks (`vm.rs:857-918`)
- Xbox prologue/epilogue pattern detection (`slices.rs:92-123`)
- Save/restore sled detection (`FindSaveRestSledsXbox` in `pass.rs`)
- Tail block merging (on `dev`, ~670 lines in `cfa.rs`)

---

## .pdata Exception Data Format

The `.pdata` section contains `IMAGE_CE_RUNTIME_FUNCTION_ENTRY` structures (8 bytes each):

```c
typedef struct {
    uint32_t FuncStart;           // Function start address (absolute)
    uint32_t PrologLen    : 8;    // Prologue length in instructions
    uint32_t FuncLen      : 22;   // Total function length in instructions
    uint32_t ThirtyTwoBit : 1;    // 1 = 32-bit instructions (always 1 on PPC)
    uint32_t ExceptionFlag: 1;    // 1 = exception handler present
} IMAGE_CE_RUNTIME_FUNCTION_ENTRY;
```

Key implications for CFA:
- **Exact function boundaries**: `FuncStart + (FuncLen * 4)` gives the function end in bytes
- **Prologue size**: `PrologLen * 4` gives prologue size in bytes -- separates register setup from body
- **Exception handler trigger**: PDATA_EH data exists when `ExceptionFlag == 1` **OR** when
  `FuncLen == 0` (jeff handles this via `func_type == 3` in `src/util/xex.rs:1036-1093`).
  The 8-byte `PDATA_EH` structure sits **immediately before** the function in `.text`:
  ```c
  struct PDATA_EH {
      uint32_t* pHandler;      // Exception handler function pointer
      uint32_t* pHandlerData;  // Exception handler metadata
  };
  ```
  For C++ exceptions: `pHandler` points to `__CxxFrameHandler`, `pHandlerData` points to `__ehfuncinfo`.
  These 8 bytes contain two ADDR32 relocations -- CFA must not disassemble them as PPC instructions.
- **~95% of ADDR32 relocations** in `.text` COMDAT sections are C++ EH headers at offset 0-7
- **`.pdata` entries are sorted by `FuncStart`**: The kernel's `RtlLookupFunctionEntry` does binary
  search, so CFA can rely on sorted ordering for efficient lookup
- **Leaf functions may be absent from `.pdata`**: Only functions with stack frames (callee-saved
  registers, stack allocation) are guaranteed entries. CFA's gap detection phase is essential for
  discovering leaf functions
- **Scale**: DC3 has ~60,000 function entries in `.pdata`
- **Compiler flags**: DC3 is compiled with `/O1 /Oi /GR /EHsc`. `/Oy` (frame pointer omission) is
  implied by `/O1` on Xbox 360, so CFA cannot rely on frame pointer chains. `/EHsc` enables C++
  exception handling, explaining the ubiquitous PDATA_EH headers
- jeff's CFA currently skips word 1 of .pdata entries on `dev` branch (in `tracker.rs:process_data()`)
  to avoid false relocations from the packed bitfield. `cfa_tests` branch is missing this fix

### Tail Blocks and .pdata Limits

MSVC sometimes places code **after** the `.pdata`-reported function end. These "tail blocks" are:
- Out-of-line code moved by the optimizer (cold paths, error handling)
- Only reachable via branches from within the function
- Not covered by `.pdata` boundaries

The `dev` branch has `merge_tail_blocks()` (~670 lines in `cfa.rs`) to detect and merge these.
The `cfa_tests` branch does NOT have this, which means functions with tail blocks will have
incorrect boundaries on `cfa_tests`.

---

## MSVC Xbox 360 Code Generation Patterns

### Register Allocation
- **Declaration order controls register assignment**: Source declaration order -> symbol IDs in IL ->
  coloring order -> interference graph -> register assignment. This is deterministic but non-invertible.
- **Callee-saved vs volatile registers** are processed sequentially during allocation.
- Register allocator uses sparse sorted linked-list interference graphs with 64-register blocks.
- Different registers -> different prologue/epilogue sequences -> affects CFA pattern matching.

### Save/Restore Intrinsic Sleds
MSVC uses helper functions to save/restore callee-saved registers instead of inline instructions:
- `__savegprlr_14` through `__savegprlr_31` (GPR save, also saves LR)
- `__restgprlr_14` through `__restgprlr_31` (GPR restore, also restores LR)
- `__savefpr_14` through `__savefpr_31` (FPR save)
- `__restfpr_14` through `__restfpr_31` (FPR restore)
- `__savevmx_14` through `__savevmx_31` / `__savevmx_64` through `__savevmx_128` (VMX save)
- `__restvmx_14` through `__restvmx_31` / `__restvmx_64` through `__restvmx_128` (VMX restore)

These are detected by `FindSaveRestSledsXbox` in `pass.rs` using byte pattern matching. The sled
functions themselves should always appear in `.pdata`.

### Prologue Patterns (Xbox MSVC)
From `check_prologue_sequence()` in `slices.rs:92-123`:
1. `mfspr r12, LR` / `stw r0, d(r1)` -- LR save (note: code checks for `r0` as source, not `r12`)
2. `mfspr r12, LR` / `bl __savegprlr_N` -- LR save + register intrinsic call
3. `subi rD, rS, XXXX` / `mfspr r12, LR` -- PIC base setup + LR save (negative `addi`)

The `is_mflr` check in the code specifically matches `mfspr r12, LR` (rd=12, spr=8), which is the
Xbox convention. The sequence checker (`check_sequence`) allows intervening instructions between the
two pattern parts, stopping at branches or instructions that use r0/r1 (`is_end_of_seq`).

**Important**: `check_prologue()` and `check_epilogue()` methods are **commented out** on `cfa_tests`
(lines 155-236 in `slices.rs`). They are restored on `dev`. `check_prologue_sequence()` itself is
still active and used by `check_tail_call()` for prologue scanning during tail call disambiguation.

### Branch Patterns Affecting CFA

CFA must handle diverse branch patterns generated by MSVC. Key variants from
`~/code/milohax/dc3-decomp/docs/decomp/patterns/fixable-control-flow.md` and
`~/code/milohax/dc3-decomp/docs/decomp/TECHNICAL_NOTES.md`:

**Bounds check variants** (all equivalent for jump table detection):
```asm
cmplwi  rX, N       ; Canonical unsigned comparison
bgt     default     ; Branch if index > N

cmpwi   rX, N       ; Signed comparison (when switch index is signed int)
bgt     default     ; Same branch condition

cmplwi  rX, N-1     ; Adjusted immediate
bge     default     ; bge with N-1 == bgt with N

cmplwi  rX, N       ; Inverted polarity
ble     switch_body ; ble = branch-if-not-greater
b       default     ; Unconditional branch to default
```

**Inlined string functions** (`strcpy`/`strlen`/`strcmp`/`strcat`) create internal loop patterns.
CFA must not misidentify these as function boundaries.

**Static initialization guards** use `ori r11, r11, bit` + conditional branch to init code.
These create complex intra-function CFGs but always rejoin the main flow.

### Stack Frame Layout
- Caller's return address stored at `sp+4` (PPC/EABI)
- Callee-saved registers saved in descending order from frame base
- `stwu r1, -<size>(r1)` allocates stack frame (updates r1, stores old r1)
- VMX operations trigger 16-byte alignment (instead of normal 8-byte)
- `/Oy` (frame pointer omission) is active under `/O1` on Xbox 360 -- CFA cannot rely on
  `r1`-based frame pointer chains for stack walking or function detection

### ICF (Identical COMDAT Folding)
MSVC's linker merges functions with identical machine code to a single address. In DC3:
- ~31,754 COMDAT-folded symbols creating ~3,068 unique merged addresses
- Some addresses have 76+ symbols pointing to them
- Common ICF targets: destructor pairs, template instantiations, simple getters
- CFA must handle multiple symbols at the same function address

### Floating-Point Specifics
- Fused multiply-add (`fmadds`, `fmsubs`) controlled by `#pragma fp_contract`
- VMX128 has 128 vector registers, flushes denormals to zero (hardware)
- 64-bit unsigned integer conversions use emulation calls (`__u64tod`, `__stou64`, etc.)
- `#pragma optimize("u", on)` enables prescheduling, dramatically reorders instructions

---

## Known Challenges & Open Problems

### 1. Jump Table Size Semantics (byte size vs entry count)

`jump_table_references` (`slices.rs:26`) stores **byte size**, but tests assert **entry count**.
The mismatch originates in `get_jump_table_entries()` (`mod.rs:91-234`), which returns
`(Vec<SectionAddress>, u32)` where the `u32` is the total byte size of the table data read.

The conversion logic (`mod.rs:114-117`) correctly derives `num_entries` from byte size for reading:
```rust
let num_entries = match jump_table_type {
    JumpTableType::Absolute => size / 4,
    JumpTableType::RelativeBytes(_) | JumpTableType::RelativeBytesTimes4(_) => size,
    JumpTableType::RelativeShorts(_) | JumpTableType::RelativeShortsTimes2(_) => size / 2,
};
```
But the returned `size` is **bytes**, not entries. This propagates through `uniq_jump_table_entries()`
(`mod.rs:236-259`) into `slices.rs:421` (`self.jump_table_references.insert(address, size)`) and
then into `AnalyzerState.jump_tables` (`cfa.rs:411`/`454`).

For `RelativeShorts` (2 bytes/entry), byte_size == 2 * entry_count, so tests expecting entry count
see exactly 2x the expected value. For `RelativeBytes` (1 byte/entry), byte_size == entry_count,
masking the bug. This is the **highest-impact fix** -- one change could flip 6+ failing tests.

### 2. Absolute Jump Table Size Guessing

When no `cmplwi` bounds check exists, the guessing routine in `get_jump_table_entries()` (`mod.rs:
195-233`, the `else` branch after `// FIXME`) walks forward reading 4-byte values until it finds a
non-address. It over-counts because trailing code bytes can look like valid addresses within the
same section. The loop breaks on:
- Relocation pointing to an external symbol
- Raw value that doesn't fall within any known section (`obj.sections.at_address(value)` fails)
- Entry outside function bounds (`target < function_start || target >= function_end`)

On `dev`, two fixes help:
- `0db1919`: `let Ok(...) = ... else { break }` -- breaks gracefully on unresolvable entries
  instead of panicking
- `dd8292f`: Uses actual bytes read (`cur_addr.address - addr.address`) as the returned size
  instead of the VM's estimate

FIXME at `mod.rs:195`: `"this guessing routine only works for absolute jump tables"`

### 3. .rdata Jump Table Rejection

`is_valid_jump_table_addr()` (`mod.rs:54-73`) on `cfa_tests` has a bug for absolute tables:
```rust
JumpTableType::Absolute => {
    let kind = obj.sections[addr.section].kind;
    kind == ObjSectionKind::Code && kind != ObjSectionKind::Bss  // redundant: Code != Bss always
}
```
This rejects `.rdata` (`ObjSectionKind::ReadOnlyData`) sections. Xbox MSVC places absolute jump
tables in `.rdata`. On `dev` (`d1297e4`), this becomes:
```rust
matches!(kind, ObjSectionKind::Code | ObjSectionKind::ReadOnlyData)
```
On `cfa_tests`, absolute tables in `.rdata` silently return empty from `uniq_jump_table_entries()`
(`mod.rs:245-247`) because the address validation fails before `get_jump_table_entries()` is called.

### 4. Stack Spill Tracking

MSVC stores a register to the stack (`stw r4, 0x50(r1)`) and reloads it into a *different* register
(`lwz r3, 0x50(r1)`) before using it for the jump table index. The VM loses track of the value
across the stack round-trip.

Current workaround: backward-looking instruction sequence matching in the `Lwz` handler
(`vm.rs:857-918`). When the VM encounters an `lwz` instruction, it disassembles the 3-4
instructions immediately before it and checks for two patterns:

**Pattern A** -- `lwz` + `cmplwi` + `bgt` + `lwz` (`vm.rs:864-888`):
Checks 12 bytes back (3 instructions). If found, copies the first `lwz`'s destination register
value into the current `lwz`'s destination. Requires matching `field_ra()` and `field_offset()`
between the two `lwz` instructions (same stack slot).

**Pattern B** -- `lwz` + `cmplwi` + `ble` + `b` + `lwz` (`vm.rs:890-918`):
Checks 16 bytes back (4 instructions). Same recovery logic but with inverted branch polarity
(`ble` instead of `bgt`, plus an unconditional `b`).

The `bgt` detection checks: `field_bo() & 30 == 12` and `field_bi() & 3 == 1` (CR bit 1 = GT).
The `ble` detection checks: `field_bo() & 30 == 4` and `field_bi() & 3 == 1` (branch-if-false on GT).

A proper solution would be a lightweight stack memory model in the VM.

### 5. Tail Call Disambiguation

When CFA encounters an unconditional `b` instruction to an unknown address, it must decide:
is this a tail call (to another function) or an internal branch? The heuristic in
`check_tail_call()` (`slices.rs:689-808`) uses multiple signals in order:
1. Already a known block -> Not a tail call (`slices.rs:702-703`)
2. Within known function bounds (from `.pdata`) -> Not a tail call (`slices.rs:705-709`)
3. Current function has a prologue -> Not a tail call (`slices.rs:711-713`)
4. Target before function start -> Known tail call (`slices.rs:715-717`)
5. Target in different section -> Known tail call (`slices.rs:719-721`)
6. Zero padding before target (4 bytes of 0x00) -> Known tail call (`slices.rs:723-727`)
7. Function end unknown -> Possible (try again later) (`slices.rs:730-732`)
8. Known function between start and target -> Known tail call (`slices.rs:735-739`)
9. Prologue scan between start and target -> Known tail call if found (`slices.rs:742-762`)
10. Recursive CFA on target -> various heuristics (`slices.rs:764-805`)

Tail blocks (code after `.pdata` end) make this harder because they look like separate functions.
On `dev`, `merge_tail_blocks()` runs as a post-pass to detect and absorb these.

### 6. rlwinm Ordering

The `rlwinm` instruction that multiplies the jump table index can appear BEFORE or AFTER the load.

**Order 1** -- `rlwinm` BEFORE `lbzx`/`lhzx`: The `Rlwinm` handler (`vm.rs:556-644`) produces a
`Range` value with an appropriate step. The `Lbzx`/`Lhzx` handlers then see a `Range` as the index
register and produce `LoadIndexed` with the base type (`RelativeBytes`/`RelativeShorts`).

**Order 2** -- `rlwinm` AFTER `lbzx`/`lhzx`: The load handlers produce `LoadIndexed` with the
base type. When `rlwinm` sees a `LoadIndexed` value as its source (`vm.rs:594-633`), it promotes:
- `RelativeBytes` -> `RelativeBytesTimes4`
- `RelativeShorts` -> `RelativeShortsTimes2`
- Already-promoted types log a warning (shouldn't happen in practice)

The `rlwinm` handler also has `GprSource`-based recovery (`vm.rs:568-580`): if the source register
has `Unknown` value but a tracked `GprSourceLocation::Register(r)`, it checks whether the original
register still has the same version and copies its value if so.

### 7. Relative Jump Table Size Guessing (UNIMPLEMENTED)

The guessing routine in the `else` branch of `get_jump_table_entries()` (`mod.rs:195-233`) only
handles absolute tables -- it reads 4-byte values and checks `obj.sections.at_address()`. There
is no equivalent for 1-byte or 2-byte relative entries. If the VM doesn't detect a `cmplwi`
bounds check, relative tables get `size = None`, and `get_jump_table_entries()` falls through to
the guessing branch which immediately breaks (non-absolute tables don't match the read logic).
The FIXME at `mod.rs:195` acknowledges this gap.

### 8. Bounds Check Variants

The VM's jump table detection relies on `cmplwi` (unsigned compare logical word immediate, opcode
`Cmpli`) for bounds checks. However, MSVC can also generate:
- **`cmpwi`** (signed compare, opcode `Cmpi`) when the switch index is signed
- **`bge` with adjusted immediate** (`cmplwi rX, N-1` + `bge`) instead of `cmplwi rX, N` + `bgt`

The VM's comparison tracking (`vm.rs:537-553`) handles both `Cmpi` and `Cmpli`, and the
`split_values_by_crb()` function (`vm.rs:948-1018`) correctly narrows ranges for all CR bit
conditions (lt=0, gt=1, eq=2, so=3). So the bounds check detection works for both signed and
unsigned comparisons. The `bge` variant also works because `bge` tests the LT bit (crb=0) with
branch-if-false, producing the same range narrowing as `bgt` with a different immediate.

---

## Test Results (on `cfa_tests` branch)

**6 passing, 14 failing** out of 20 tests.

### Passing (6)
- `test_super_basic_cfa` (test 0) - trivial function, no jump table
- `test_jump_table_relative_bytes_1` (test 4) - Minecraft TU2
- `test_jump_table_relative_bytes_2` (test 5) - Sonic Unleashed
- `test_jump_table_relative_bytes_3` (test 6) - Gamepad Debug
- `test_jump_table_relative_bytes_4` (test 7) - Gamepad Debug
- `test_jump_table_relative_bytes_6` (test 9) - TBRB

### Failure Categories

#### 1. Relative short entry count 2x expected (6+ tests)
**Tests**: 11, 12, 15, 16, 17, 18 (`relative_shorts_1/2/5/6/7/8`)
**Symptom**: Reported jump table size is exactly double the expected value.
**Root cause**: Tests assert entry count, but `jump_table_references` stores byte size.
For `RelativeShorts`, each entry is 2 bytes, so `byte_size = 2 * entry_count`.
**Fix**: One change could flip 6+ tests. See [Challenge #1](#1-jump-table-size-semantics-byte-size-vs-entry-count).

#### 2. Absolute jump table size guessing (3 tests)
**Tests**: 1, 2, 3 (`absolute_1/2/3`)
**Symptom**: Test 1 panics, test 2 over-counts entries (16 vs expected 4), test 3 wrong function end.
**Root cause**: Guessing routine over-counts when no `cmplwi` bounds check. See [Challenge #2](#2-absolute-jump-table-size-guessing).
**Note**: `dev` branch has fixes (`0db1919`, `dd8292f`).

#### 3. Function end detected too early (2-3 tests)
**Tests**: 8, 10, 13, 14 (`relative_bytes_5/7`, `relative_shorts_3/4`)
**Symptom**: Function end address is before the expected end -- CFA misses basic blocks.
**Root cause**: Likely missed basic blocks only reachable through jump table entries, or
tail call heuristics incorrectly classifying internal branches.

#### 4. Stack spill tracking (1 test)
**Tests**: 19 (`absolute_stack_meme`)
**Symptom**: Function end wrong because jump table isn't detected.
**Root cause**: Stack round-trip loses register value tracking. See [Challenge #4](#4-stack-spill-tracking).

### Test Source Games
- Tests 0: synthetic
- Tests 1-3, 19: unknown / general MSVC patterns
- Test 4: Minecraft TU2
- Test 5: Sonic Unleashed
- Tests 6-7: Gamepad Debug
- Tests 8-10: TBRB (The Beatles: Rock Band)
- Tests 11-18: various (commented in `cfa_tests.rs`)

---

## Critical Code Differences: cfa_tests vs dev

The `cfa_tests` branch diverged from `main` independently of `dev`. Several Xbox-critical features
exist only on `dev`. Here's an inventory of what `cfa_tests` is **missing**:

### Missing from cfa_tests (present on dev)

1. **Tail block merging** (~670 lines in `cfa.rs`)
   - `merge_tail_blocks()` detects code after `.pdata` function end that belongs to the function
   - `skip_ranges` / `merged_tail_blocks` / `extended_functions` state tracking
   - Without this, functions with out-of-line code have incorrect boundaries

2. **`.rdata` absolute jump table support** (`mod.rs: is_valid_jump_table_addr()`)
   - `dev` allows `ReadOnlyData` sections for absolute jump tables
   - `cfa_tests` only allows `Code` sections -- silently rejects Xbox `.rdata` tables

3. **Jump table size overflow protection** (`mod.rs: get_jump_table_entries()`)
   - `dev` breaks gracefully when an entry can't be resolved (`0db1919`)
   - `cfa_tests` panics or over-counts

4. **Function bounds inflation fix** (`cfa.rs`)
   - `dev` prevents over-estimated jump tables from inflating function boundaries (`dd8292f`)

5. **`.pdata` word 1 metadata skipping** (`tracker.rs:process_data()`)
   - `dev` skips the bitfield word (PrologLen/FuncLen/flags) to avoid false relocations
   - `cfa_tests` processes it, potentially creating invalid relocation entries

6. **`check_prologue()` / `check_epilogue()` restored** (`slices.rs`)
   - Commented out on `cfa_tests` (lines 155-236), restored on `dev`
   - `check_epilogue()` adds `(&is_mtlr, &is_or)` as a third pattern on `dev`
   - `check_prologue_sequence()` adds `Stwux` matching alongside `Stwu` on `dev`

7. **Jump table handling rework in `slices.rs`** (instruction_callback)
   - `dev` distinguishes inline jump tables (addr == bctr+4) from external (.rdata) tables
   - Only inline tables extend the block end; external tables don't affect block boundaries
   - Uses actual byte size from `uniq_jump_table_entries()` instead of VM estimate

8. **`process_function_at()` end preservation** (`cfa.rs`)
   - `dev` preserves `info.end` from .pdata even when slices can't finalize
   - `cfa_tests` sets `info.end = None`, losing the known end

9. **Additional functions** (`cfa.rs` on `dev`)
   - `locate_sda_bases()`: VM-based SDA base detection from entry point
   - `locate_bss_memsets()`: Finds ProDG .bss initialization memset calls
   - `merge_tail_blocks()` / `check_tail_block()`: Post-pass tail block detection

### Missing from dev (present on cfa_tests)

1. **Unit test infrastructure** (`cfa_tests.rs` + `cfa_tests.yml`)
   - 20 test cases with `create_dummy_obj()` for isolated CFA testing
   - Hex-encoded function bytes from real Xbox games

2. **GC/Wii code cleanup**
   - Removed `FindSaveRestSleds` (GC/Wii), `FindTRKInterruptVectorTable`, `signatures.rs`
   - Kept only Xbox-relevant `FindSaveRestSledsXbox`
   - Note: `dev` has `pub mod signatures` restored in `mod.rs` (needed for some functionality)

### Reconciliation Plan
Cherry-pick test infrastructure from `cfa_tests` onto a new branch from `dev`. Expect some test
assertions to change (especially absolute JT tests) due to the fixes on `dev`. The 2x shorts bug
should be fixed regardless of which branch base is used.

---

## Developer Notes (from screenshots in `upload/`)

The screenshots (`upload/hugh1.png`, `upload/hugh2.png`) contain planning notes about jump table
detection strategy.

### Absolute Jump Tables
- Can ignore `bgt`/`blt` for bounds -- some tables don't have them
- Tables can be inline in `.text` OR in `.rdata` on Xbox
- Walk entries, stop when you find a non-address value
- Extra validation: `bctr` address + 4 == start of jump table (for inline `.text` tables)

### Relative Jump Tables
- Start with dtk's vanilla jump table detection, swap `lwzx` for `lbzx`/`lhzx`
- `rlwinm` can come before OR after the load instruction (both orderings exist in MSVC)
- If no `rlwinm`, don't multiply the offset (plain `RelativeBytes`/`RelativeShorts`)
- There WILL be a `bgt` that gives the table size
- If no `bgt`, probably not a jump table
- There must be an `rlwinm` between `bgt`/`l*zx` or between `l*zx`/`bctr`

### Overall TODO
- "Go back to dtk's CFA and jump table analysis, start fresh" -- consider reworking to more
  closely follow dtk's proven patterns, adapted for MSVC/Xenon. Use as research reference.

---

## External Reference Documentation

Relevant docs found across `~/code/milohax/` repositories:

### MSVC Xbox 360 Compiler Behavior
- **`~/code/milohax/dc3-decomp/docs/decomp/MSVC_X360_REGALLOC.md`**
  Deep reverse engineering of MSVC's register allocator internals. Explains why declaration order
  controls register assignment, how interference graphs work, and why the same function recompiled
  with different declaration order gets different registers (and thus different prologues).
  Key CFA detail: Register class processing order (volatile GPR -> callee-saved GPR -> FPR -> CR ->
  LR/CTR) determines which `__savegprlr_N` sled is called, affecting prologue patterns.

- **`~/code/milohax/dc3-decomp/docs/decomp/XBOX360_PRAGMA_REFERENCE.md`**
  Compiler pragmas affecting codegen: `fp_contract` (fused multiply-add), `optimize("u")`
  (prescheduling -- dramatically reorders instructions), bitfield ordering.

- **`~/code/milohax/dc3-decomp/docs/decomp/XBOX360_FLOATING_POINT_CODEGEN.md`**
  FPU vs VMX128 differences. Fused multiply-add detection, denormal behavior, 64-bit integer
  conversion emulation calls (`__u64tod`, etc.), VMX128's 128 vector registers.

- **`~/code/milohax/dc3-decomp/docs/decomp/TECHNICAL_NOTES.md`**
  Stack frame layouts, compiler optimization flags (`/O1` = `/Oy /Ob2 /GF` on Xbox 360),
  inlined string functions (`strcpy`/`strlen`/`strcmp`/`strcat`), merged functions (ICF),
  comparison operator codegen (`cmpwi` vs `cmplwi`, `bge` vs `bgt` with adjusted immediates),
  static init guards (`ori r11, r11, bit`), bool truncation patterns (`clrlwi 24`/`clrlwi 31`).

### Control Flow & Codegen Patterns
- **`~/code/milohax/dc3-decomp/docs/decomp/patterns/fixable-control-flow.md`**
  Branch polarity (`beq`/`bne`), loop forms (for/while/do-while), early returns. Shows how
  `cmplwi + ble` serves the same role as `cmplwi + bgt` for jump table bounds detection.

- **`~/code/milohax/dc3-decomp/docs/decomp/patterns/fixable-declarations.md`**
  Variable declaration order effects on register allocation. Directly impacts CFA's stack tracking
  and prologue detection (different declaration orders produce different register save sequences).

- **`~/code/milohax/dc3-decomp/docs/decomp/patterns/fixable-bool-mask.md`**
  `clrlwi` bool masking instruction patterns. These generate `rlwinm` instructions that CFA's VM
  must not confuse with jump table index shifts (distinguished by SH=0 for bool vs SH=2 for times-4).

- **`~/code/milohax/dc3-decomp/docs/decomp/patterns/fixable-comparison.md`**
  Comparison operator codegen patterns. Signed vs unsigned comparisons affect which opcode
  (`cmpwi` vs `cmplwi`) appears in jump table bounds checks.

- **`~/code/milohax/dc3-decomp/docs/decomp/patterns/unfixable-compiler.md`**
  Compiler scheduling heuristics (instruction reordering, ASSERT_REVS). Affects CFA assumptions
  about instruction ordering in jump table detection.

- **`~/code/milohax/dc3-decomp/docs/decomp/patterns/verifiable-icf.md`**
  ICF (Identical COMDAT Folding) patterns. Critical for understanding how multiple symbols at the
  same address affect CFA's function discovery and symbol resolution.

- **`~/code/milohax/dc3-decomp/docs/decomp/patterns/INDEX.md`**
  Master index of all decomp pattern categories.

### XEX Format & Exception Handling
- **`~/code/milohax/dc3-decomp/docs/reference/FREE60_XEX_FORMAT.md`**
  XEX header structure (magic, module flags, PE data offset, security info, optional headers).
  Image data entries define sections. Content starts at offset 0x2000 with AES CBC encryption.

- **`~/code/milohax/dc3-decomp/docs/sessions/2026-02-12-pdata-role-in-x360-linking.md`**
  Deep dive into `.pdata` format, `IMAGE_CE_RUNTIME_FUNCTION_ENTRY`, exception dispatch mechanism,
  `RtlLookupFunctionEntry` binary search, `RtlUnwind` stack walking. Key CFA details: `.pdata`
  entries are sorted by FuncStart; `FuncLen == 0` also triggers PDATA_EH handling; leaf functions
  may be absent from `.pdata`.

- **`~/code/milohax/dc3-decomp/docs/sessions/2026-02-11-dtk-pdata-splitting-bug.md`**
  Jump table symbol handling bugs, `jumptable_XXXXXXXX` naming convention, COMDAT section splitting.

### PowerPC Architecture & Tooling
- **`~/code/milohax/m2c/docs/VMX128.md`**
  Xbox 360 VMX128 vector extension documentation. VMX128 calling convention and XMVECTOR
  parameter passing -- critical for CFA tracking through SIMD function boundaries.

- **`~/code/milohax/m2c/docs/sessions/M2C_VMX128_INTEGRATION_RESEARCH.md`**
  Deep dive into VMX128 integration with m2c decompiler. XMVECTOR parameter tracking and stack
  handling in decompilation context.

- **`~/code/milohax/m2c/MSVC_SYMBOL_FIX_PLAN.md`**
  Plan for fixing MSVC symbol handling in m2c. Affects symbol resolution relevant to CFA.

- **`~/code/milohax/m2c/m2c/arch_ppc.py`**
  m2c PPC decompiler backend. Shows how another tool handles PPC -> C decompilation.

- **`~/code/milohax/vmx128-research/`**
  Ghidra PPC processor with XEXLoaderWV, powerpc-rs disassembler. Useful for cross-referencing
  disassembly output and understanding Xbox-specific PPC extensions.

- **`~/code/milohax/llvm-project/llvm/lib/Target/PowerPC/`**
  Authoritative LLVM PowerPC backend. PPC calling conventions, instruction definitions.
  Reference for instruction semantics when implementing VM handlers.

### jeff Internal Docs
- **`~/code/milohax/jeff/docs/terminology.md`**
  Technical terminology for jeff/CFA analysis. PowerPC-specific definitions and control flow terms.

- **`~/code/milohax/jeff/docs/other_approaches.md`**
  Alternative CFA approaches considered during jeff design.

- **`~/code/milohax/jeff/archive/lzx-integration.md`**
  LZX compression integration for XEX format parsing (archived, but useful for XEX section handling).

### DC3 Decomp Project Context
- **`~/code/milohax/dc3-decomp/docs/FAQ.md`**
  Project overview. DC3's debug build (no LTO) + map file makes Xbox 360 decomp feasible. jeff was
  created specifically for parsing and splitting Xbox 360 games like DC3.

- **`~/code/milohax/dc3-decomp/docs/reference/PRIORITIZATION.md`**
  Decomp prioritization guide. DC3 has ~46,897 total functions with 50% matched. AT_LIMIT functions
  (90%+) are considered effectively done.

- **`~/code/milohax/dc3-decomp/docs/decomp/GAP_ANALYSIS.md`**
  Strategic investment guide for decompilation effort. Identifies function categories and matching
  priorities.

---

## Branch Reconciliation Notes

The `dev` and `cfa_tests` branches diverged independently from `main`. Important work exists on both:
- `dev`: Production CFA fixes (jump table size, `.rdata` support, tail blocks) + COFF linking work
- `cfa_tests`: Unit test infrastructure + test cases + GC/Wii code cleanup

These will eventually need to be reconciled. The CFA test infrastructure from `cfa_tests` should be
rebased/cherry-picked onto `dev` (or a new branch from `dev`), since `dev` has the more correct CFA
implementation. Some test expectations may need updating after the rebase due to the fixes on `dev`.

Priority order for getting tests green:
1. Fix the 2x shorts byte-size-vs-entry-count semantic mismatch (6+ tests)
2. Port `.rdata` jump table support from `dev` (helps absolute tests)
3. Port jump table size overflow protection from `dev` (helps absolute tests)
4. Investigate function-end-too-early failures (may need tail block merging from `dev`)
5. Stack spill tracking improvements (test 19)
