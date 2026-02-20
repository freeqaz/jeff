# DTK OOM Bug: comdat_symbols HashSet Cloning

## Summary

`dtk xex split` OOM-killed at **19GB RSS** (kernel killed at 07:08:51). Root cause: cloning a HashSet of 88,062 COMDAT symbol names to each of the 2,223 split objects.

## Root Cause

In `src/util/split.rs` lines 1460-1464:

```rust
if !comdat_symbols.is_empty() {
    log::debug!("Marking {} symbols as COMDAT", comdat_symbols.len());
    for obj in &mut objects {
        obj.comdat_symbols = comdat_symbols.clone();  // <-- THIS LINE
    }
}
```

### The Math

- `comdat_symbols` contains **88,062** unique symbol names (all global defined symbols except lbl_*, pdata@*, except_data_*, except_record_*, __unwind$*)
- Each `HashSet<String>` clone costs ~13 MB (88K entries * ~156 bytes/entry including String heap + HashSet overhead)
- Cloned to **2,223 objects** = **~28.4 GB total**
- Kernel killed dtk at 19GB (hadn't finished all clones)

### Why This Didn't Happen Before

The COMDAT expansion (commit range HEAD~3..HEAD in xex.rs) changed from only handling `__unwind$` symbols (a few hundred) to ALL global defined symbols (88K). The HashSet cloning existed before but was trivially small.

## Recommended Fix

The `comdat_symbols` set is only read (`.contains()` checks) in `write_coff()`, never mutated. Three fix options, in order of preference:

### Option A: Per-object filtering (best - minimal memory, no API change)

```rust
if !comdat_symbols.is_empty() {
    log::debug!("Marking {} symbols as COMDAT", comdat_symbols.len());
    for obj in &mut objects {
        // Only keep symbols that actually exist in this object
        let local: HashSet<String> = obj.symbols.iter()
            .filter(|(_, sym)| sym.flags.is_global()
                && sym.section.is_some()
                && comdat_symbols.contains(&sym.name))
            .map(|(_, sym)| sym.name.clone())
            .collect();
        obj.comdat_symbols = local;
    }
}
```

Memory: ~88K total entries across all objects (each symbol in exactly one object) = ~13 MB total instead of 28 GB.

### Option B: Shared reference via Arc

```rust
// In ObjInfo: pub comdat_symbols: Arc<HashSet<String>>,
let shared = Arc::new(comdat_symbols);
for obj in &mut objects {
    obj.comdat_symbols = Arc::clone(&shared);  // 8 bytes per clone
}
```

Memory: 13 MB (one copy) + 8 bytes * 2,223 objects. Requires changing the field type.

### Option C: Pass as separate parameter to write_coff

```rust
pub fn write_coff(obj: &ObjInfo, comdat_symbols: &HashSet<String>) -> Result<Vec<u8>>
```

Memory: 13 MB (one copy). Requires API change.

## How to Test

```bash
# Run split and monitor memory (should stay well under 1GB, was 19GB before)
RUST_LOG=debug dtk xex split config/373307D9/config.yml /tmp/dtk-test-output 2>&1 | grep "Marking"

# Quick validation that it still produces correct .obj files:
# Compare output of a few .obj files before/after the fix
diff <(xxd /tmp/dtk-test-output/obj/App.obj | head -100) <(xxd build/373307D9/obj/App.obj | head -100)
```

## OOM Timeline

```
06:48:19 - qbittorrent-nox killed (2.3GB) - first victim
07:08:51 - dtk killed (19GB RSS, 22GB VM) - main culprit
07:08:51 - dbus-broker killed (collateral damage)
07:08:51 - clang++ invoked OOM killer (collateral - ninja builds running in parallel)
```

## Impact

- Blocking: `ninja` builds fail because `dtk xex split` is a prerequisite step
- The fix is safe: all three options are semantically equivalent (same set of symbols checked)
- The existing COMDAT extraction logic in `write_coff` is correct; only the storage/sharing is the problem
