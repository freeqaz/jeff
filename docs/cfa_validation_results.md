# CFA Validation Results

Validation performed 2026-02-21.

## Comparison A: Fork vs Upstream (origin/main)

**Question:** What do our 118 commits fix that rjkiv/jeff doesn't?

**Method:** Built `dtk` from `origin/main` and `fork/main`, ran `xex split` on DC3 (config/373307D9/config.yml), diffed output.

### Results

| Metric | Value |
|---|---|
| Functions detected | 69,336 (both) |
| Crashes/panics | 0 (both) |
| Differing .s files | 770 / ~2,500 total |
| Differing .obj files | 2,218 |
| Files with function size changes | 137 |
| Files with .rdata section relocation | 640 |
| Total code size delta | +556 bytes (fork larger) |

**No crashes from upstream.** Both complete successfully. The differences are structural, not crash-preventing.

### Difference Categories

1. **`.rdata` jump table relocation (640 files):** Upstream puts jump table data in separate `.rdata$r` sections with absolute addresses. Fork keeps jump table data inline in `.rdata` within the function's section. This is the `.rdata` absolute jump table fix — it allows objdiff to correctly resolve jump table references for matching.

2. **Function size changes (137 files, all fork-larger):** Fork detects additional trailing code that upstream misses. All 137 files have the fork version strictly larger (never smaller). Typical delta is +4 bytes (padding/alignment) with the largest being +8 bytes. This comes from:
   - **Tail block detection:** Fork detects 2 tail blocks that upstream marks as "Not a function" and merges them into their parent functions:
     - `0x82D4FFA8-0x82D4FFE0` → merged into function at `0x82D4FF38`
     - `0x82D51A30-0x82D51A64` → merged into function at `0x82D519F0`
   - **Alignment changes:** `.balign 4` → `.balign 8` in many files

3. **Symbol naming (lbl_ references, ~15 files):** Minor differences in local label naming.

### Value Assessment

The fork's changes are **correctness improvements**, not crash fixes:
- Jump table data is placed in the correct section for COFF object matching
- Tail blocks are properly attributed to their parent functions
- Section alignment is more accurate

These matter for decomp matching but are not required for basic splitting.

## Comparison B: Candidate vs Legacy (within fork)

**Question:** Does the pipeline abstraction (Candidate mode) change anything vs Legacy?

**Method:** Ran `DTK_CFA_PIPELINE_MODE=legacy` and `DTK_CFA_PIPELINE_MODE=candidate` on DC3, diffed output.

### Results

| Metric | Value |
|---|---|
| Differing files (excluding paths) | **0** |

**Output is 100% identical.** The only differences are output directory paths in `config.json` and `dep` files. The Candidate pipeline's seed discovery adds nothing for DC3.

### Conclusion

The pipeline abstraction (Layer 2) and shadow VM (Layer 3) can be fully removed. They add ~6,400 lines of code with zero behavioral impact on DC3 output.

## Summary

| Layer | Lines | Impact on DC3 | Verdict |
|---|---|---|---|
| Layer 1: Analysis fixes (vm.rs, slices.rs, mod.rs, split.rs, xex.rs) | ~6,700 | 770 files improved | **Keep** |
| Layer 2: Pipeline abstraction (pipeline.rs, cfa.rs types) | ~2,100 | None | **Remove** |
| Layer 3: Shadow VM (vm2.rs, shadow tests) | ~4,600 | None | **Remove** |
