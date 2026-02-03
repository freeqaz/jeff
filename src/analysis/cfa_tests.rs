use super::*;
use crate::obj::{
    ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
    ObjSymbolKind, ObjSymbolScope,
};

// =========================================================================
// PPC instruction encoding helpers
// =========================================================================

const BLR: u32 = 0x4E800020;
const NOP: u32 = 0x60000000;
const ADDI_R3: u32 = 0x38630001; // addi r3, r3, 1

/// Encode `b offset` (unconditional relative branch, not link, not absolute)
fn ppc_b(offset: i32) -> u32 { 0x48000000 | (offset as u32 & 0x03FFFFFC) }

/// Encode `bne offset` (conditional branch, CR0 not-equal)
fn ppc_bne(offset: i32) -> u32 { 0x40820000 | (offset as u32 & 0x0000FFFC) }

/// Encode `bl offset` (branch and link)
fn ppc_bl(offset: i32) -> u32 { 0x48000001 | (offset as u32 & 0x03FFFFFC) }

/// `bctr` (branch to count register)
const BCTR: u32 = 0x4E800420;

/// Build a minimal code section from instruction words at the given base address.
fn make_code_section(base_addr: u32, instructions: &[u32]) -> ObjSection {
    let data: Vec<u8> = instructions.iter().flat_map(|w| w.to_be_bytes()).collect();
    ObjSection {
        name: ".text".into(),
        kind: ObjSectionKind::Code,
        address: base_addr as u64,
        size: data.len() as u64,
        data,
        align: 4,
        ..Default::default()
    }
}

/// Build a minimal ObjInfo with one code section from instruction words.
fn make_test_obj(base_addr: u32, instructions: &[u32]) -> ObjInfo {
    let section = make_code_section(base_addr, instructions);
    ObjInfo::new(
        ObjKind::Executable,
        ObjArchitecture::PowerPc,
        "test".to_string(),
        vec![],
        vec![section],
    )
}

/// Add a function symbol to `obj` at the given address with given size.
fn add_func_symbol(obj: &mut ObjInfo, name: &str, addr: u32, size: u32, scope: ObjSymbolScope) {
    let mut flags = ObjSymbolFlagSet::default();
    flags.set_scope(scope);
    obj.add_symbol(
        ObjSymbol {
            name: name.to_string(),
            address: addr as u64,
            section: Some(0),
            size: size as u64,
            size_known: true,
            kind: ObjSymbolKind::Function,
            flags,
            ..Default::default()
        },
        false,
    )
    .unwrap();
}

// =========================================================================
// Helper function tests
// =========================================================================

#[test]
fn test_is_unconditional_blr() {
    use powerpc::{Extensions, Ins};
    let blr = Ins::new(BLR, Extensions::xenon());
    assert!(AnalyzerState::is_unconditional_blr(&blr));

    let nop = Ins::new(NOP, Extensions::xenon());
    assert!(!AnalyzerState::is_unconditional_blr(&nop));

    // blrl (link bit set) should not count
    let blrl = Ins::new(0x4E800021, Extensions::xenon());
    assert!(!AnalyzerState::is_unconditional_blr(&blrl));
}

#[test]
fn test_branch_into_range() {
    use powerpc::{Extensions, Ins};
    // b -0xC at address 0x1010 -> target 0x1004
    let ins = Ins::new(ppc_b(-0xC), Extensions::xenon());
    let result = AnalyzerState::branch_into_range(&ins, 0x1010, 0x1000, 0x1010);
    assert_eq!(result, Some(0x1004));

    // Same branch but range doesn't contain target
    let result = AnalyzerState::branch_into_range(&ins, 0x1010, 0x1008, 0x1010);
    assert_eq!(result, None);

    // bl (link bit) should return None
    let bl_ins = Ins::new(ppc_bl(-0xC), Extensions::xenon());
    let result = AnalyzerState::branch_into_range(&bl_ins, 0x1010, 0x1000, 0x1010);
    assert_eq!(result, None);
}

// =========================================================================
// check_tail_block tests
// =========================================================================

/// Case 1: Classic tail block -- starts with `b` back into preceding function, ends with blr.
#[test]
fn test_tail_block_case1_backward_branch_then_blr() {
    let section = make_code_section(0x1000, &[
        NOP, NOP, NOP, NOP,         // preceding func body
        ppc_b(-0xC),                 // b 0x1004 (back into preceding)
        ADDI_R3,                     // addi r3, r3, 1
        BLR,                         // blr
    ]);

    let result = AnalyzerState::check_tail_block(
        &section,
        SectionAddress::new(0, 0x1010),
        SectionAddress::new(0, 0x101C),
        SectionAddress::new(0, 0x1000),
        SectionAddress::new(0, 0x1010),
    );
    assert_eq!(result, Some(SectionAddress::new(0, 0x101C)));
}

/// Case 2: Conditional backward branch + blr.
#[test]
fn test_tail_block_case2_conditional_backward_branch_with_blr() {
    let section = make_code_section(0x1000, &[
        NOP, NOP, NOP, NOP,         // preceding func
        ADDI_R3,                     // 0x1010
        ppc_bne(-0x14),              // 0x1014: bne -> 0x1004
        BLR,                         // 0x1018: blr
    ]);

    let result = AnalyzerState::check_tail_block(
        &section,
        SectionAddress::new(0, 0x1010),
        SectionAddress::new(0, 0x101C),
        SectionAddress::new(0, 0x1000),
        SectionAddress::new(0, 0x1010),
    );
    assert_eq!(result, Some(SectionAddress::new(0, 0x101C)));
}

/// Not a tail block: gap contains a function call (bl).
#[test]
fn test_not_tail_block_contains_call() {
    let section = make_code_section(0x1000, &[
        NOP, NOP, NOP, NOP,
        ppc_bl(0x100),               // bl (function call)
        BLR,
    ]);

    let result = AnalyzerState::check_tail_block(
        &section,
        SectionAddress::new(0, 0x1010),
        SectionAddress::new(0, 0x1018),
        SectionAddress::new(0, 0x1000),
        SectionAddress::new(0, 0x1010),
    );
    assert_eq!(result, None);
}

/// Not a tail block: forward branch to another function.
#[test]
fn test_not_tail_block_forward_branch() {
    let section = make_code_section(0x1000, &[
        NOP, NOP, NOP, NOP,
        ppc_b(0x100),                // b 0x1110 (forward)
        BLR,
    ]);

    let result = AnalyzerState::check_tail_block(
        &section,
        SectionAddress::new(0, 0x1010),
        SectionAddress::new(0, 0x1018),
        SectionAddress::new(0, 0x1000),
        SectionAddress::new(0, 0x1010),
    );
    assert_eq!(result, None);
}

/// Not a tail block: gap too large (> 64 bytes).
#[test]
fn test_not_tail_block_too_large() {
    let mut insns = vec![NOP; 4]; // preceding func
    insns.extend(std::iter::repeat(NOP).take(20)); // 80 bytes
    let section = make_code_section(0x1000, &insns);

    let result = AnalyzerState::check_tail_block(
        &section,
        SectionAddress::new(0, 0x1010),
        SectionAddress::new(0, 0x1060), // 80 bytes > 64
        SectionAddress::new(0, 0x1000),
        SectionAddress::new(0, 0x1010),
    );
    assert_eq!(result, None);
}

/// Not a tail block: backward branch but no blr.
#[test]
fn test_not_tail_block_no_blr() {
    let section = make_code_section(0x1000, &[
        NOP, NOP, NOP, NOP,
        ADDI_R3,
        ppc_bne(-0x14),              // bne -> 0x1004
        NOP,                         // no blr
    ]);

    let result = AnalyzerState::check_tail_block(
        &section,
        SectionAddress::new(0, 0x1010),
        SectionAddress::new(0, 0x101C),
        SectionAddress::new(0, 0x1000),
        SectionAddress::new(0, 0x1010),
    );
    assert_eq!(result, None);
}

/// Not a tail block: contains bctr.
#[test]
fn test_not_tail_block_indirect_branch() {
    let section = make_code_section(0x1000, &[
        NOP, NOP, NOP, NOP,
        BCTR,
    ]);

    let result = AnalyzerState::check_tail_block(
        &section,
        SectionAddress::new(0, 0x1010),
        SectionAddress::new(0, 0x1014),
        SectionAddress::new(0, 0x1000),
        SectionAddress::new(0, 0x1010),
    );
    assert_eq!(result, None);
}

/// Case 1 variant: blr found before gap_end (tail block shorter than gap).
#[test]
fn test_tail_block_case1_blr_before_gap_end() {
    let section = make_code_section(0x1000, &[
        NOP, NOP, NOP, NOP,
        ppc_b(-0xC),                 // b 0x1004
        BLR,                         // blr at 0x1014
        NOP,                         // padding
    ]);

    let result = AnalyzerState::check_tail_block(
        &section,
        SectionAddress::new(0, 0x1010),
        SectionAddress::new(0, 0x101C), // gap extends past blr
        SectionAddress::new(0, 0x1000),
        SectionAddress::new(0, 0x1010),
    );
    assert_eq!(result, Some(SectionAddress::new(0, 0x1018)));
}

/// Exactly at MAX_TAIL_BLOCK_BYTES boundary (64 bytes = 16 instructions).
#[test]
fn test_tail_block_at_max_size_boundary() {
    let mut insns = vec![NOP; 4]; // preceding func (0x1000..0x1010)
    // 16-instruction tail block (exactly 64 bytes, 0x1010..0x1050)
    for _ in 0..14 {
        insns.push(NOP);
    }
    insns.push(ppc_b(-0x40)); // b back into preceding func
    insns.push(BLR);

    let section = make_code_section(0x1000, &insns);

    let result = AnalyzerState::check_tail_block(
        &section,
        SectionAddress::new(0, 0x1010),
        SectionAddress::new(0, 0x1050), // exactly 64 bytes
        SectionAddress::new(0, 0x1000),
        SectionAddress::new(0, 0x1010),
    );
    assert_eq!(result, Some(SectionAddress::new(0, 0x1050)));
}

// =========================================================================
// merge_tail_blocks tests
// =========================================================================

/// Test that merge_tail_blocks merges a simple tail block into its predecessor.
#[test]
fn test_merge_tail_blocks_basic() {
    let mut obj = make_test_obj(0x1000, &[
        NOP, NOP, NOP, NOP,
        ppc_b(-0xC),
        ADDI_R3,
        BLR,
    ]);

    add_func_symbol(&mut obj, "fn_00001000", 0x1000, 0x10, ObjSymbolScope::Local);
    add_func_symbol(&mut obj, "fn_00001010", 0x1010, 0x0C, ObjSymbolScope::Local);

    let mut state = AnalyzerState::default();
    state.functions.insert(
        SectionAddress::new(0, 0x1000),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x1010)),
            slices: None,
        },
    );
    state.functions.insert(
        SectionAddress::new(0, 0x1010),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x101C)),
            slices: None,
        },
    );

    state.merge_tail_blocks(&obj).unwrap();

    assert!(!state.functions.contains_key(&SectionAddress::new(0, 0x1010)));
    let func1 = state.functions.get(&SectionAddress::new(0, 0x1000)).unwrap();
    assert_eq!(func1.end, Some(SectionAddress::new(0, 0x101C)));
    assert!(state.merged_tail_blocks.contains(&SectionAddress::new(0, 0x1010)));
    assert!(state.extended_functions.contains(&SectionAddress::new(0, 0x1000)));
}

/// Test that merge_tail_blocks skips functions with global-scope symbols.
#[test]
fn test_merge_tail_blocks_preserves_global_scope() {
    let mut obj = make_test_obj(0x1000, &[
        NOP, NOP, NOP, NOP,
        ppc_b(-0xC),
        ADDI_R3,
        BLR,
    ]);

    add_func_symbol(&mut obj, "fn_00001000", 0x1000, 0x10, ObjSymbolScope::Local);
    add_func_symbol(&mut obj, "RealFunction", 0x1010, 0x0C, ObjSymbolScope::Global);

    let mut state = AnalyzerState::default();
    state.functions.insert(
        SectionAddress::new(0, 0x1000),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x1010)),
            slices: None,
        },
    );
    state.functions.insert(
        SectionAddress::new(0, 0x1010),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x101C)),
            slices: None,
        },
    );

    state.merge_tail_blocks(&obj).unwrap();

    // Both functions should still exist
    assert!(state.functions.contains_key(&SectionAddress::new(0, 0x1000)));
    assert!(state.functions.contains_key(&SectionAddress::new(0, 0x1010)));
    assert!(state.merged_tail_blocks.is_empty());
    assert!(state.extended_functions.is_empty());
}

/// Test that apply() marks merged tail block symbols as deleted.
#[test]
fn test_apply_removes_merged_tail_block_symbols() {
    let mut obj = make_test_obj(0x1000, &[
        NOP, NOP, NOP, NOP,
        ppc_b(-0xC),
        ADDI_R3,
        BLR,
    ]);

    add_func_symbol(&mut obj, "fn_00001010", 0x1010, 0x0C, ObjSymbolScope::Local);

    let mut state = AnalyzerState::default();
    state.functions.insert(
        SectionAddress::new(0, 0x1000),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x101C)),
            slices: None,
        },
    );
    state.merged_tail_blocks.push(SectionAddress::new(0, 0x1010));

    state.apply(&mut obj).unwrap();

    let result =
        obj.symbols.kind_at_section_address(0, 0x1010, ObjSymbolKind::Function).unwrap();
    assert!(result.is_none(), "Function symbol should be stripped/deleted after apply");
}

/// Test that apply() updates symbol sizes for extended functions.
#[test]
fn test_apply_extends_function_size() {
    let mut obj = make_test_obj(0x1000, &[
        NOP, NOP, NOP, NOP,
        ppc_b(-0xC),
        ADDI_R3,
        BLR,
    ]);

    add_func_symbol(&mut obj, "fn_00001000", 0x1000, 0x10, ObjSymbolScope::Local);

    let mut state = AnalyzerState::default();
    state.functions.insert(
        SectionAddress::new(0, 0x1000),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x101C)),
            slices: None,
        },
    );
    state.extended_functions.push(SectionAddress::new(0, 0x1000));

    state.apply(&mut obj).unwrap();

    let (_, sym) = obj
        .symbols
        .kind_at_section_address(0, 0x1000, ObjSymbolKind::Function)
        .unwrap()
        .expect("function symbol should exist");
    assert_eq!(sym.size, 0x1C, "symbol size should be extended to 0x1C");
    assert!(sym.size_known);
}

/// Test merging multiple sequential tail blocks into one predecessor.
#[test]
fn test_merge_multiple_sequential_tail_blocks() {
    let mut obj = make_test_obj(0x1000, &[
        NOP, NOP, NOP, NOP,     // func1 body (0x1000..0x1010)
        ppc_b(-0xC),            // 0x1010: b 0x1004
        ADDI_R3,                // 0x1014
        BLR,                    // 0x1018: blr
        ppc_b(-0x18),           // 0x101C: b 0x1008 (back into func1)
        BLR,                    // 0x1020: blr
    ]);

    add_func_symbol(&mut obj, "fn_00001000", 0x1000, 0x10, ObjSymbolScope::Local);
    add_func_symbol(&mut obj, "fn_00001010", 0x1010, 0x0C, ObjSymbolScope::Local);
    add_func_symbol(&mut obj, "fn_0000101C", 0x101C, 0x08, ObjSymbolScope::Local);

    let mut state = AnalyzerState::default();
    state.functions.insert(
        SectionAddress::new(0, 0x1000),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x1010)),
            slices: None,
        },
    );
    state.functions.insert(
        SectionAddress::new(0, 0x1010),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x101C)),
            slices: None,
        },
    );
    state.functions.insert(
        SectionAddress::new(0, 0x101C),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x1024)),
            slices: None,
        },
    );

    state.merge_tail_blocks(&obj).unwrap();

    assert!(!state.functions.contains_key(&SectionAddress::new(0, 0x1010)));
    assert!(state.merged_tail_blocks.contains(&SectionAddress::new(0, 0x1010)));

    let func1 = state.functions.get(&SectionAddress::new(0, 0x1000)).unwrap();
    assert!(func1.end.unwrap().address >= 0x101C);
}

/// Test that non-adjacent functions are not merged.
#[test]
fn test_merge_tail_blocks_skips_non_adjacent() {
    let mut obj = make_test_obj(0x1000, &[
        NOP, NOP, NOP, NOP,         // func1 (0x1000..0x1010)
        NOP,                         // gap (0x1010..0x1014)
        ppc_b(-0x10),                // 0x1014: b 0x1004
        BLR,                         // 0x1018
    ]);

    add_func_symbol(&mut obj, "fn_00001000", 0x1000, 0x10, ObjSymbolScope::Local);
    add_func_symbol(&mut obj, "fn_00001014", 0x1014, 0x08, ObjSymbolScope::Local);

    let mut state = AnalyzerState::default();
    state.functions.insert(
        SectionAddress::new(0, 0x1000),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x1010)),
            slices: None,
        },
    );
    state.functions.insert(
        SectionAddress::new(0, 0x1014),
        FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x101C)),
            slices: None,
        },
    );

    state.merge_tail_blocks(&obj).unwrap();

    assert!(state.functions.contains_key(&SectionAddress::new(0, 0x1000)));
    assert!(state.functions.contains_key(&SectionAddress::new(0, 0x1014)));
    assert!(state.merged_tail_blocks.is_empty());
}

/// Test FunctionInfo state detection methods.
#[test]
fn test_function_info_states() {
    let default_info = FunctionInfo::default();
    assert!(!default_info.is_analyzed());
    assert!(!default_info.is_function());
    assert!(!default_info.is_non_function());
    assert!(!default_info.is_unfinalized());

    let non_function = FunctionInfo { analyzed: true, end: None, slices: None };
    assert!(non_function.is_non_function());

    let unfinalized = FunctionInfo {
        analyzed: true,
        end: None,
        slices: Some(FunctionSlices::default()),
    };
    assert!(unfinalized.is_unfinalized());

    let complete = FunctionInfo {
        analyzed: true,
        end: Some(SectionAddress::new(0, 0x100)),
        slices: Some(FunctionSlices::default()),
    };
    assert!(complete.is_function());
}
