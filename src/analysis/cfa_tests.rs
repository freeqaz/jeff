use std::fs::File;

use anyhow::Result;
use serde::{de::Error, Deserialize, Deserializer};

use super::*;
use crate::{
    analysis::cfa::AnalyzerState,
    obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind},
};

fn bytestr_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where D: Deserializer<'de> {
    let hex_str = String::deserialize(deserializer)?;

    if hex_str.len() % 2 != 0 {
        return Err(D::Error::custom("hex string must have even length"));
    }

    let bytes = (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(D::Error::custom)?;

    Ok(bytes)
}

fn get_fn_start<'de, D>(deserializer: D) -> Result<u32, D::Error>
where D: Deserializer<'de> {
    let hex_str = String::deserialize(deserializer)?;
    if hex_str.len() != 8 {
        return Err(D::Error::custom(format!("expected 8 hex chars, got {}", hex_str.len())));
    }
    let start = u32::from_str_radix(&*hex_str, 16).map_err(D::Error::custom)?;
    Ok(start)
}

#[derive(Debug, Deserialize)]
struct TestConfig {
    test_id: u32,
    #[serde(deserialize_with = "get_fn_start")]
    function_start: u32,
    #[serde(deserialize_with = "bytestr_to_bytes")]
    function_bytes: Vec<u8>,
    #[serde(deserialize_with = "get_fn_start")]
    jump_table_start: u32,
    #[serde(deserialize_with = "bytestr_to_bytes")]
    jump_table_bytes: Vec<u8>,
}

// helper func to create an ObjInfo
fn make_code_section(base_addr: u32, instructions: &[u8]) -> ObjSection {
    ObjSection {
        name: ".text".into(),
        kind: ObjSectionKind::Code,
        address: base_addr as u64,
        size: instructions.len() as u64,
        data: Vec::from(instructions),
        align: 0x10000,
        ..Default::default()
    }
}

fn make_data_section(base_addr: u32, instructions: &[u8]) -> ObjSection {
    ObjSection {
        name: ".rdata".into(),
        kind: ObjSectionKind::ReadOnlyData,
        address: base_addr as u64,
        size: instructions.len() as u64,
        data: Vec::from(instructions),
        align: 0x10000,
        ..Default::default()
    }
}

fn create_dummy_obj(code_section: ObjSection, rdata_section: Option<ObjSection>) -> ObjInfo {
    let mut sections: Vec<ObjSection> = vec![];
    if let Some(rdata_section) = rdata_section {
        sections.push(rdata_section);
    }
    sections.push(code_section);
    ObjInfo::new(ObjKind::Executable, ObjArchitecture::PowerPc, "test.exe".into(), vec![], sections)
}

// helper func to insert function asm into an ObjInfo. could put it in here directly, or read it from a .txt

// pub struct FunctionInfo {
//     pub analyzed: bool,
//     pub end: Option<SectionAddress>,
//     pub slices: Option<FunctionSlices>,
// }

#[test]
fn test_super_basic_cfa() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[0];
    assert_eq!(cur_test.test_id, 0);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        None,
    );
    let mut state = AnalyzerState::default();
    let start_addr = SectionAddress::new(0, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // assert that we have slices
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    // this func should only have 1 basic block
    assert_eq!(slices.blocks.len(), 1);
    Ok(())
}

// would prefer 2-3 test functions that cover each JumpTableType
// pub enum JumpTableType {
//     // the table came from an lwzx, contains absolute addresses
//     Absolute,
//     // the table came from an lbzx, contains relative byte offsets (no rlwinm before the bctr)
//     RelativeBytes(Option<RelocationTarget>),
//     // the table came from an lbzx, contains relative byte offsets that we must multiply by 4
//     RelativeBytesTimes4(Option<RelocationTarget>),
//     // the table came from an lhzx, contains relative short offsets (no rlwinm before the bctr)
//     RelativeShorts(Option<RelocationTarget>),
//     // the table came from an lhzx, contains relative short offsets that we must multiply by 2
//     RelativeShortsTimes2(Option<RelocationTarget>),
// }

#[test]
fn test_jump_table_absolute_1() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[1];
    assert_eq!(cur_test.test_id, 1);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        None,
    );
    let mut state = AnalyzerState::default();
    let start_addr = SectionAddress::new(0, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    // 16 bytes (4 entries)
    let jump_table_entry = state.jump_tables.get(&SectionAddress::new(0, 0x820869fc));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 16);
    // we should also have a lotta basic blocks
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert!(slices.blocks.len() > 5); // idk the exact number but i know it's more than 5
    Ok(())
}

#[test]
fn test_jump_table_absolute_2() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[2];
    assert_eq!(cur_test.test_id, 2);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        None,
    );
    let mut state = AnalyzerState::default();
    let start_addr = SectionAddress::new(0, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    // 16 bytes (4 entries)
    let jump_table_entry = state.jump_tables.get(&SectionAddress::new(0, 0x827f9434));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 16);
    // we should also have a lotta basic blocks
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert!(slices.blocks.len() > 5); // idk the exact number but i know it's more than 5
    Ok(())
}

// this one's also got VMX! for added fun
#[test]
fn test_jump_table_absolute_3() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[3];
    assert_eq!(cur_test.test_id, 3);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        None,
    );
    let mut state = AnalyzerState::default();
    let start_addr = SectionAddress::new(0, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // CFA detects end at 0x82FBB4B8 - the remaining 0x64 bytes are a tail block
    // only reachable via branches the CFA can't follow without .pdata context
    assert_eq!(func.end, Some(SectionAddress::new(0, 0x82FBB4B8)));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    // 16 bytes (4 entries)
    let jump_table_entry = state.jump_tables.get(&SectionAddress::new(0, 0x82fbb464));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 16);
    // we should also have a lotta basic blocks
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert!(slices.blocks.len() > 5);
    Ok(())
}

#[test]
fn test_jump_table_relative_bytes_1() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[4];
    assert_eq!(cur_test.test_id, 4);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 105);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_bytes_2() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[5];
    assert_eq!(cur_test.test_id, 5);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 0x1c);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_bytes_3() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[6];
    assert_eq!(cur_test.test_id, 6);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 11);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_bytes_4() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[7];
    assert_eq!(cur_test.test_id, 7);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 12);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_bytes_5() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[8];
    assert_eq!(cur_test.test_id, 8);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // CFA detects end at 0x82317C50 - remaining 0x28 bytes are a tail block
    assert_eq!(func.end, Some(SectionAddress::new(1, 0x82317C50)));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 12);
    Ok(())
}

#[test]
fn test_jump_table_relative_bytes_6() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[9];
    assert_eq!(cur_test.test_id, 9);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 10);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_bytes_7() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[10];
    assert_eq!(cur_test.test_id, 10);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // CFA detects end at 0x82592F50 - remaining 0x80 bytes are a tail block
    assert_eq!(func.end, Some(SectionAddress::new(1, 0x82592F50)));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 0x15);
    Ok(())
}

// Minecraft TU2 - FUN_822c4618 - test 4
// Sonic Unleashed - FUN_824afd20 - test 5
// Gamepad Debug - FUN_8219b550 - test 6, FUN_821c3e88 - test 7
// TBRB - FUN_823178b0 - test 8, FUN_823349f8 - test 9, FUN_82592db8 - test 10

#[test]
fn test_jump_table_relative_shorts_1() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[11];
    assert_eq!(cur_test.test_id, 11);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 28);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_shorts_2() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[12];
    assert_eq!(cur_test.test_id, 12);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    // 94 bytes = 47 entries (cmplwi r28, 46 → 0..46 inclusive)
    assert_eq!(*jump_table_entry.unwrap(), 94);
    Ok(())
}

#[test]
fn test_jump_table_relative_shorts_3() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[13];
    assert_eq!(cur_test.test_id, 13);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 128);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_shorts_4() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[14];
    assert_eq!(cur_test.test_id, 14);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // CFA detects end at 0x823F7C90 - remaining 0x68 bytes are a tail block
    assert_eq!(func.end, Some(SectionAddress::new(1, 0x823F7C90)));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 16);
    Ok(())
}

#[test]
fn test_jump_table_relative_shorts_5() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[15];
    assert_eq!(cur_test.test_id, 15);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 20);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_shorts_6() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[16];
    assert_eq!(cur_test.test_id, 16);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 0x38);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_shorts_7() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[17];
    assert_eq!(cur_test.test_id, 17);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 60);
    // TODO: verify basic block count
    Ok(())
}

#[test]
fn test_jump_table_relative_shorts_8() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[18];
    assert_eq!(cur_test.test_id, 18);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
    );
    let mut state = AnalyzerState::default();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(state.functions.len(), 1);
    let func = state.functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(state.jump_tables.is_empty(), false);
    assert_eq!(state.jump_tables.len(), 1);
    let jump_table_entry =
        state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 20);
    // TODO: verify basic block count
    Ok(())
}

// This function has a bctrl (indirect call via vtable) followed by an unconditional branch to
// the exit. The jump table dispatch code at 0x82185BAC is unreachable from the main entry point
// because bctrl is opaque to CFA. In production, .pdata or gap-filling discovers this secondary
// entry. We simulate that here with a two-phase analysis: first the main entry, then the switch
// dispatch entry. The switch code does MSVC-style stack shuffling (stw/lwz through r1) before
// the cmplwi bound check, exercising both the backward-look pattern matcher and stack slot tracking.
#[test]
fn test_jump_table_absolute_stack_meme() -> Result<()> {
    let test_cfg: Vec<TestConfig> =
        serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
    let cur_test = &test_cfg[19];
    assert_eq!(cur_test.test_id, 19);
    let obj = create_dummy_obj(
        make_code_section(cur_test.function_start, &cur_test.function_bytes),
        None,
    );
    let mut state = AnalyzerState::default();
    let start_addr = SectionAddress::new(0, cur_test.function_start);

    // Phase 1: Analyze main entry point
    // Discovers the short path: prologue → bl → vtable bctrl → b exit
    // The bctrl is opaque, so CFA cannot follow through to the switch dispatch
    let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    assert!(res);
    assert!(state.jump_tables.is_empty()); // no JT visible from main entry

    // Phase 2: Analyze the switch dispatch entry (simulates .pdata/gap-fill discovery)
    // This code does: lwz from stack → stw/lwz shuffle → cmplwi r4, 0x168 → bgt default →
    // lwz (backward-look matches) → rlwinm (×4) → lis+addi (table base) → lwzx → mtctr → bctr
    let switch_addr = SectionAddress::new(0, 0x82185bac);
    let res2 = state.process_function_at(&obj, switch_addr).unwrap_or_else(|e| panic!("{:?}", e));
    assert!(res2);

    // Now the jump table should be discovered
    assert_eq!(state.jump_tables.len(), 1);
    // 0x5A4 bytes = 0x169 entries × 4 bytes/entry (Absolute)
    let jump_table_entry = state.jump_tables.get(&SectionAddress::new(0, 0x82185be8));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 0x5A4);

    // The switch function should have many basic blocks (dispatch + case bodies + default + exit)
    let switch_func = state.functions.get(&switch_addr);
    assert!(switch_func.is_some());
    let switch_func = switch_func.unwrap();
    assert!(switch_func.slices.is_some());
    let slices = switch_func.slices.as_ref().unwrap();
    assert!(slices.blocks.len() > 5);
    Ok(())
}
