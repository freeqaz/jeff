use std::fs::File;

use anyhow::Result;
use serde::{de::Error, Deserialize, Deserializer};

use std::collections::BTreeMap;

use super::*;
use crate::{
    analysis::cfa::{CfaConfig, FunctionInfo, SectionAddress, process_function_at},
    obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind},
};

fn bytestr_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
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
where
    D: Deserializer<'de>,
{
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    let start_addr = SectionAddress::new(0, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
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

// Absolute general skeleton:
// lis r12, <jump_table_addr-hi>
// addi r12, r12, <jump_table_addr-lo>
// rlwinm r0, rX, 0x2, 0x0, 0x1d
// lwzx r0, r12, r0
// mtctr r0
// bctr
// <jump_table_addr>

// Relative bytes (no rlwinm) general skeleton:
// cmplwi crN, rX, <limit>
// bgt crN, default
// lis r12, <jump_table_addr-hi>
// addi r12, r12, <jump_table_addr-lo>
// lbzx r0, r12, rX
// slwi r0, r0, 0x2
// lis r12, <start_of_the_cases-hi>
// nop
// addi r12, r12, <start_of_the_cases-lo>
// add r12, r12, r0
// mtctr r12
// bctr
// <start_of_the_cases>
// ...
// <default>

// Relative bytes (no rlwinm) alternate skeleton:
// cmplwi crN, rX, <limit>
// bgt crN, default
// lis r12, <jump_table_addr-hi>
// addi r12, r12, <jump_table_addr-lo>
// lbzx r0, r12, rX
// lis r12, <start_of_the_cases-hi>
// addi r12, r12, <start_of_the_cases-lo>
// add r12, r12, r0
// mtctr r12
// nop
// nop
// bctr
// <start_of_the_cases>
// ...
// <default>

// Relative bytes (rlwinm after lbzx) skeleton:
// cmplwi crN, rX, <limit>
// bgt crN, default
// lis r12, <jump_table_addr-hi>
// addi r12, r12, <jump_table_addr-lo>
// lbzx r0, r12, rX
// rlwinm r0, r0, 0x2, 0x0, 0x1d
// lis r12, <start_of_the_cases-hi>
// nop
// addi r12, r12, <start_of_the_cases-lo>
// add r12, r12, r0
// mtctr r12
// bctr
// <start_of_the_cases>
// ...
// <default>

// Relative shorts (rlwinm before lhzx) skeleton:
// cmplwi crN, rX, <limit>
// bgt crN, default
// lis r12, <jump_table_addr-hi>
// addi r12, r12, <jump_table_addr-lo>
// rlwinm r0, rX, 0x1, 0x0, 0x1e
// lhzx r0, r12, r0
// lis r12, <start_of_the_cases-hi>
// addi r12, r12, <start_of_the_cases-lo>
// add r12, r12, r0
// mtctr r12
// nop
// bctr
// <start_of_the_cases>
// ...
// <default>

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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    let start_addr = SectionAddress::new(0, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    // 16 bytes (4 entries)
    let jump_table_entry = jump_tables.get(&SectionAddress::new(0, 0x820869fc));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 16);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 12);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    let start_addr = SectionAddress::new(0, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    // 16 bytes (4 entries)
    let jump_table_entry = jump_tables.get(&SectionAddress::new(0, 0x827f9434));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 16);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 12);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    let start_addr = SectionAddress::new(0, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    // 16 bytes (4 entries)
    let jump_table_entry = jump_tables.get(&SectionAddress::new(0, 0x82fbb464));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 16);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 11);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 105);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 50);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 0x1c);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 55);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 11);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 58);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 12);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 71);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 12);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 76);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 10);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 55);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 0x15);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 43);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 28);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 57);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    // 94 bytes = 47 entries (cmplwi r28, 46 → 0..46 inclusive)
    assert_eq!(*jump_table_entry.unwrap(), 94);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 100);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 128);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 134);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 16);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 172);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 20);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 201);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 0x38);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 92);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 60);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 99);
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    // section 1 is .text now that we have a relative jump table in .rdata
    let start_addr = SectionAddress::new(1, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    let jump_table_entry =
        jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 20);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 135);
    Ok(())
}

// this one has an absolute jump table,
// except different registers are used when rlwinm'ing - it stores R4 to 0x50(R1), and then loads from 0x50(R1) into R3, and R3 is then used to index.
// to get this to pass, we need some sort of mechanism that keeps track of what's in the stack at any given time
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
    let config = CfaConfig::default();
    let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
    let mut jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();
    let start_addr = SectionAddress::new(0, cur_test.function_start);
    // CFA completed with no errors
    let res = process_function_at(&obj, &config, &mut functions, &mut jump_tables, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
    // we have one more function
    assert!(res);
    assert_eq!(functions.len(), 1);
    let func = functions.get(&start_addr);
    assert!(func.is_some());
    let func = func.unwrap();
    assert!(func.is_function());
    // does the detected function end match our expected end?
    assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
    // for this func, we should have 1 jump table
    assert_eq!(jump_tables.is_empty(), false);
    assert_eq!(jump_tables.len(), 1);
    // 0x5A4 bytes = 0x169 entries × 4 bytes/entry (Absolute)
    let jump_table_entry = jump_tables.get(&SectionAddress::new(0, 0x82185be8));
    assert!(jump_table_entry.is_some());
    assert_eq!(*jump_table_entry.unwrap(), 0x5A4);
    assert!(func.slices.is_some());
    let slices = func.slices.as_ref().unwrap();
    assert_eq!(slices.blocks.len(), 189);
    Ok(())
}
