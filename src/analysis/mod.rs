use std::{collections::BTreeSet, num::NonZeroU32};

use anyhow::{anyhow, bail, ensure, Context, Result};
use powerpc::{Extensions, Ins};

use crate::{
    analysis::{cfa::SectionAddress, vm::JumpTableType},
    array_ref,
    obj::{
        ObjInfo, ObjKind, ObjRelocKind, ObjSection, ObjSectionKind, ObjSymbolKind, SectionIndex,
    },
};

pub mod cfa;
pub mod cfa_tests;
pub mod executor;
pub mod objects;
pub mod pass;
pub mod signatures;
pub mod slices;
pub mod tracker;
pub mod vm;

pub fn disassemble(section: &ObjSection, address: u32) -> Option<Ins> {
    read_u32(section, address).map(|v| Ins::new(v, Extensions::xenon()))
}

pub fn read_u32(section: &ObjSection, address: u32) -> Option<u32> {
    let offset = (address as u64 - section.address) as usize;
    if section.data.len() < offset + 4 {
        return None;
    }
    Some(u32::from_be_bytes(*array_ref!(section.data, offset, 4)))
}

fn read_unresolved_relocation_address(
    obj: &ObjInfo,
    section: &ObjSection,
    address: u32,
    reloc_kind: Option<ObjRelocKind>,
) -> Result<Option<RelocationTarget>> {
    if let Some(reloc) = obj.unresolved_relocations.iter().find(|reloc| {
        reloc.section as SectionIndex == section.elf_index && reloc.address == address
    }) {
        if reloc.module_id != obj.module_id {
            return Ok(Some(RelocationTarget::External));
        }
        if let Some(reloc_kind) = reloc_kind {
            ensure!(reloc.kind == reloc_kind);
        }
        let (target_section_index, target_section) =
            obj.sections.get_elf_index(reloc.target_section as SectionIndex).ok_or_else(|| {
                anyhow!(
                    "Failed to find target section {} for unresolved relocation",
                    reloc.target_section
                )
            })?;
        Ok(Some(RelocationTarget::Address(SectionAddress {
            section: target_section_index,
            address: target_section.address as u32 + reloc.addend,
        })))
    } else {
        Ok(None)
    }
}

fn read_relocation_address(
    obj: &ObjInfo,
    section: &ObjSection,
    address: u32,
    reloc_kind: Option<ObjRelocKind>,
) -> Result<Option<RelocationTarget>> {
    let Some(reloc) = section.relocations.at(address) else {
        return Ok(None);
    };
    if let Some(reloc_kind) = reloc_kind {
        ensure!(reloc.kind == reloc_kind);
    }
    let symbol = &obj.symbols[reloc.target_symbol];
    let Some(section_index) = symbol.section else {
        return Ok(Some(RelocationTarget::External));
    };
    Ok(Some(RelocationTarget::Address(SectionAddress {
        section: section_index,
        address: (symbol.address as i64 + reloc.addend) as u32,
    })))
}

pub fn read_address(obj: &ObjInfo, section: &ObjSection, address: u32) -> Result<SectionAddress> {
    if obj.kind == ObjKind::Relocatable {
        let mut opt = read_relocation_address(obj, section, address, Some(ObjRelocKind::Absolute))?;
        if opt.is_none() {
            opt = read_unresolved_relocation_address(
                obj,
                section,
                address,
                Some(ObjRelocKind::Absolute),
            )?;
        }
        opt.and_then(|t| match t {
            RelocationTarget::Address(addr) => Some(addr),
            RelocationTarget::External => None,
        })
        .with_context(|| {
            format!("Failed to find relocation for {:#010X} in section {}", address, section.name)
        })
    } else {
        let offset = (address as u64 - section.address) as usize;
        let address = u32::from_be_bytes(*array_ref!(section.data, offset, 4));
        let (section_index, _) = obj.sections.at_address(address)?;
        Ok(SectionAddress::new(section_index, address))
    }
}

fn is_valid_jump_table_addr(
    obj: &ObjInfo,
    addr: SectionAddress,
    jump_table_type: JumpTableType,
) -> bool {
    match jump_table_type {
        // Absolute jump tables are typically in .text, but Xbox 360 compiler
        // places them in .rdata (ReadOnlyData) instead
        JumpTableType::Absolute => {
            let kind = obj.sections[addr.section].kind;
            matches!(kind, ObjSectionKind::Code | ObjSectionKind::ReadOnlyData)
        }
        // else, addr must not be in code or bss
        JumpTableType::RelativeBytes(_)
        | JumpTableType::RelativeBytesTimes4(_)
        | JumpTableType::RelativeShorts(_)
        | JumpTableType::RelativeShortsTimes2(_) => {
            !matches!(obj.sections[addr.section].kind, ObjSectionKind::Code | ObjSectionKind::Bss)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationTarget {
    Address(SectionAddress),
    External,
}

#[inline(never)]
pub fn relocation_target_for(
    obj: &ObjInfo,
    addr: SectionAddress,
    reloc_kind: Option<ObjRelocKind>,
) -> Result<Option<RelocationTarget>> {
    let section = &obj.sections[addr.section];
    let mut opt = read_relocation_address(obj, section, addr.address, reloc_kind)?;
    if opt.is_none() {
        opt = read_unresolved_relocation_address(obj, section, addr.address, reloc_kind)?;
    }
    Ok(opt)
}

fn get_jump_table_entries(
    obj: &ObjInfo,
    addr: SectionAddress, // the address the jump table is at
    jump_table_type: JumpTableType,
    size: Option<NonZeroU32>,
    from: SectionAddress, // the address of the bctr that uses the jump table
    function_start: SectionAddress,
    function_end: Option<SectionAddress>,
) -> Result<(Vec<SectionAddress>, u32)> {
    assert!(!matches!(jump_table_type, JumpTableType::RelativeShortsTimes2(_)),
            "Somehow, we found a jump table type lhzx that needs its offsets multiplied at addr {} from {}", addr, from);

    let section = &obj.sections[addr.section];
    // Check for an existing symbol with a known size, and use that if available.
    // Allows overriding jump table size analysis.
    let known_size = obj
        .symbols
        .kind_at_section_address(addr.section, addr.address, ObjSymbolKind::Object)
        .ok()
        .flatten()
        .and_then(|(_, s)| if s.size_known { NonZeroU32::new(s.size as u32) } else { None });

    if let Some(size) = known_size.or(size).map(|n| n.get()) {
        let num_entries = match jump_table_type {
            JumpTableType::Absolute => size / 4,
            JumpTableType::RelativeBytes(_) | JumpTableType::RelativeBytesTimes4(_) => size,
            JumpTableType::RelativeShorts(_) | JumpTableType::RelativeShortsTimes2(_) => size / 2,
        };
        log::debug!(
            "Located jump table @ {:#010X} with entry count {} (from {:#010X})",
            addr,
            num_entries,
            from
        );
        let mut entries = Vec::with_capacity(num_entries as usize);
        let mut data = section.data_range(addr.address, addr.address + size)?;
        let relative_addr = match jump_table_type {
            JumpTableType::Absolute => None,
            JumpTableType::RelativeBytes(addr)
            | JumpTableType::RelativeBytesTimes4(addr)
            | JumpTableType::RelativeShorts(addr)
            | JumpTableType::RelativeShortsTimes2(addr) => {
                match addr.context("No relative address to apply jump table offsets to!")? {
                    RelocationTarget::Address(addr) => Some(addr),
                    _ => bail!("No relative address to apply jump table offsets to! (RelocationTarget is type External)"),
                }
            }
        };
        let mut cur_addr = addr; // cur_addr == the address of the current jump table entry we're analyzing
        let increment = match jump_table_type {
            JumpTableType::Absolute => 4,
            JumpTableType::RelativeBytes(_) | JumpTableType::RelativeBytesTimes4(_) => 1,
            JumpTableType::RelativeShorts(_) | JumpTableType::RelativeShortsTimes2(_) => 2,
        };
        loop {
            if data.is_empty() {
                break;
            }
            let reloc_address = match jump_table_type {
                JumpTableType::Absolute => cur_addr,
                JumpTableType::RelativeBytes(_) => relative_addr.unwrap() + data[0] as u32,
                JumpTableType::RelativeBytesTimes4(_) => {
                    relative_addr.unwrap() + (data[0] as u32 * 4)
                }
                JumpTableType::RelativeShorts(_) => {
                    relative_addr.unwrap() + u16::from_be_bytes(*array_ref!(data, 0, 2)) as u32
                }
                JumpTableType::RelativeShortsTimes2(_) => {
                    relative_addr.unwrap()
                        + (u16::from_be_bytes(*array_ref!(data, 0, 2)) as u32 * 2)
                }
            };
            if let Some(target) =
                relocation_target_for(obj, reloc_address, Some(ObjRelocKind::Absolute))?
            {
                match target {
                    RelocationTarget::Address(addr) => entries.push(addr),
                    RelocationTarget::External => {
                        bail!("Jump table entry at {:#010X} points to external symbol", cur_addr)
                    }
                }
            } else {
                let entry_addr = match jump_table_type {
                    JumpTableType::Absolute => u32::from_be_bytes(*array_ref!(data, 0, 4)),
                    JumpTableType::RelativeBytes(_)
                    | JumpTableType::RelativeBytesTimes4(_)
                    | JumpTableType::RelativeShorts(_)
                    | JumpTableType::RelativeShortsTimes2(_) => reloc_address.address,
                };
                if entry_addr > 0 {
                    let Ok((section_index, _)) = obj.sections.at_address(entry_addr) else {
                        // End of actual table - VM may have over-estimated size
                        log::debug!(
                            "Jump table ended early: entry {:#010X} at {:#010X} not in any section",
                            entry_addr, cur_addr
                        );
                        break;
                    };
                    entries.push(SectionAddress::new(section_index, entry_addr));
                }
            }
            data = &data[increment..];
            cur_addr += increment as u32;
        }
        // Return actual bytes read, not VM-estimated size (which may be larger)
        let actual_size = cur_addr.address - addr.address;
        Ok((entries, actual_size))
    }
    // FIXME: this guessing routine only works for absolute jump tables
    // make one for relative jump tables!
    else {
        let mut entries = Vec::new();
        let mut cur_addr = addr;
        loop {
            let target = if let Some(target) =
                relocation_target_for(obj, cur_addr, Some(ObjRelocKind::Absolute))?
            {
                match target {
                    RelocationTarget::Address(addr) => addr,
                    RelocationTarget::External => break,
                }
            } else if obj.kind == ObjKind::Executable {
                let Some(value) = read_u32(section, cur_addr.address) else {
                    break;
                };
                let Ok((section_index, _)) = obj.sections.at_address(value) else {
                    break;
                };
                SectionAddress::new(section_index, value)
            } else {
                break;
            };
            if target < function_start || matches!(function_end, Some(end) if target >= end) {
                break;
            }
            entries.push(target);
            cur_addr += 4;
        }
        let size = cur_addr.address - addr.address;
        log::info!(
            "Guessed jump table @ {:#010X} with entry count {} (from {:#010X})",
            addr,
            size / 4,
            from
        );
        Ok((entries, size))
    }
}

pub fn uniq_jump_table_entries(
    obj: &ObjInfo,
    addr: SectionAddress, // the address the jump table is at
    jump_table_type: JumpTableType,
    size: Option<NonZeroU32>,
    from: SectionAddress, // the address of the bctr that uses the jump table
    function_start: SectionAddress,
    function_end: Option<SectionAddress>,
) -> Result<(BTreeSet<SectionAddress>, u32)> {
    if !is_valid_jump_table_addr(obj, addr, jump_table_type) {
        return Ok((BTreeSet::new(), 0));
    }
    let (entries, size) = get_jump_table_entries(
        obj,
        addr,
        jump_table_type,
        size,
        from,
        function_start,
        function_end,
    )
    .with_context(|| format!("While fetching jump table entries starting at {addr:#010X}"))?;
    Ok((BTreeSet::from_iter(entries.iter().cloned()), size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::vm::JumpTableType;
    use crate::obj::{ObjArchitecture, ObjInfo, ObjKind, ObjRelocations,
                     ObjSection, ObjSectionKind, ObjSplits};
    use std::num::NonZeroU32;

    fn make_test_section(name: &str, kind: ObjSectionKind, address: u64, data: Vec<u8>) -> ObjSection {
        ObjSection {
            name: name.to_string(),
            kind,
            address,
            size: data.len() as u64,
            data,
            align: 4,
            elf_index: 0,
            relocations: ObjRelocations::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: ObjSplits::default(),
        }
    }

    fn make_test_obj(sections: Vec<ObjSection>) -> ObjInfo {
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "test".to_string(),
            vec![],
            sections,
        )
    }

    /// Regression test: jump table with invalid entry should break, not error.
    /// Reproduces Minecraft tu2.xex crash where VM over-estimates table size.
    #[test]
    fn test_jump_table_breaks_on_invalid_entry() {
        let mut code_data = vec![0u8; 0x100];
        code_data[0x50..0x54].copy_from_slice(&0x80000010u32.to_be_bytes()); // valid
        code_data[0x54..0x58].copy_from_slice(&0x80000020u32.to_be_bytes()); // valid
        code_data[0x58..0x5C].copy_from_slice(&0x90000000u32.to_be_bytes()); // INVALID - outside section
        code_data[0x5C..0x60].copy_from_slice(&0x80000030u32.to_be_bytes()); // never reached

        let text_section = make_test_section(
            ".text", ObjSectionKind::Code, 0x80000000, code_data,
        );

        let obj = make_test_obj(vec![text_section]);

        let result = uniq_jump_table_entries(
            &obj,
            SectionAddress::new(0, 0x80000050),
            JumpTableType::Absolute,
            NonZeroU32::new(16),
            SectionAddress::new(0, 0x80000080),
            SectionAddress::new(0, 0x80000000),
            Some(SectionAddress::new(0, 0x80000100)),
        );

        assert!(result.is_ok(), "Should break gracefully, not error");
        let (entries, size) = result.unwrap();
        assert!(entries.len() <= 2, "Should stop at invalid entry");
        // Verify size is actual bytes read (2 entries * 4 bytes = 8), not VM estimate (16)
        assert_eq!(size, 8, "Should return actual bytes read, not VM estimate");
    }

    /// Test that external jump tables (not immediately after bctr) don't inflate function bounds.
    #[test]
    fn test_external_jump_table_size_returned_correctly() {
        // Build code section: code at start, jump table at a different location
        // Function at 0x80000000-0x80000040
        // Jump table at 0x80000080 (external, not inline)
        let mut code_data = vec![0u8; 0x100];
        // Jump table entries at offset 0x80 (address 0x80000080)
        code_data[0x80..0x84].copy_from_slice(&0x80000010u32.to_be_bytes()); // valid
        code_data[0x84..0x88].copy_from_slice(&0x80000020u32.to_be_bytes()); // valid
        code_data[0x88..0x8C].copy_from_slice(&0xFFFFFFFFu32.to_be_bytes()); // INVALID

        let text_section = make_test_section(
            ".text", ObjSectionKind::Code, 0x80000000, code_data,
        );

        let obj = make_test_obj(vec![text_section]);

        // bctr at 0x80000030, jump table at 0x80000080 (not inline - not at bctr+4)
        let result = uniq_jump_table_entries(
            &obj,
            SectionAddress::new(0, 0x80000080), // external jump table
            JumpTableType::Absolute,
            NonZeroU32::new(12),  // 3 entries claimed but only 2 valid
            SectionAddress::new(0, 0x80000030), // bctr address
            SectionAddress::new(0, 0x80000000), // function start
            Some(SectionAddress::new(0, 0x80000100)), // function end
        );

        assert!(result.is_ok());
        let (entries, size) = result.unwrap();
        assert_eq!(entries.len(), 2, "Should have 2 valid entries");
        assert_eq!(size, 8, "Should return actual bytes read (2*4=8), not VM estimate (12)");
    }

    /// Verify valid jump tables still work after fix.
    #[test]
    fn test_jump_table_valid_entries_work() {
        let mut code_data = vec![0u8; 0x100];
        code_data[0x50..0x54].copy_from_slice(&0x80000010u32.to_be_bytes());
        code_data[0x54..0x58].copy_from_slice(&0x80000020u32.to_be_bytes());
        code_data[0x58..0x5C].copy_from_slice(&0x80000030u32.to_be_bytes());

        let text_section = make_test_section(
            ".text", ObjSectionKind::Code, 0x80000000, code_data,
        );

        let obj = make_test_obj(vec![text_section]);

        let result = uniq_jump_table_entries(
            &obj,
            SectionAddress::new(0, 0x80000050),
            JumpTableType::Absolute,
            NonZeroU32::new(12),
            SectionAddress::new(0, 0x80000080),
            SectionAddress::new(0, 0x80000000),
            Some(SectionAddress::new(0, 0x80000100)),
        );

        assert!(result.is_ok());
        let (entries, size) = result.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(size, 12);
    }

    /// Test that absolute jump tables in ReadOnlyData sections work (Xbox 360 pattern).
    /// Xbox compiler places jump tables in .rdata instead of inline in .text.
    #[test]
    fn test_jump_table_in_rdata_section() {
        // Build code section (section 0): 0x80000000-0x800000FF
        let code_data = vec![0u8; 0x100];
        let text_section = make_test_section(
            ".text", ObjSectionKind::Code, 0x80000000, code_data,
        );

        // Build rdata section (section 1): 0x82000000-0x820000FF
        // Jump table at 0x82000050 with entries pointing back to .text
        let mut rdata_data = vec![0u8; 0x100];
        rdata_data[0x50..0x54].copy_from_slice(&0x80000010u32.to_be_bytes()); // points to .text
        rdata_data[0x54..0x58].copy_from_slice(&0x80000020u32.to_be_bytes()); // points to .text
        rdata_data[0x58..0x5C].copy_from_slice(&0x80000030u32.to_be_bytes()); // points to .text
        let rdata_section = make_test_section(
            ".rdata", ObjSectionKind::ReadOnlyData, 0x82000000, rdata_data,
        );

        let obj = make_test_obj(vec![text_section, rdata_section]);

        // Jump table is in section 1 (.rdata) at address 0x82000050
        // bctr is in section 0 (.text) at address 0x80000080
        // Function spans 0x80000000-0x80000100 in .text
        let result = uniq_jump_table_entries(
            &obj,
            SectionAddress::new(1, 0x82000050), // jump table in rdata section
            JumpTableType::Absolute,
            NonZeroU32::new(12),  // 3 entries
            SectionAddress::new(0, 0x80000080), // bctr in code section
            SectionAddress::new(0, 0x80000000), // function start in code
            Some(SectionAddress::new(0, 0x80000100)), // function end in code
        );

        assert!(result.is_ok(), "Jump table in .rdata should be valid");
        let (entries, size) = result.unwrap();
        assert_eq!(entries.len(), 3, "Should have 3 valid entries pointing to .text");
        assert_eq!(size, 12, "Should return correct size (3 entries * 4 bytes)");

        // Verify entries point to the correct addresses in the code section
        assert!(entries.contains(&SectionAddress::new(0, 0x80000010)));
        assert!(entries.contains(&SectionAddress::new(0, 0x80000020)));
        assert!(entries.contains(&SectionAddress::new(0, 0x80000030)));
    }

    /// Test that is_valid_jump_table_addr correctly rejects invalid section types.
    #[test]
    fn test_is_valid_jump_table_addr_rejects_bss() {
        let bss_section = make_test_section(
            ".bss", ObjSectionKind::Bss, 0x80000000, vec![],
        );
        let obj = make_test_obj(vec![bss_section]);

        // BSS sections should be rejected for absolute jump tables
        let addr = SectionAddress::new(0, 0x80000000);
        assert!(!is_valid_jump_table_addr(&obj, addr, JumpTableType::Absolute));
    }

    /// Test that is_valid_jump_table_addr accepts Code sections (original behavior).
    #[test]
    fn test_is_valid_jump_table_addr_accepts_code() {
        let code_section = make_test_section(
            ".text", ObjSectionKind::Code, 0x80000000, vec![0u8; 0x100],
        );
        let obj = make_test_obj(vec![code_section]);

        let addr = SectionAddress::new(0, 0x80000000);
        assert!(is_valid_jump_table_addr(&obj, addr, JumpTableType::Absolute));
    }

    /// Test that is_valid_jump_table_addr accepts ReadOnlyData sections (new behavior).
    #[test]
    fn test_is_valid_jump_table_addr_accepts_rdata() {
        let rdata_section = make_test_section(
            ".rdata", ObjSectionKind::ReadOnlyData, 0x82000000, vec![0u8; 0x100],
        );
        let obj = make_test_obj(vec![rdata_section]);

        let addr = SectionAddress::new(0, 0x82000000);
        assert!(is_valid_jump_table_addr(&obj, addr, JumpTableType::Absolute));
    }
}
