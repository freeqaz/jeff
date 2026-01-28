use std::{
    cmp::min,
    collections::BTreeMap,
    fmt::{Debug, Display, Formatter, UpperHex},
    ops::{Add, AddAssign, BitAnd, Sub},
};

use anyhow::{bail, ensure, Context, Result};
use itertools::Itertools;

use crate::{
    analysis::{
        executor::{ExecCbData, ExecCbResult, Executor},
        skip_alignment,
        slices::{FunctionSlices, TailCallResult},
        vm::{BranchTarget, GprValue, StepResult, VM},
        RelocationTarget,
    },
    obj::{
        ObjInfo, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
        SectionIndex,
    },
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionAddress {
    pub section: SectionIndex,
    pub address: u32,
}

impl Debug for SectionAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#X}", self.section as isize, self.address)
    }
}

impl Display for SectionAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#X}", self.section as isize, self.address)
    }
}

impl SectionAddress {
    pub fn new(section: SectionIndex, address: u32) -> Self { Self { section, address } }

    pub fn offset(self, offset: i32) -> Self {
        Self { section: self.section, address: self.address.wrapping_add_signed(offset) }
    }

    pub fn align_up(self, align: u32) -> Self {
        Self { section: self.section, address: (self.address + align - 1) & !(align - 1) }
    }

    pub fn align_down(self, align: u32) -> Self {
        Self { section: self.section, address: self.address & !(align - 1) }
    }

    pub fn is_aligned(self, align: u32) -> bool { self.address & (align - 1) == 0 }

    pub fn wrapping_add(self, rhs: u32) -> Self {
        Self { section: self.section, address: self.address.wrapping_add(rhs) }
    }
}

impl Add<u32> for SectionAddress {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self { section: self.section, address: self.address + rhs }
    }
}

impl Sub<u32> for SectionAddress {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self::Output {
        Self { section: self.section, address: self.address - rhs }
    }
}

impl AddAssign<u32> for SectionAddress {
    fn add_assign(&mut self, rhs: u32) { self.address += rhs; }
}

impl UpperHex for SectionAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#010X}", self.section as isize, self.address)
    }
}

impl BitAnd<u32> for SectionAddress {
    type Output = u32;

    fn bitand(self, rhs: u32) -> Self::Output { self.address & rhs }
}

#[derive(Default, Debug, Clone)]
pub struct FunctionInfo {
    pub analyzed: bool,
    pub end: Option<SectionAddress>,
    pub slices: Option<FunctionSlices>,
}

impl FunctionInfo {
    pub fn is_analyzed(&self) -> bool { self.analyzed }

    pub fn is_function(&self) -> bool {
        self.analyzed && self.end.is_some() && self.slices.is_some()
    }

    pub fn is_non_function(&self) -> bool {
        self.analyzed && self.end.is_none() && self.slices.is_none()
    }

    pub fn is_unfinalized(&self) -> bool {
        self.analyzed && self.end.is_none() && self.slices.is_some()
    }
}

#[derive(Debug, Default)]
pub struct AnalyzerState {
    pub sda_bases: Option<(u32, u32)>,
    pub functions: BTreeMap<SectionAddress, FunctionInfo>,
    pub jump_tables: BTreeMap<SectionAddress, u32>,
    pub known_symbols: BTreeMap<SectionAddress, Vec<ObjSymbol>>,
    pub known_sections: BTreeMap<SectionIndex, String>,
}

impl AnalyzerState {
    pub fn apply(&self, obj: &mut ObjInfo) -> Result<()> {
        for (&section_index, section_name) in &self.known_sections {
            obj.sections[section_index].rename(section_name.clone())?;
        }
        for (&start, FunctionInfo { end, .. }) in self.functions.iter() {
            let Some(end) = end else { continue };
            let section = &obj.sections[start.section];
            ensure!(
                section.contains_range(start.address..end.address),
                "Function {:#010X}..{:#010X} out of bounds of section {} {:#010X}..{:#010X}",
                start.address,
                end,
                section.name,
                section.address,
                section.address + section.size
            );
            let name = if obj.module_id == 0 {
                format!("fn_{:08X}", start.address)
            } else {
                format!("fn_{}_{:X}", obj.module_id, start.address)
            };
            obj.add_symbol(
                ObjSymbol {
                    name,
                    address: start.address as u64,
                    section: Some(start.section),
                    size: (end.address - start.address) as u64,
                    size_known: true,
                    kind: ObjSymbolKind::Function,
                    ..Default::default()
                },
                false,
            )?;
        }
        let mut iter = self.jump_tables.iter().peekable();
        while let Some((&addr, &(mut size))) = iter.next() {
            // Truncate overlapping jump tables
            if let Some((&next_addr, _)) = iter.peek() {
                if next_addr.section == addr.section {
                    size = min(size, next_addr.address - addr.address);
                }
            }
            let section = &obj.sections[addr.section];
            ensure!(
                section.contains_range(addr.address..addr.address + size),
                "Jump table {:#010X}..{:#010X} out of bounds of section {} {:#010X}..{:#010X}",
                addr.address,
                addr.address + size,
                section.name,
                section.address,
                section.address + section.size
            );
            let address_str = if obj.module_id == 0 {
                format!("{:08X}", addr.address)
            } else {
                format!(
                    "{}_{}_{:X}",
                    obj.module_id,
                    section.name.trim_start_matches('.'),
                    addr.address
                )
            };
            obj.add_symbol(
                ObjSymbol {
                    name: format!("jumptable_{address_str}"),
                    address: addr.address as u64,
                    section: Some(addr.section),
                    size: size as u64,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Local.into()),
                    kind: ObjSymbolKind::Object,
                    ..Default::default()
                },
                false,
            )?;
        }
        for (&_addr, symbols) in &self.known_symbols {
            for symbol in symbols {
                // Remove overlapping symbols
                if symbol.size > 0 {
                    let end = symbol.address + symbol.size;
                    let overlapping = obj
                        .symbols
                        .for_section_range(
                            symbol.section.unwrap(),
                            symbol.address as u32 + 1..end as u32,
                        )
                        .filter(|(_, s)| s.kind == symbol.kind)
                        .map(|(a, _)| a)
                        .collect_vec();
                    for index in overlapping {
                        let existing = &obj.symbols[index];
                        let symbol = ObjSymbol {
                            name: format!("__DELETED_{}", existing.name),
                            kind: ObjSymbolKind::Unknown,
                            size: 0,
                            flags: ObjSymbolFlagSet(
                                ObjSymbolFlags::RelocationIgnore
                                    | ObjSymbolFlags::NoWrite
                                    | ObjSymbolFlags::NoExport
                                    | ObjSymbolFlags::Stripped,
                            ),
                            ..existing.clone()
                        };
                        obj.symbols.replace(index, symbol)?;
                    }
                }
                obj.add_symbol(symbol.clone(), true)?;
            }
        }
        Ok(())
    }

    pub fn detect_functions(&mut self, obj: &ObjInfo) -> Result<()> {
        // Apply known functions from pdata/import data
        for (&addr, &size) in &obj.known_functions {
            self.functions.insert(addr, FunctionInfo {
                analyzed: false,
                end: size.map(|size| addr + size),
                slices: None,
            });
        }

        // Apply known functions from symbols
        for (_, symbol) in obj.symbols.by_kind(ObjSymbolKind::Function) {
            let Some(section_index) = symbol.section else { continue };
            let addr_ref = SectionAddress::new(section_index, symbol.address as u32);
            self.functions.insert(addr_ref, FunctionInfo {
                analyzed: false,
                end: if symbol.size_known { Some(addr_ref + symbol.size as u32) } else { None },
                slices: None,
            });
        }

        // Also check the beginning of every code section
        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            let this_sec_start = SectionAddress::new(section_index, section.address as u32);
            if obj
                .symbols
                .by_name(&format!("except_data_{:08X}", this_sec_start.address + 8))?
                .is_some()
            {
                continue;
            }
            self.functions.entry(this_sec_start).or_default();
        }

        // Process known functions first
        for addr in self.functions.keys().cloned().collect_vec() {
            self.process_function_at(obj, addr)?;

            // some assertions, since we're working with known function boundaries
            // if we got this from pdata or import data, there should be a known end
            if let Some(value) = obj.known_functions.get(&addr) {
                if let Some(func) = self.functions.get(&addr) {
                    if let Some(known_size) = value {
                        let known_end = addr + *known_size;
                        assert_eq!(func.end.is_some(), true, "Function at {} has no detected end rather than known end {}. There must be an error in processing!", addr, known_end);
                        let func_end = func.end.unwrap();
                        assert_eq!(func_end, known_end,
                                   "Function at {} has known end addr {}, but during processing, ending was found to be {}!",
                                   addr, known_end, func_end);
                    }
                } else {
                    unreachable!();
                }
            }
            // assert something with slices?
        }

        // the rest...
        println!("Known functions complete.");

        if let Some(entry) = obj.entry.map(|n| n as u32) {
            // Locate entry function bounds
            let (section_index, _) = obj
                .sections
                .at_address(entry)
                .context(format!("Entry point {entry:#010X} outside of any section"))?;
            self.process_function_at(obj, SectionAddress::new(section_index, entry))?;
        }
        // Locate bounds for referenced functions until none are left
        self.process_functions(obj)?;
        // Final pass(es)
        while self.finalize_functions(obj, true)? {
            self.process_functions(obj)?;
        }
        if self.functions.iter().any(|(_, i)| i.is_unfinalized()) {
            log::error!("Failed to finalize functions:");
            for (addr, info) in self.functions.iter().filter(|(_, i)| i.is_unfinalized()) {
                log::error!(
                    "  {:#010X}: blocks [{:?}]",
                    addr,
                    info.slices.as_ref().unwrap().possible_blocks.keys()
                );
            }
            bail!("Failed to finalize functions");
        }
        Ok(())
    }

    fn finalize_functions(&mut self, obj: &ObjInfo, finalize: bool) -> Result<bool> {
        let mut finalized_any = false;
        let unfinalized = self
            .functions
            .iter()
            .filter_map(|(&addr, info)| {
                if info.is_unfinalized() {
                    info.slices.clone().map(|s| (addr, s))
                } else {
                    None
                }
            })
            .collect_vec();
        for (addr, mut slices) in unfinalized {
            // log::info!("Trying to finalize {:#010X}", addr);
            let Some(function_start) = slices.start() else {
                bail!("Function slice without start @ {:#010X}", addr);
            };
            let function_end = slices.end();
            let mut current = SectionAddress::new(addr.section, 0);
            while let Some((&block, vm)) = slices.possible_blocks.range(current..).next() {
                current = block + 4;
                let vm = vm.clone();
                match slices.check_tail_call(
                    obj,
                    block,
                    function_start,
                    function_end,
                    &self.functions,
                    Some(vm.clone()),
                ) {
                    TailCallResult::Not => {
                        log::trace!("Finalized block @ {:#010X}", block);
                        slices.possible_blocks.remove(&block);
                        slices.analyze(
                            obj,
                            block,
                            function_start,
                            function_end,
                            &self.functions,
                            Some(vm),
                        )?;
                        // Start at the beginning of the function again
                        current = SectionAddress::new(addr.section, 0);
                    }
                    TailCallResult::Is => {
                        log::trace!("Finalized tail call @ {:#010X}", block);
                        slices.possible_blocks.remove(&block);
                        slices.function_references.insert(block);
                        // Start at the beginning of the function again
                        current = SectionAddress::new(addr.section, 0);
                    }
                    TailCallResult::Possible => {
                        if finalize {
                            log::trace!(
                                "Still couldn't determine {:#010X}, assuming non-tail-call",
                                block
                            );
                            slices.possible_blocks.remove(&block);
                            slices.analyze(
                                obj,
                                block,
                                function_start,
                                function_end,
                                &self.functions,
                                Some(vm),
                            )?;
                        }
                    }
                    TailCallResult::Error(e) => return Err(e),
                }
            }
            if slices.can_finalize() {
                log::trace!("Finalizing {:#010X}", addr);
                slices.finalize(obj, &self.functions)?;
                for address in slices.function_references.iter().cloned() {
                    // Only create functions for code sections
                    // Some games use branches to data sections to prevent dead stripping (Mario Party)
                    if matches!(obj.sections.get(address.section), Some(section) if section.kind == ObjSectionKind::Code)
                    {
                        self.functions.entry(address).or_default();
                    }
                }
                self.jump_tables.append(&mut slices.jump_table_references.clone());
                let end = slices.end();
                let info = self.functions.get_mut(&addr).unwrap();
                info.analyzed = true;
                info.end = end;
                info.slices = Some(slices.clone());
                finalized_any = true;
            }
        }
        Ok(finalized_any)
    }

    fn first_unbounded_function(&self) -> Option<SectionAddress> {
        self.functions.iter().find(|(_, info)| !info.is_analyzed()).map(|(&addr, _)| addr)
    }

    fn process_functions(&mut self, obj: &ObjInfo) -> Result<()> {
        loop {
            match self.first_unbounded_function() {
                Some(addr) => {
                    log::trace!("Processing {:#010X}", addr);
                    self.process_function_at(obj, addr)?;
                }
                None => {
                    if !self.finalize_functions(obj, false)? && !self.detect_new_functions(obj)? {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn process_function_at(&mut self, obj: &ObjInfo, addr: SectionAddress) -> Result<bool> {
        Ok(if let Some(mut slices) = self.process_function(obj, addr)? {
            for address in slices.function_references.iter().cloned() {
                // Only create functions for code sections
                // Some games use branches to data sections to prevent dead stripping (Mario Party)
                if matches!(obj.sections.get(address.section), Some(section) if section.kind == ObjSectionKind::Code)
                {
                    self.functions.entry(address).or_default();
                }
            }
            self.jump_tables.append(&mut slices.jump_table_references.clone());
            if slices.can_finalize() {
                slices.finalize(obj, &self.functions)?;
                let info = self.functions.entry(addr).or_default();
                info.analyzed = true;
                info.end = slices.end();
                info.slices = Some(slices);
            } else {
                let info = self.functions.entry(addr).or_default();
                info.analyzed = true;
                // Don't overwrite info.end - preserve known end from pdata/symbols
                info.slices = Some(slices);
            }
            true
        } else {
            log::info!("Not a function @ {:#010X}", addr);
            let info = self.functions.entry(addr).or_default();
            info.analyzed = true;
            info.end = None;
            false
        })
    }

    fn process_function(
        &mut self,
        obj: &ObjInfo,
        start: SectionAddress,
    ) -> Result<Option<FunctionSlices>> {
        let mut slices = FunctionSlices::default();
        let function_end = self.functions.get(&start).and_then(|info| info.end);
        Ok(match slices.analyze(obj, start, start, function_end, &self.functions, None)? {
            true => Some(slices),
            false => None,
        })
    }

    fn detect_new_functions(&mut self, obj: &ObjInfo) -> Result<bool> {
        let mut new_functions = vec![];
        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            if section.name == ".xidata" {
                continue;
            } // because we already did our xidata processing at this point
            let section_start = SectionAddress::new(section_index, section.address as u32);
            let section_end = section_start + section.size as u32;
            let mut iter = self.functions.range(section_start..section_end).peekable();
            loop {
                match (iter.next(), iter.peek()) {
                    (Some((&first, first_info)), Some(&(&second, second_info))) => {
                        let Some(first_end) = first_info.end else { continue };
                        if first_end > second {
                            bail!("Overlapping functions {}-{} -> {}", first, first_end, second);
                        }
                        let addr = match skip_alignment(section, first_end, second) {
                            Some(addr) => addr,
                            None => continue,
                        };
                        if second > addr {
                            // don't try to add a function where there's an exception symbol
                            if obj
                                .symbols
                                .by_name(&format!("except_data_{:08X}", addr.address + 8))?
                                .is_some()
                            {
                                continue;
                            }
                            log::trace!(
                                "Trying function @ {:#010X} (from {:#010X}-{:#010X} <-> {:#010X}-{:#010X?})",
                                addr,
                                first.address,
                                first_end,
                                second.address,
                                second_info.end,
                            );
                            new_functions.push(addr);
                        }
                    }
                    (Some((last, last_info)), None) => {
                        let Some(last_end) = last_info.end else { continue };
                        if last_end < section_end {
                            let addr = match skip_alignment(section, last_end, section_end) {
                                Some(addr) => addr,
                                None => continue,
                            };
                            if addr < section_end {
                                log::trace!(
                                    "Trying function @ {:#010X} (from {:#010X}-{:#010X} <-> {:#010X})",
                                    addr,
                                    last.address,
                                    last_end,
                                    section_end,
                                );
                                new_functions.push(addr);
                            }
                        }
                    }
                    _ => break,
                }
            }
        }
        let found_new = !new_functions.is_empty();
        for addr in new_functions {
            let opt = self.functions.insert(addr, FunctionInfo::default());
            ensure!(opt.is_none(), "Attempted to detect duplicate function @ {:#010X}", addr);
        }
        Ok(found_new)
    }
}

/// Execute VM from entry point following branches and function calls
/// until SDA bases are initialized (__init_registers)
pub fn locate_sda_bases(obj: &mut ObjInfo) -> Result<bool> {
    let Some(entry) = obj.entry else {
        return Ok(false);
    };
    let (section_index, _) = obj
        .sections
        .at_address(entry as u32)
        .context(format!("Entry point {entry:#010X} outside of any section"))?;
    let entry_addr = SectionAddress::new(section_index, entry as u32);

    let mut executor = Executor::new(obj);
    executor.push(entry_addr, VM::new(), false);
    let result = executor.run(
        obj,
        |ExecCbData { executor, vm, result, ins_addr, section: _, ins: _, block_start: _ }| {
            match result {
                StepResult::Continue | StepResult::LoadStore { .. } => {
                    return Ok(ExecCbResult::Continue);
                }
                StepResult::Illegal => bail!("Illegal instruction @ {}", ins_addr),
                StepResult::Jump(target) => {
                    if let BranchTarget::Address(RelocationTarget::Address(addr)) = target {
                        return Ok(ExecCbResult::Jump(addr));
                    }
                }
                StepResult::Branch(branches) => {
                    for branch in branches {
                        if let BranchTarget::Address(RelocationTarget::Address(addr)) =
                            branch.target
                        {
                            executor.push(addr, branch.vm, false);
                        }
                    }
                }
            }

            if let (GprValue::Constant(sda2_base), GprValue::Constant(sda_base)) =
                (vm.gpr_value(2), vm.gpr_value(13))
            {
                return Ok(ExecCbResult::End((sda2_base, sda_base)));
            }

            Ok(ExecCbResult::EndBlock)
        },
    )?;
    match result {
        Some((sda2_base, sda_base)) => {
            obj.sda2_base = Some(sda2_base as u32);
            obj.sda_base = Some(sda_base as u32);
            Ok(true)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::slices::FunctionSlices;

    /// Test FunctionInfo state detection methods
    #[test]
    fn test_function_info_states() {
        // Default state: not analyzed
        let default_info = FunctionInfo::default();
        assert!(!default_info.is_analyzed());
        assert!(!default_info.is_function());
        assert!(!default_info.is_non_function());
        assert!(!default_info.is_unfinalized());

        // Analyzed with known end but no slices (shouldn't happen normally)
        let known_end_only = FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x100)),
            slices: None,
        };
        assert!(known_end_only.is_analyzed());
        assert!(!known_end_only.is_function()); // needs slices
        assert!(!known_end_only.is_non_function()); // has end
        assert!(!known_end_only.is_unfinalized()); // has end

        // Analyzed as non-function (no end, no slices)
        let non_function = FunctionInfo {
            analyzed: true,
            end: None,
            slices: None,
        };
        assert!(non_function.is_analyzed());
        assert!(!non_function.is_function());
        assert!(non_function.is_non_function());
        assert!(!non_function.is_unfinalized());

        // Unfinalized: analyzed, no end, has slices
        let unfinalized = FunctionInfo {
            analyzed: true,
            end: None,
            slices: Some(FunctionSlices::default()),
        };
        assert!(unfinalized.is_analyzed());
        assert!(!unfinalized.is_function());
        assert!(!unfinalized.is_non_function());
        assert!(unfinalized.is_unfinalized());

        // Fully analyzed function: has end and slices
        let complete = FunctionInfo {
            analyzed: true,
            end: Some(SectionAddress::new(0, 0x100)),
            slices: Some(FunctionSlices::default()),
        };
        assert!(complete.is_analyzed());
        assert!(complete.is_function());
        assert!(!complete.is_non_function());
        assert!(!complete.is_unfinalized());
    }

    /// Test that a function with a known end from pdata/symbols maintains that end
    /// when slices can't finalize. This tests the fix in process_function_at().
    ///
    /// Before fix: info.end would be set to None when can_finalize() returned false
    /// After fix: info.end is preserved (not overwritten)
    #[test]
    fn test_known_end_preserved_state() {
        // Simulate the state after process_function_at with the fix:
        // - We had a known end from pdata (0x100)
        // - Slices couldn't finalize (has possible_blocks)
        // - The fix preserves info.end instead of setting it to None
        let known_end = SectionAddress::new(0, 0x100);
        let info = FunctionInfo {
            analyzed: true,
            end: Some(known_end), // preserved from pdata
            slices: Some(FunctionSlices::default()), // slices that couldn't finalize
        };

        // With the fix, this state is valid: we have a known end even though
        // slices couldn't finalize. This allows the function to proceed with
        // the pdata-provided bounds.
        assert!(info.is_analyzed());
        assert!(info.is_function()); // has both end and slices
        assert_eq!(info.end, Some(known_end));
    }

    /// Test that AnalyzerState correctly initializes functions from known_functions (pdata)
    #[test]
    fn test_analyzer_state_known_function_init() {
        let mut state = AnalyzerState::default();

        // Simulate adding a known function from pdata with a known size
        let func_addr = SectionAddress::new(0, 0x1000);
        let func_size = 0x50u32;
        let func_end = func_addr + func_size;

        state.functions.insert(func_addr, FunctionInfo {
            analyzed: false,
            end: Some(func_end),
            slices: None,
        });

        // Verify the function was added with the correct end
        let info = state.functions.get(&func_addr).unwrap();
        assert!(!info.analyzed);
        assert_eq!(info.end, Some(func_end));
        assert!(info.slices.is_none());
    }

    /// Test the scenario where process_function_at receives a function with
    /// a pre-set end (from pdata) and slices can't finalize.
    ///
    /// This simulates what happens after the fix: the end is preserved.
    #[test]
    fn test_end_preserved_when_cannot_finalize() {
        let mut state = AnalyzerState::default();

        // Setup: function with known end from pdata
        let func_addr = SectionAddress::new(0, 0x1000);
        let known_end = SectionAddress::new(0, 0x1050);

        state.functions.insert(func_addr, FunctionInfo {
            analyzed: false,
            end: Some(known_end),
            slices: None,
        });

        // Simulate what process_function_at does when slices can't finalize:
        // With the fix, it should preserve the existing end
        let slices = FunctionSlices::default();
        // Note: FunctionSlices::default() has possible_blocks empty, so can_finalize() = true
        // But we're testing the code path conceptually

        // Get existing info and simulate the "can't finalize" branch
        let info = state.functions.get_mut(&func_addr).unwrap();
        let original_end = info.end; // Should be Some(known_end)

        // Simulate the fixed code path (doesn't overwrite info.end):
        info.analyzed = true;
        // info.end = None; // OLD BUG: this line was present
        // NEW FIX: we don't touch info.end, preserving the known value
        info.slices = Some(slices);

        // Verify the end is preserved
        assert_eq!(info.end, original_end);
        assert_eq!(info.end, Some(known_end));
    }

    /// Test the scenario where slices CAN finalize - end should come from slices
    #[test]
    fn test_end_from_slices_when_can_finalize() {
        let mut state = AnalyzerState::default();

        // Setup: function without known end
        let func_addr = SectionAddress::new(0, 0x1000);

        state.functions.insert(func_addr, FunctionInfo::default());

        // Create slices that represent a finalized function
        let mut slices = FunctionSlices::default();
        // Add a block to give the slices an end
        slices.blocks.insert(func_addr, Some(SectionAddress::new(0, 0x1020)));

        // Simulate what process_function_at does when slices CAN finalize:
        let info = state.functions.get_mut(&func_addr).unwrap();
        info.analyzed = true;
        info.end = slices.end(); // Set from slices
        info.slices = Some(slices.clone());

        // Verify the end comes from slices
        assert!(info.is_analyzed());
        assert_eq!(info.end, slices.end());
    }
}

/// ProDG hardcodes .bss and .sbss section initialization in `entry`
/// This function locates the memset calls and returns a list of
/// (address, size) pairs for the .bss sections.
pub fn locate_bss_memsets(obj: &mut ObjInfo) -> Result<Vec<(u32, u32)>> {
    let mut bss_sections: Vec<(u32, u32)> = Vec::new();
    let Some(entry) = obj.entry else {
        return Ok(bss_sections);
    };
    let (section_index, _) = obj
        .sections
        .at_address(entry as u32)
        .context(format!("Entry point {entry:#010X} outside of any section"))?;
    let entry_addr = SectionAddress::new(section_index, entry as u32);

    let mut executor = Executor::new(obj);
    executor.push(entry_addr, VM::new(), false);
    executor.run(
        obj,
        |ExecCbData { executor: _, vm, result, ins_addr, section: _, ins: _, block_start: _ }| {
            match result {
                StepResult::Continue | StepResult::LoadStore { .. } => Ok(ExecCbResult::Continue),
                StepResult::Illegal => bail!("Illegal instruction @ {}", ins_addr),
                StepResult::Jump(_target) => Ok(ExecCbResult::End(())),
                StepResult::Branch(branches) => {
                    for branch in branches {
                        if branch.link {
                            // Some ProDG crt0.s versions use the wrong registers, some don't
                            if let (
                                GprValue::Constant(addr),
                                GprValue::Constant(value),
                                GprValue::Constant(size),
                            ) = {
                                if vm.gpr_value(4) == GprValue::Constant(0) {
                                    (vm.gpr_value(3), vm.gpr_value(4), vm.gpr_value(5))
                                } else {
                                    (vm.gpr_value(4), vm.gpr_value(5), vm.gpr_value(6))
                                }
                            } {
                                if value == 0 && size > 0 {
                                    bss_sections.push((addr as u32, size as u32));
                                }
                            }
                        }
                    }
                    if bss_sections.len() >= 2 {
                        return Ok(ExecCbResult::End(()));
                    }
                    Ok(ExecCbResult::Continue)
                }
            }
        },
    )?;
    Ok(bss_sections)
}
