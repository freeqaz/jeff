use std::{
    cmp::min,
    collections::BTreeMap,
    fmt::{Debug, Display, Formatter, UpperHex},
    ops::{Add, AddAssign, BitAnd, Sub},
};

use anyhow::{bail, ensure, Context, Result};
use itertools::Itertools;
use powerpc::Opcode;

use crate::{
    analysis::{
        disassemble,
        executor::{ExecCbData, ExecCbResult, Executor},
        skip_alignment,
        slices::{FunctionSlices, TailCallResult},
        vm::{BranchTarget, GprValue, StepResult, VM},
        RelocationTarget,
    },
    obj::{
        ObjInfo, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags,
        ObjSymbolKind, ObjSymbolScope, SectionIndex,
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
    /// Functions that were merged as tail blocks into their predecessors.
    /// These need to be removed from obj.symbols during apply().
    pub merged_tail_blocks: Vec<SectionAddress>,
    /// Functions whose ends were extended by absorbing tail blocks.
    /// These need their symbol size updated in apply().
    pub extended_functions: Vec<SectionAddress>,
}

impl AnalyzerState {
    pub fn apply(&self, obj: &mut ObjInfo) -> Result<()> {
        for (&section_index, section_name) in &self.known_sections {
            obj.sections[section_index].rename(section_name.clone())?;
        }
        // Remove symbols for functions that were merged as tail blocks
        for addr in &self.merged_tail_blocks {
            if let Ok(Some((index, _))) = obj.symbols.kind_at_section_address(
                addr.section,
                addr.address,
                ObjSymbolKind::Function,
            ) {
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
        // Update sizes for functions that absorbed tail blocks
        for addr in &self.extended_functions {
            if let Some(info) = self.functions.get(addr) {
                if let Some(end) = info.end {
                    let new_size = (end.address - addr.address) as u64;
                    if let Ok(Some((index, _))) = obj.symbols.kind_at_section_address(
                        addr.section,
                        addr.address,
                        ObjSymbolKind::Function,
                    ) {
                        let existing = &obj.symbols[index];
                        if existing.size != new_size {
                            let symbol = ObjSymbol {
                                size: new_size,
                                size_known: true,
                                ..existing.clone()
                            };
                            obj.symbols.replace(index, symbol)?;
                        }
                    }
                }
            }
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
                        // pdata sizes are conservative and may not include
                        // out-of-line tail blocks, so allow func_end >= known_end
                        if func_end < known_end {
                            panic!(
                                "Function at {} has known end addr {}, but during processing, \
                                 ending was found to be {} (smaller than expected)!",
                                addr, known_end, func_end
                            );
                        } else if func_end != known_end {
                            log::info!(
                                "Function at {} extends beyond pdata end {} to {} \
                                 (likely tail block inclusion)",
                                addr, known_end, func_end
                            );
                        }
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

        // Merge tail blocks: small functions that are actually out-of-line code
        // from the preceding function (e.g., loop exit paths placed after .pdata end)
        self.merge_tail_blocks(obj)?;

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
                info.end = None;
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

    /// Post-pass to merge small functions that are actually tail blocks of their predecessor.
    ///
    /// After all functions are detected (from pdata, symbols, and gap-filling), this scans for
    /// adjacent function pairs where the second function is a tail block of the first. This
    /// handles cases where symbols.txt already has the fake function defined from a previous run.
    fn merge_tail_blocks(&mut self, obj: &ObjInfo) -> Result<()> {
        let mut merges: Vec<(SectionAddress, SectionAddress)> = vec![];

        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            let section_start = SectionAddress::new(section_index, section.address as u32);
            let section_end = section_start + section.size as u32;

            // Collect only the addresses and ends we need — avoid cloning FunctionInfo/slices.
            let func_bounds: Vec<(SectionAddress, Option<SectionAddress>)> = self
                .functions
                .range(section_start..section_end)
                .map(|(&addr, info)| (addr, info.end))
                .collect();

            for window in func_bounds.windows(2) {
                let (prev_addr, prev_end) = window[0];
                let (func_addr, func_end) = window[1];

                let Some(prev_end) = prev_end else { continue };
                let Some(func_end) = func_end else { continue };

                // Only consider the case where the candidate function starts right
                // at the predecessor's end (no gap/alignment between them)
                if func_addr != prev_end {
                    continue;
                }

                // Skip merging if the candidate has a global-scope symbol
                // (user, PDB, or map file explicitly defined it as a real function)
                if let Ok(Some((_, sym))) = obj.symbols.kind_at_section_address(
                    func_addr.section,
                    func_addr.address,
                    ObjSymbolKind::Function,
                ) {
                    if sym.flags.scope() == ObjSymbolScope::Global {
                        log::info!(
                            "Skipping tail block merge of {:#010X} (global-scope symbol '{}')",
                            func_addr, sym.name,
                        );
                        continue;
                    }
                }

                // Check if this function is a tail block
                if let Some(_tail_end) = Self::check_tail_block(
                    section, func_addr, func_end, prev_addr, prev_end,
                ) {
                    log::info!(
                        "Merging tail block function {:#010X}-{:#010X} into {:#010X} (extending from {:#010X})",
                        func_addr, func_end, prev_addr, prev_end,
                    );
                    merges.push((prev_addr, func_addr));
                }
            }
        }

        for (prev_addr, tail_addr) in &merges {
            let tail_end = self
                .functions
                .get(tail_addr)
                .and_then(|i| i.end)
                .expect("tail function must exist in map");
            // Remove the fake function
            self.functions.remove(tail_addr);
            // Track for symbol removal in apply()
            self.merged_tail_blocks.push(*tail_addr);
            // Extend the predecessor's end and track for size update in apply()
            self.extended_functions.push(*prev_addr);
            if let Some(info) = self.functions.get_mut(prev_addr) {
                info.end = Some(tail_end);
                // Mark for re-analysis with the new bounds
                info.analyzed = false;
                info.slices = None;
            }
        }

        if !merges.is_empty() {
            log::info!("Merged {} tail block(s), re-analyzing affected functions", merges.len());
            // Re-analyze the extended functions
            for (prev_addr, _) in &merges {
                self.process_function_at(obj, *prev_addr)?;
            }
        }

        Ok(())
    }

    /// Maximum size of a tail block candidate in bytes (16 instructions).
    const MAX_TAIL_BLOCK_BYTES: u32 = 64;

    /// Check whether `ins` is an unconditional `blr` (return from function).
    fn is_unconditional_blr(ins: &powerpc::Ins) -> bool {
        ins.op == Opcode::Bclr && !ins.field_lk() && (ins.field_bo() & 0b10100 == 0b10100)
    }

    /// If `ins` at `ins_addr` is a non-link, non-absolute branch whose target falls within
    /// `func_start..func_end`, return `Some(target)`. Otherwise return `None`.
    fn branch_into_range(
        ins: &powerpc::Ins,
        ins_addr: u32,
        func_start: u32,
        func_end: u32,
    ) -> Option<u32> {
        if ins.field_lk() || ins.field_aa() {
            return None;
        }
        let target = ins.branch_dest(ins_addr)?;
        if target >= func_start && target < func_end { Some(target) } else { None }
    }

    /// Check if code at `gap_start` (up to `gap_end`) is a tail block of the preceding function.
    ///
    /// A tail block is an out-of-line code fragment (typically a loop exit path) that the
    /// compiler placed after the .pdata-reported function end. It's characterized by:
    /// - Starting with an unconditional branch (`b`, not `bl`) back into the preceding function
    /// - Or containing only a few instructions that all branch back into the preceding function
    ///   before ending with `blr`
    ///
    /// Returns `Some(block_end)` if this is a tail block, where `block_end` is the address
    /// just past the last instruction in the tail block.
    fn check_tail_block(
        section: &ObjSection,
        gap_start: SectionAddress,
        gap_end: SectionAddress,
        preceding_func_start: SectionAddress,
        preceding_func_end: SectionAddress,
    ) -> Option<SectionAddress> {
        let gap_size = gap_end.address - gap_start.address;
        if gap_size > Self::MAX_TAIL_BLOCK_BYTES {
            return None;
        }

        // Case 1: First instruction is an unconditional branch back into the predecessor.
        if let Some(result) = Self::check_tail_block_backward_branch(
            section,
            gap_start,
            gap_end,
            preceding_func_start,
            preceding_func_end,
        ) {
            return Some(result);
        }

        // Case 2: All branches target the predecessor, block ends with blr.
        Self::check_tail_block_scan_block(
            section,
            gap_start,
            gap_end,
            preceding_func_start,
            preceding_func_end,
        )
    }

    /// Case 1: First instruction is an unconditional branch (`b`, not `bl`) back into
    /// the preceding function. This is the classic out-of-line loop exit.
    ///
    /// Scans forward from `gap_start` until a `blr` or `gap_end` to determine the
    /// tail block extent.
    fn check_tail_block_backward_branch(
        section: &ObjSection,
        gap_start: SectionAddress,
        gap_end: SectionAddress,
        preceding_func_start: SectionAddress,
        preceding_func_end: SectionAddress,
    ) -> Option<SectionAddress> {
        let first_ins = disassemble(section, gap_start.address)?;

        if first_ins.op != Opcode::B {
            return None;
        }
        // Must branch back into the preceding function
        Self::branch_into_range(
            &first_ins,
            gap_start.address,
            preceding_func_start.address,
            preceding_func_end.address,
        )?;

        // Scan forward to find the end of this tail block (up to blr or gap_end)
        let mut addr = gap_start;
        loop {
            let ins = disassemble(section, addr.address)?;
            addr += 4;
            if Self::is_unconditional_blr(&ins) {
                return Some(addr);
            }
            if addr >= gap_end {
                return Some(gap_end);
            }
        }
    }

    /// Case 2: Scan the entire gap block — if every branch instruction targets back
    /// into the preceding function (no outward calls or forward jumps to other functions),
    /// and the block ends with `blr`, treat it as a tail block.
    fn check_tail_block_scan_block(
        section: &ObjSection,
        gap_start: SectionAddress,
        gap_end: SectionAddress,
        preceding_func_start: SectionAddress,
        preceding_func_end: SectionAddress,
    ) -> Option<SectionAddress> {
        let mut has_backward_branch = false;
        let mut ends_with_blr = false;
        let mut addr = gap_start;

        while addr < gap_end {
            let ins = disassemble(section, addr.address)?;
            addr += 4;

            if Self::is_unconditional_blr(&ins) {
                ends_with_blr = true;
                if addr >= gap_end {
                    break;
                }
                continue;
            }

            match ins.op {
                // Unconditional or conditional branch (not link)
                Opcode::B | Opcode::Bc if !ins.field_lk() && !ins.field_aa() => {
                    let ins_addr = addr.address - 4;
                    if Self::branch_into_range(
                        &ins,
                        ins_addr,
                        preceding_func_start.address,
                        preceding_func_end.address,
                    )
                    .is_some()
                    {
                        has_backward_branch = true;
                        continue;
                    }
                    // Forward branch within the gap is OK
                    if let Some(target) = ins.branch_dest(ins_addr) {
                        if target >= gap_start.address && target < gap_end.address {
                            continue;
                        }
                    }
                    // Branch outside both the gap and preceding function
                    return None;
                }
                // bl (function call) — tail blocks don't call other functions
                Opcode::B if ins.field_lk() => return None,
                // bctr (indirect branch) — too complex to analyze
                Opcode::Bcctr => return None,
                // Other instructions are fine (arithmetic, loads, stores, etc.)
                _ => {}
            }
        }

        if has_backward_branch && ends_with_blr { Some(gap_end) } else { None }
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

#[cfg(test)]
#[path = "cfa_tests.rs"]
mod cfa_tests;
