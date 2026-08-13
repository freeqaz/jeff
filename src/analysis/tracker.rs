use std::{
    collections::{BTreeMap, BTreeSet},
    mem::take,
};

use anyhow::{bail, Result};
use cwextab::decode_extab;
use powerpc::Opcode;
use tracing::{debug_span, info_span};
use tracing_attributes::instrument;

use crate::{
    analysis::{
        cfa::SectionAddress,
        executor::{ExecCbData, ExecCbResult, Executor},
        relocation_target_for, uniq_jump_table_entries,
        vm::{is_store_op, BranchTarget, Value, StepResult, VM},
        RelocationTarget,
    },
    obj::{
        ObjDataKind, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
        ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, SectionIndex, SymbolIndex,
    },
    util::config::{create_auto_symbol_name, is_auto_symbol},
};

#[derive(Debug, Copy, Clone)]
pub enum Relocation {
    Ha(RelocationTarget),
    Hi(RelocationTarget),
    Lo(RelocationTarget),
    Sda21(RelocationTarget),
    Rel14(RelocationTarget),
    Rel24(RelocationTarget),
    Absolute(RelocationTarget),
}

impl Relocation {
    fn kind_and_address(&self) -> Option<(ObjRelocKind, SectionAddress)> {
        let (reloc_kind, target) = match self {
            Relocation::Ha(v) => (ObjRelocKind::PpcAddr16Ha, v),
            Relocation::Hi(v) => (ObjRelocKind::PpcAddr16Hi, v),
            Relocation::Lo(v) => (ObjRelocKind::PpcAddr16Lo, v),
            Relocation::Sda21(v) => (ObjRelocKind::PpcEmbSda21, v),
            Relocation::Rel14(v) => (ObjRelocKind::PpcRel14, v),
            Relocation::Rel24(v) => (ObjRelocKind::PpcRel24, v),
            Relocation::Absolute(v) => (ObjRelocKind::Absolute, v),
        };
        match *target {
            RelocationTarget::Address(address) => Some((reloc_kind, address)),
            RelocationTarget::External => None,
        }
    }
}

#[derive(Debug)]
pub enum DataKind {
    Unknown = -1,
    Word,
    Half,
    Byte,
    Float,
    Double,
    // String,
    // String16,
}

pub struct Tracker {
    processed_functions: BTreeSet<SectionAddress>,
    /// Every function body this tracker actually walked, as `start -> size`.
    ///
    /// Used by the second, post-repair tracker pass in `cmd::xex` to answer
    /// "which function bodies has nobody analysed yet?" — a function that was
    /// synthesized, promoted, grown or merged after the first pass either is
    /// absent from this map or is present with a different size, and is exactly
    /// the set whose instruction stream would otherwise split with no
    /// relocations. See `retrack_unanalyzed_functions`.
    analyzed_functions: BTreeMap<SectionAddress, u32>,
    sda2_base: Option<u32>, // r2
    sda_base: Option<u32>,  // r13
    pub relocations: BTreeMap<SectionAddress, Relocation>,
    data_types: BTreeMap<SectionAddress, DataKind>,
    stack_address: Option<u32>,
    stack_end: Option<u32>,
    db_stack_addr: Option<u32>,
    arena_lo: Option<u32>,
    arena_hi: Option<u32>,
    pub known_relocations: BTreeSet<SectionAddress>,

    stores_to: BTreeSet<SectionAddress>, // for determining data vs rodata, sdata(2)/sbss(2)
    sda_to: BTreeSet<SectionAddress>,    // for determining data vs sdata
    hal_to: BTreeSet<SectionAddress>,    // for determining data vs sdata
}

impl Tracker {
    pub fn new(obj: &ObjInfo) -> Tracker {
        Self {
            processed_functions: Default::default(),
            analyzed_functions: Default::default(),
            sda2_base: obj.sda2_base,
            sda_base: obj.sda_base,
            relocations: Default::default(),
            data_types: Default::default(),
            stack_address: obj.stack_address,
            stack_end: obj.stack_end.or_else(|| {
                // Stack ends after all BSS sections
                obj.sections
                    .iter()
                    .rfind(|&(_, s)| s.kind == ObjSectionKind::Bss)
                    .map(|(_, s)| (s.address + s.size) as u32)
            }),
            db_stack_addr: obj.db_stack_addr,
            arena_lo: obj
                .arena_lo
                .or_else(|| obj.db_stack_addr.map(|db_stack_addr| (db_stack_addr + 0x1F) & !0x1F)),
            arena_hi: Some(obj.arena_hi.unwrap_or(0x81700000)),
            known_relocations: Default::default(),
            stores_to: Default::default(),
            sda_to: Default::default(),
            hal_to: Default::default(),
        }
    }

    #[instrument(name = "tracker", skip(self, obj))]
    pub fn process(&mut self, obj: &ObjInfo) -> Result<()> {
        self.process_code(obj)?;
        if obj.kind == ObjKind::Executable {
            for (section_index, section) in obj.sections.iter().filter(|(_, s)| {
                matches!(s.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData)
            }) {
                log::debug!("Processing section {}, address {:#X}", section_index, section.address);
                self.process_data(obj, section_index, section)?;
            }
        }
        self.check_extab_relocations(obj)?;
        self.reject_invalid_relocations(obj)?;
        Ok(())
    }

    /// Remove data relocations that point to an unaligned address if the aligned address has a
    /// relocation. A relocation will never point to the middle of an address.
    fn reject_invalid_relocations(&mut self, obj: &ObjInfo) -> Result<()> {
        let mut to_reject = vec![];
        for (&address, reloc) in &self.relocations {
            let section = &obj.sections[address.section];
            if !matches!(section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData) {
                continue;
            }
            let Some((_, target)) = reloc.kind_and_address() else {
                continue;
            };
            if !target.is_aligned(4) && self.relocations.contains_key(&target.align_down(4)) {
                log::debug!("Rejecting invalid relocation @ {} -> {}", address, target);
                to_reject.push(address);
            }
        }
        for address in to_reject {
            self.relocations.remove(&address);
        }
        Ok(())
    }

    /// Check all of the extab relocations, and reject any invalid ones by checking against the decoded table data
    /// of each table.
    fn check_extab_relocations(&mut self, obj: &ObjInfo) -> Result<()> {
        let mut to_reject = vec![];
        let Some((section_index, section)) = obj.sections.by_name("extab")? else {
            // No extab section found, return
            return Ok(());
        };
        let mut decoded_reloc_addrs: BTreeSet<u32> = BTreeSet::new();

        // Decode each exception table, and collect all of the relocations from the decoded data for each
        for (_, symbol) in obj.symbols.for_section(section_index) {
            let extab_name = &symbol.name;
            let extab_start_addr: u32 = symbol.address as u32;
            let extab_end_addr: u32 = extab_start_addr + symbol.size as u32;
            let Ok(extab_data) = section.data_range(extab_start_addr, extab_end_addr) else {
                log::warn!("Failed to get extab data for symbol {}", extab_name);
                continue;
            };
            let data = match decode_extab(extab_data) {
                Ok(decoded_data) => decoded_data,
                Err(e) => {
                    log::warn!(
                        "Exception table decoding failed for symbol {}, reason: {}",
                        extab_name,
                        e
                    );
                    continue;
                }
            };

            for reloc in data.relocations {
                let reloc_addr = extab_start_addr + reloc.offset;
                decoded_reloc_addrs.insert(reloc_addr);
            }
        }

        let section_start_addr = SectionAddress::new(section_index, section.address as u32);
        let section_end_addr = section_start_addr + (section.size as u32);

        // Check all the extab relocations against the list of relocations from the decoded tables. Any
        // relocations that aren't in the list are invalid, and are removed (if a table fails to decode,
        // however, its relocations are all removed).
        for (&address, _) in self.relocations.range(section_start_addr..section_end_addr) {
            if !decoded_reloc_addrs.contains(&address.address) {
                log::debug!("Rejecting invalid extab relocation @ {}", address);
                to_reject.push(address);
            }
        }

        for address in to_reject {
            self.relocations.remove(&address);
        }
        Ok(())
    }

    fn process_code(&mut self, obj: &ObjInfo) -> Result<()> {
        if let Some(entry) = obj.entry {
            let (section_index, _) = obj.sections.at_address(entry as u32)?;
            let entry_addr = SectionAddress::new(section_index, entry as u32);
            self.process_function_by_address(obj, entry_addr)?;
        }
        for (section_index, _) in obj.sections.by_kind(ObjSectionKind::Code) {
            for (_, symbol) in obj.symbols.for_section(section_index).filter(|(_, symbol)| {
                symbol.kind == ObjSymbolKind::Function
                    && symbol.size_known
                    && !symbol.name.contains("__imp")
            }) {
                let addr = SectionAddress::new(section_index, symbol.address as u32);
                if !self.processed_functions.insert(addr) {
                    continue;
                }
                self.process_function(obj, symbol)?;
            }
        }
        Ok(())
    }

    fn process_function_by_address(&mut self, obj: &ObjInfo, addr: SectionAddress) -> Result<()> {
        if self.processed_functions.contains(&addr) {
            return Ok(());
        }
        self.processed_functions.insert(addr);
        if let Some((_, symbol)) = obj
            .symbols
            .at_section_address(addr.section, addr.address)
            .find(|(_, symbol)| symbol.kind == ObjSymbolKind::Function && symbol.size_known)
        {
            self.process_function(obj, symbol)?;
        } else {
            log::warn!("Failed to locate function symbol @ {:#010X}", addr);
        }
        Ok(())
    }

    #[inline]
    fn gpr_address(
        &self,
        obj: &ObjInfo,
        ins_addr: SectionAddress,
        value: &Value,
    ) -> Option<RelocationTarget> {
        match *value {
            Value::Constant(value) => {
                self.is_valid_address(obj, ins_addr, value as u32).map(RelocationTarget::Address)
            }
            Value::Address(address) => Some(address),
            _ => None,
        }
    }

    fn instruction_callback(
        &mut self,
        data: ExecCbData,
        obj: &ObjInfo,
        function_start: SectionAddress,
        function_end: SectionAddress,
        possible_missed_branches: &mut BTreeMap<SectionAddress, Box<VM>>,
    ) -> Result<ExecCbResult<()>> {
        let ExecCbData { executor, vm, result, ins_addr, section: _, ins, block_start: _ } = data;

        // Judge containment against the function that actually CONTAINS this
        // instruction, not against the function the walk started from.
        //
        // `Executor::run` walks a basic block linearly — `ExecCbResult::Continue`
        // advances `state.address += 4` — and it bounds that walk at the end of
        // the SECTION, not at the end of a function; it has no notion of a
        // function at all. So a block that does not end in a terminator runs off
        // the end of its function and into the next one. That happens routinely:
        // `StepResult::Illegal` returns `Continue`, so the inter-function padding
        // word does not end a block, and `StepResult::Jump` seeds
        // `possible_missed_branches` with `ins_addr + 4`, which after a tail `b`
        // IS that padding word (dc3 `Curl_resolv_timeout` @ 0x8256AAD4).
        //
        // The defect is not that the walk strays — it is that `function_start` /
        // `function_end` are captured once per `process_function` and do not
        // follow it, so `is_function_addr` answers for the WRONG function. At dc3
        // `hostip.obj` `.text+0x53c` the captured bounds are
        // `[0x8256AAB8, 0x8256AAD8)` (`Curl_resolv_timeout`) while `ins_addr` is
        // 0x8256AAFC and the branch target 0x8256AB0C — both inside
        // `Curl_resolv_unlock` `[0x8256AAD8, 0x8256AB74)`. The intra-function `bc`
        // reads as leaving its function and gets a `Rel14` it must never have.
        // (T2-rel14-rootcause.md §1.)
        //
        // WHY NOT JUST STOP THE WALK. Measured, and rejected on the measurement:
        // ending the block at `function_end` costs 94 relocation records across
        // 17 rb3-xenon objects (26 REFLO, 47 PAIR, 21 REFHI, 3 ADDR24) and their
        // in-place immediates stop being zeroed. Those records are CORRECT — they
        // are `lis`/`lfs` hi-lo pairs whose two halves straddle a function
        // boundary that dtk carved in the wrong place (`fn_8249B200` is declared
        // `size:0x4`; `Color.obj`'s `lis` sits in the previous function and its
        // `lfs` in `fn_824F5730`). Hi-lo pairing is a dataflow fact and does not
        // depend on function bounds; only the branch-containment question does.
        // A bounds check on the whole callback throws the first away to fix the
        // second. See docs/sessions/2026-08-13-tracker-runaway-walk/README.md.
        let (fn_start, fn_end) = if ins_addr >= function_start && ins_addr < function_end {
            (function_start, function_end)
        } else {
            enclosing_function_bounds(obj, ins_addr).unwrap_or((function_start, function_end))
        };
        // Using > instead of >= to treat a branch to the beginning of the function as a tail call
        let is_function_addr = |addr: SectionAddress| addr > fn_start && addr < fn_end;
        let _span = debug_span!("ins", addr = %ins_addr, op = ?ins.op).entered();

        match result {
            StepResult::Continue => {
                match ins.op {
                    // addi rD, rA, SIMM
                    Opcode::Addi | Opcode::Addic | Opcode::Addic_ => {
                        let source = ins.field_ra() as usize;
                        let target = ins.field_rd() as usize;
                        if let Some(value) = self.gpr_address(obj, ins_addr, &vm.gpr[target].value)
                        {
                            if (source == 2
                                && matches!(self.sda2_base, Some(v) if vm.gpr[2].value == Value::Constant(v as u64)))
                                || (source == 13
                                    && matches!(self.sda_base, Some(v) if vm.gpr[13].value == Value::Constant(v as u64)))
                            {
                                self.relocations.insert(ins_addr, Relocation::Sda21(value));
                                if let RelocationTarget::Address(address) = value {
                                    self.sda_to.insert(address);
                                }
                            } else if let (Some(hi_addr), Some(lo_addr)) =
                                (vm.gpr[target].hi_addr, vm.gpr[target].lo_addr)
                            {
                                let hi_reloc = self.relocations.get(&hi_addr).cloned();
                                if hi_reloc.is_none() {
                                    debug_assert_ne!(
                                        value,
                                        RelocationTarget::Address(SectionAddress::new(
                                            SectionIndex::MAX,
                                            0
                                        ))
                                    );
                                    self.relocations.insert(hi_addr, Relocation::Ha(value));
                                }
                                let lo_reloc = self.relocations.get(&lo_addr).cloned();
                                if lo_reloc.is_none() {
                                    self.relocations.insert(lo_addr, Relocation::Lo(value));
                                }
                                if let RelocationTarget::Address(address) = value {
                                    self.hal_to.insert(address);
                                }
                            }
                        }
                    }
                    // ori rA, rS, UIMM
                    Opcode::Ori => {
                        let target = ins.field_ra() as usize;
                        if let Some(value) = self.gpr_address(obj, ins_addr, &vm.gpr[target].value)
                        {
                            if let (Some(hi_addr), Some(lo_addr)) =
                                (vm.gpr[target].hi_addr, vm.gpr[target].lo_addr)
                            {
                                let hi_reloc = self.relocations.get(&hi_addr).cloned();
                                if hi_reloc.is_none() {
                                    self.relocations.insert(hi_addr, Relocation::Ha(value));
                                }
                                let lo_reloc = self.relocations.get(&lo_addr).cloned();
                                if lo_reloc.is_none() {
                                    self.relocations.insert(lo_addr, Relocation::Lo(value));
                                }
                                if let RelocationTarget::Address(address) = value {
                                    self.hal_to.insert(address);
                                }
                            }
                        }
                    }
                    _ => {}
                }
                Ok(ExecCbResult::Continue)
            }
            StepResult::LoadStore { address, source, source_reg } => {
                if !obj.blocked_relocation_sources.contains(ins_addr) {
                    if (source_reg == 2
                        && matches!(self.sda2_base, Some(v) if source.value == Value::Constant(v as u64)))
                        || (source_reg == 13
                            && matches!(self.sda_base, Some(v) if source.value == Value::Constant(v as u64)))
                    {
                        self.relocations.insert(ins_addr, Relocation::Sda21(address));
                        if let RelocationTarget::Address(address) = address {
                            self.sda_to.insert(address);
                        }
                    } else {
                        match (source.hi_addr, source.lo_addr) {
                            (Some(hi_addr), None) => {
                                let hi_reloc = self.relocations.get(&hi_addr).cloned();
                                if hi_reloc.is_none() {
                                    debug_assert_ne!(
                                        address,
                                        RelocationTarget::Address(SectionAddress::new(
                                            SectionIndex::MAX,
                                            0
                                        ))
                                    );
                                    self.relocations.insert(hi_addr, Relocation::Ha(address));
                                }
                                if hi_reloc.is_none()
                                    || matches!(hi_reloc, Some(Relocation::Ha(v)) if v == address)
                                {
                                    self.relocations.insert(ins_addr, Relocation::Lo(address));
                                }
                                if let RelocationTarget::Address(address) = address {
                                    self.hal_to.insert(address);
                                }
                            }
                            (Some(hi_addr), Some(lo_addr)) => {
                                let hi_reloc = self.relocations.get(&hi_addr).cloned();
                                if hi_reloc.is_none() {
                                    debug_assert_ne!(
                                        address,
                                        RelocationTarget::Address(SectionAddress::new(
                                            SectionIndex::MAX,
                                            0
                                        ))
                                    );
                                    self.relocations.insert(hi_addr, Relocation::Ha(address));
                                }
                                let lo_reloc = self.relocations.get(&lo_addr).cloned();
                                if lo_reloc.is_none() {
                                    self.relocations.insert(lo_addr, Relocation::Lo(address));
                                }
                                if let RelocationTarget::Address(address) = address {
                                    self.hal_to.insert(address);
                                }
                            }
                            _ => {}
                        }
                    }
                    if let RelocationTarget::Address(address) = address {
                        self.data_types.insert(address, data_kind_from_op(ins.op));
                        if is_store_op(ins.op) {
                            self.stores_to.insert(address);
                        }
                    }
                }
                Ok(ExecCbResult::Continue)
            }
            StepResult::Illegal => {
                log::debug!(
                    "Illegal instruction hit @ {:#010X} (function {:#010X}-{:#010X})",
                    ins_addr,
                    function_start,
                    function_end
                );
                Ok(ExecCbResult::Continue)
            }
            StepResult::Jump(target) => match target {
                BranchTarget::Return => Ok(ExecCbResult::EndBlock),
                BranchTarget::Unknown
                | BranchTarget::JumpTable {
                    jump_table_address: RelocationTarget::External, ..
                } => {
                    let next_addr = ins_addr + 4;
                    if next_addr < function_end {
                        possible_missed_branches.insert(ins_addr + 4, vm.clone_all());
                    }
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::Address(addr) => {
                    let next_addr = ins_addr + 4;
                    if next_addr < function_end {
                        possible_missed_branches.insert(ins_addr + 4, vm.clone_all());
                    }
                    if let RelocationTarget::Address(addr) = addr {
                        if is_function_addr(addr) {
                            return Ok(ExecCbResult::Jump(addr));
                        }
                    }
                    if ins.is_direct_branch() {
                        self.relocations.insert(ins_addr, Relocation::Rel24(addr));
                    }
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::JumpTable {
                    jump_table_type: jt,
                    jump_table_address: RelocationTarget::Address(address),
                    size,
                } => {
                    let (entries, _) = uniq_jump_table_entries(
                        obj,
                        address,
                        jt,
                        size,
                        ins_addr,
                        function_start,
                        Some(function_end),
                    )?;
                    for target in entries {
                        if is_function_addr(target) {
                            executor.push(target, vm.clone_all(), true);
                        }
                    }
                    Ok(ExecCbResult::EndBlock)
                }
            },
            StepResult::Branch(branches) => {
                for branch in branches {
                    match branch.target {
                        BranchTarget::Unknown
                        | BranchTarget::Return
                        | BranchTarget::JumpTable {
                            jump_table_address: RelocationTarget::External,
                            ..
                        } => {}
                        BranchTarget::Address(target) => {
                            let (addr, is_fn_addr) = if let RelocationTarget::Address(addr) = target
                            {
                                (addr, is_function_addr(addr))
                            } else {
                                (SectionAddress::new(SectionIndex::MAX, 0), false)
                            };
                            // NOTE, task 161: the not-taken entry here is a
                            // SYNTHESIZED fall-through — `VM::step` builds it as
                            // `BranchTarget::Address(ins_addr + 4)` with
                            // `link: false` — and when a `bc` is the last
                            // instruction of its declared function that address
                            // equals `function_end`, fails the exclusive test in
                            // `is_function_addr`, and is stamped with a Rel14
                            // naming the instruction AFTER the branch. T2's
                            // second trigger. Suppressing it here was implemented
                            // and MEASURED, and is deliberately not landed: it
                            // perturbs `merge_fallthrough_leaf_fragments`, whose
                            // absorb decisions read the tracker's reloc-target
                            // xref counts, and cost 5 mangled rb3-xenon symbol
                            // names across 15 objects. The records themselves are
                            // stopped at the writer instead, by comparing the
                            // relocation against the instruction's own encoded
                            // displacement (util/xex.rs, R1). See
                            // docs/sessions/2026-08-13-tracker-runaway-walk/README.md §6.
                            if branch.link || !is_fn_addr {
                                self.relocations.insert(ins_addr, match ins.op {
                                    Opcode::B => Relocation::Rel24(target),
                                    Opcode::Bc => {
                                        if addr == function_start {
                                            // MSVC's linker doesn't accept REL14 in tail calls
                                            Relocation::Rel24(target)
                                        } else {
                                            Relocation::Rel14(target)
                                        }
                                    }
                                    _ => continue,
                                });
                            } else if is_fn_addr {
                                executor.push(addr, branch.vm, true);
                            }
                        }
                        BranchTarget::JumpTable {
                            jump_table_type: jt,
                            jump_table_address: RelocationTarget::Address(address),
                            size,
                        } => {
                            let (entries, _) = uniq_jump_table_entries(
                                obj,
                                address,
                                jt,
                                size,
                                ins_addr,
                                function_start,
                                Some(function_end),
                            )?;
                            for target in entries {
                                if is_function_addr(target) {
                                    executor.push(target, branch.vm.clone_all(), true);
                                }
                            }
                        }
                    }
                }
                Ok(ExecCbResult::EndBlock)
            }
        }
    }

    pub fn process_function(&mut self, obj: &ObjInfo, symbol: &ObjSymbol) -> Result<()> {
        let Some(section_index) = symbol.section else {
            bail!("Function '{}' missing section", symbol.name)
        };
        let function_start = SectionAddress::new(section_index, symbol.address as u32);
        let function_end = function_start + symbol.size as u32;
        self.analyzed_functions.insert(function_start, symbol.size as u32);
        let _span =
            info_span!("fn", name = %symbol.name, start = %function_start, end = %function_end)
                .entered();

        // The compiler can sometimes create impossible-to-reach branches,
        // but we still want to track them.
        let mut possible_missed_branches = BTreeMap::new();

        let mut executor = Executor::new(obj);
        executor.push(function_start, VM::new_with_base(self.sda2_base, self.sda_base), false);
        loop {
            executor.run(obj, |data| -> Result<ExecCbResult<()>> {
                self.instruction_callback(
                    data,
                    obj,
                    function_start,
                    function_end,
                    &mut possible_missed_branches,
                )
            })?;

            if possible_missed_branches.is_empty() {
                break;
            }
            let mut added = false;
            for (addr, vm) in take(&mut possible_missed_branches) {
                let section = &obj.sections[addr.section];
                if !executor.visited(section.address as u32, addr) {
                    executor.push(addr, vm, true);
                    added = true;
                }
            }
            if !added {
                break;
            }
        }
        Ok(())
    }

    fn process_data(
        &mut self,
        obj: &ObjInfo,
        section_index: SectionIndex,
        section: &ObjSection,
    ) -> Result<()> {
        let is_pdata = section.name == ".pdata";
        let mut addr = SectionAddress::new(section_index, section.address as u32);
        for (i, chunk) in section.data.chunks_exact(4).enumerate() {
            // Xbox 360 .pdata entries are 8 bytes: word 0 = function VA,
            // word 1 = packed metadata (not an address). Skip word 1 to
            // avoid false relocations to __unwind$ symbols.
            if is_pdata && i % 2 == 1 {
                addr += 4;
                continue;
            }
            let value = u32::from_be_bytes(chunk.try_into()?);
            if let Some(value) = self.is_valid_address(obj, addr, value) {
                self.relocations
                    .insert(addr, Relocation::Absolute(RelocationTarget::Address(value)));
            }
            addr += 4;
        }
        Ok(())
    }

    fn is_valid_address(
        &self,
        obj: &ObjInfo,
        from: SectionAddress,
        addr: u32,
    ) -> Option<SectionAddress> {
        // Check for an existing relocation
        if cfg!(debug_assertions) {
            let relocation_target = relocation_target_for(obj, from, None).ok().flatten();
            if !matches!(relocation_target, None | Some(RelocationTarget::External)) {
                // Executable inputs can legitimately carry source relocations already.
                // Continue with normal validation so debug and release behavior match.
                log::trace!(
                    "Source already has relocation (from {} -> {:?}), continuing address validation for {:#010X}",
                    from,
                    relocation_target,
                    addr
                );
            }
        }
        // Remainder of this function is for executable objects only
        if obj.kind == ObjKind::Relocatable {
            return None;
        }
        // Check blocked relocation sources
        if obj.blocked_relocation_sources.contains(from) {
            return None;
        }
        // Find the section containing the address
        if let Ok((section_index, section)) = obj.sections.at_address(addr) {
            // References to code sections will never be unaligned
            if section.kind == ObjSectionKind::Code && addr & 3 != 0 {
                return None;
            }
            let section_address = SectionAddress::new(section_index, addr);
            // Check blocked relocation targets
            if obj.blocked_relocation_targets.contains(section_address) {
                return None;
            }
            // It's valid
            Some(section_address)
        } else {
            // Check known relocations (function signature matching)
            if self.known_relocations.contains(&from) {
                return Some(SectionAddress::new(SectionIndex::MAX, addr));
            }
            // Check special symbols
            if self.stack_address == Some(addr)
                || self.stack_end == Some(addr)
                || self.db_stack_addr == Some(addr)
                || self.arena_lo == Some(addr)
                || self.arena_hi == Some(addr)
                || self.sda2_base == Some(addr)
                || self.sda_base == Some(addr)
            {
                return Some(SectionAddress::new(SectionIndex::MAX, addr));
            }
            // Not valid
            None
        }
    }

    fn special_symbol(
        &self,
        obj: &mut ObjInfo,
        addr: u32,
        reloc_kind: ObjRelocKind,
    ) -> Option<SymbolIndex> {
        if !matches!(
            reloc_kind,
            ObjRelocKind::PpcAddr16Ha | ObjRelocKind::PpcAddr16Lo
            // RSOLinkInit uses a data table containing references to _SDA_BASE_ and _SDA2_BASE_
            | ObjRelocKind::Absolute
        ) {
            return None;
        }
        // HACK for RSOStaticLocateObject
        // for section in &obj.sections {
        //     if addr == section.address as u32 {
        //         let name = format!("_f_{}", section.name.trim_start_matches('.'));
        //         return generate_special_symbol(obj, addr, &name).ok();
        //     }
        // }
        let mut check_symbol = |opt: Option<u32>, name: &str| -> Option<SymbolIndex> {
            if let Some(value) = opt {
                if addr == value {
                    return generate_special_symbol(obj, value, name).ok();
                }
            }
            None
        };
        check_symbol(self.stack_address, "_stack_addr")
            .or_else(|| check_symbol(self.stack_end, "_stack_end"))
            .or_else(|| check_symbol(self.arena_lo, "__ArenaLo"))
            .or_else(|| check_symbol(self.arena_hi, "__ArenaHi"))
            .or_else(|| check_symbol(self.db_stack_addr, "_db_stack_addr"))
            .or_else(|| check_symbol(self.sda2_base, "_SDA2_BASE_"))
            .or_else(|| check_symbol(self.sda_base, "_SDA_BASE_"))
    }

    #[instrument(name = "apply", skip(self, obj))]
    pub fn apply(&self, obj: &mut ObjInfo, replace: bool) -> Result<()> {
        fn apply_section_name(section: &mut ObjSection, name: &str) {
            let module_id = if let Some((_, b)) = section.name.split_once(':') {
                b.parse::<u32>().unwrap_or(0)
            } else {
                0
            };
            let new_name =
                if module_id == 0 { name.to_string() } else { format!("{name}:{module_id}") };
            log::debug!("Renaming {} to {}", section.name, new_name);
            section.name = new_name;
        }

        for (section_index, section) in obj.sections.iter_mut() {
            if !section.section_known {
                if section.kind == ObjSectionKind::Code {
                    apply_section_name(section, ".text");
                    continue;
                }
                let start = SectionAddress::new(section_index, section.address as u32);
                let end = start + section.size as u32;
                if self.sda_to.range(start..end).next().is_some() {
                    if self.stores_to.range(start..end).next().is_some() {
                        if section.kind == ObjSectionKind::Bss {
                            apply_section_name(section, ".sbss");
                        } else {
                            apply_section_name(section, ".sdata");
                        }
                    } else if section.kind == ObjSectionKind::Bss {
                        apply_section_name(section, ".sbss2");
                    } else {
                        apply_section_name(section, ".sdata2");
                        section.kind = ObjSectionKind::ReadOnlyData;
                    }
                } else if self.hal_to.range(start..end).next().is_some() {
                    if section.kind == ObjSectionKind::Bss {
                        apply_section_name(section, ".bss");
                    } else if self.stores_to.range(start..end).next().is_some() {
                        apply_section_name(section, ".data");
                    } else {
                        apply_section_name(section, ".rodata");
                        section.kind = ObjSectionKind::ReadOnlyData;
                    }
                }
            }
        }

        self.apply_relocations(obj, replace)?;

        // Rename all discovered extab dtors from extab relocations
        if let Some((_, extab_section)) = obj.sections.by_name("extab")? {
            for (_, reloc) in extab_section.relocations.iter() {
                let symbol = &obj.symbols[reloc.target_symbol];
                // Only rename auto symbols
                if is_auto_symbol(symbol) {
                    let mut new_symbol = symbol.clone();
                    let name =
                        create_auto_symbol_name("dtor", obj.module_id, symbol.address as u32);

                    new_symbol.name = name;
                    obj.symbols.replace(reloc.target_symbol, new_symbol)?;
                }
            }
        }

        Ok(())
    }

    /// The size of the function body this tracker walked starting at `addr`, if any.
    pub fn analyzed_function_size(&self, addr: SectionAddress) -> Option<u32> {
        self.analyzed_functions.get(&addr).copied()
    }

    /// Commit only the tracked relocations to `obj`, without the section
    /// classification/renaming or extab dtor renaming that [`Self::apply`] also
    /// performs.
    ///
    /// A second, incremental tracker pass must NOT re-run those: its
    /// `sda_to`/`stores_to`/`hal_to` sets are derived from a small subset of the
    /// module's functions, so feeding them to the section classifier could flip
    /// a section named `.data` by the full first pass to `.rodata` purely
    /// because the handful of functions in the second pass happen not to store
    /// to it. Relocation insertion has no such whole-module dependency.
    pub fn apply_relocations(&self, obj: &mut ObjInfo, replace: bool) -> Result<()> {
        for (&addr, reloc) in &self.relocations {
            let Some((reloc_kind, target)) = reloc.kind_and_address() else {
                // Skip external relocations, they already exist
                continue;
            };
            if obj.blocked_relocation_sources.contains(addr)
                || obj.blocked_relocation_targets.contains(target)
            {
                // Skip blocked relocations
                continue;
            }
            if obj.kind == ObjKind::Relocatable {
                // Sanity check: relocatable objects already have relocations,
                // did our analyzer find one that isn't real?
                let section = &obj.sections[addr.section];
                if section.relocations.at(addr.address).is_none()
                    // We _do_ want to rebuild missing R_PPC_REL24 relocations
                    && !matches!(reloc_kind, ObjRelocKind::PpcRel24)
                {
                    log::warn!(
                        "Found invalid relocation {} {:?} (target {}) in relocatable object",
                        addr,
                        reloc,
                        target
                    );
                }
            }
            let (data_kind, inferred_alignment) = self
                .data_types
                .get(&target)
                .map(|dt| match dt {
                    DataKind::Unknown => (ObjDataKind::Unknown, None),
                    DataKind::Word => (ObjDataKind::Byte4, None),
                    DataKind::Half => (ObjDataKind::Byte2, None),
                    DataKind::Byte => (ObjDataKind::Byte, None),
                    DataKind::Float => (ObjDataKind::Float, Some(4)),
                    DataKind::Double => (ObjDataKind::Double, Some(8)),
                })
                .unwrap_or_default();
            let (target_symbol, addend) =
                if let Some(symbol) = self.special_symbol(obj, target.address, reloc_kind) {
                    (symbol, 0)
                } else if let Some((symbol_idx, symbol)) =
                    obj.symbols.for_relocation(target, reloc_kind)?
                {
                    let symbol_address = symbol.address;
                    if symbol_address as u32 == target.address
                        && ((data_kind != ObjDataKind::Unknown
                            && symbol.data_kind == ObjDataKind::Unknown)
                            || (symbol.align.is_none() && inferred_alignment.is_some()))
                    {
                        let mut new_symbol = symbol.clone();
                        if symbol.data_kind == ObjDataKind::Unknown {
                            new_symbol.data_kind = data_kind;
                        }
                        if symbol.align.is_none() {
                            if let Some(inferred_alignment) = inferred_alignment {
                                if symbol_address as u32 % inferred_alignment == 0 {
                                    new_symbol.align = Some(inferred_alignment);
                                }
                            }
                        }
                        obj.symbols.replace(symbol_idx, new_symbol)?;
                    }
                    (symbol_idx, target.address as i64 - symbol_address as i64)
                } else {
                    // Create a new label
                    let name = if obj.module_id == 0 {
                        format!("lbl_{:08X}", target.address)
                    } else {
                        format!(
                            "lbl_{}_{}_{:X}",
                            obj.module_id,
                            obj.sections[target.section].name.trim_start_matches('.'),
                            target.address
                        )
                    };
                    let symbol_idx = obj.symbols.add_direct(ObjSymbol {
                        name,
                        address: target.address as u64,
                        section: Some(target.section),
                        data_kind,
                        ..Default::default()
                    })?;
                    (symbol_idx, 0)
                };
            let reloc = ObjReloc { kind: reloc_kind, target_symbol, addend, module: None };
            let section = &mut obj.sections[addr.section];
            if replace {
                section.relocations.replace(addr.address, reloc);
            } else if let Err(e) = section.relocations.insert(addr.address, reloc.clone()) {
                let reloc_symbol = &obj.symbols[target_symbol];
                if reloc_symbol.name != "_unresolved" {
                    let iter_symbol = &obj.symbols[e.value.target_symbol];
                    if iter_symbol.address as i64 + e.value.addend
                        != reloc_symbol.address as i64 + addend
                    {
                        bail!(
                            "Conflicting relocations (target {:#010X}): {:#010X?} ({} {:#X}) != {:#010X?} ({} {:#X})",
                            target,
                            e.value,
                            iter_symbol.name,
                            iter_symbol.address as i64 + e.value.addend,
                            reloc,
                            reloc_symbol.name,
                            reloc_symbol.address as i64 + addend,
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

/// Bounds `(start, end)` of the function that actually contains `addr`.
///
/// `Tracker::instruction_callback` uses this only when the executor's block walk
/// has run past the end of the function it was started on: the containment
/// question ("does this branch leave its function, and therefore need a
/// relocation?") has to be answered by the function the branch is IN, and the
/// walk's own `function_start`/`function_end` no longer describe it.
///
/// `end` is the declared end when `addr` falls inside the declared body. When it
/// does not — an instruction in the gap after an under-sized or size-less symbol
/// — it is the start of the next function symbol, so that the gap is attributed
/// to the symbol that precedes it rather than to no function at all. dtk carves
/// plenty of those: dc3's `??$FindSetBitInArray@I@D3DXShader@@YAIPAIIK@Z` is
/// declared `size:0x40` while its loop-exit `bc` sits one instruction past the
/// declared end and branches back INTO the body.
///
/// Returns `None` when no function symbol precedes `addr` in its section, in
/// which case the caller keeps the walk's own bounds.
fn enclosing_function_bounds(
    obj: &ObjInfo,
    addr: SectionAddress,
) -> Option<(SectionAddress, SectionAddress)> {
    let section = obj.sections.get(addr.section)?;
    let (_, start_sym) = obj
        .symbols
        .for_section_range(addr.section, ..=addr.address)
        .rev()
        .find(|(_, s)| s.kind == ObjSymbolKind::Function)?;
    let start = SectionAddress::new(addr.section, start_sym.address as u32);
    let declared_end = start + start_sym.size as u32;
    if start_sym.size_known && start_sym.size > 0 && addr < declared_end {
        return Some((start, declared_end));
    }
    let next = obj
        .symbols
        .for_section_range(addr.section, start.address.saturating_add(1)..)
        .find(|(_, s)| s.kind == ObjSymbolKind::Function)
        .map(|(_, s)| s.address as u32)
        .unwrap_or_else(|| (section.address + section.size) as u32);
    Some((start, SectionAddress::new(addr.section, next.max(declared_end.address))))
}

fn data_kind_from_op(op: Opcode) -> DataKind {
    match op {
        Opcode::Lbz => DataKind::Byte,
        Opcode::Lbzu => DataKind::Byte,
        Opcode::Lbzux => DataKind::Byte,
        Opcode::Lbzx => DataKind::Byte,
        Opcode::Lfd => DataKind::Double,
        Opcode::Lfdu => DataKind::Double,
        Opcode::Lfdux => DataKind::Double,
        Opcode::Lfdx => DataKind::Double,
        Opcode::Lfs => DataKind::Float,
        Opcode::Lfsu => DataKind::Float,
        Opcode::Lfsux => DataKind::Float,
        Opcode::Lfsx => DataKind::Float,
        Opcode::Lha => DataKind::Half,
        Opcode::Lhau => DataKind::Half,
        Opcode::Lhaux => DataKind::Half,
        Opcode::Lhax => DataKind::Half,
        Opcode::Lhbrx => DataKind::Half,
        Opcode::Lhz => DataKind::Half,
        Opcode::Lhzu => DataKind::Half,
        Opcode::Lhzux => DataKind::Half,
        Opcode::Lhzx => DataKind::Half,
        Opcode::Lwz => DataKind::Word,
        Opcode::Lwzu => DataKind::Word,
        Opcode::Lwzux => DataKind::Word,
        Opcode::Lwzx => DataKind::Word,
        Opcode::Stb => DataKind::Byte,
        Opcode::Stbu => DataKind::Byte,
        Opcode::Stbux => DataKind::Byte,
        Opcode::Stbx => DataKind::Byte,
        Opcode::Stfd => DataKind::Double,
        Opcode::Stfdu => DataKind::Double,
        Opcode::Stfdux => DataKind::Double,
        Opcode::Stfdx => DataKind::Double,
        Opcode::Stfiwx => DataKind::Float,
        Opcode::Stfs => DataKind::Float,
        Opcode::Stfsu => DataKind::Float,
        Opcode::Stfsux => DataKind::Float,
        Opcode::Stfsx => DataKind::Float,
        Opcode::Sth => DataKind::Half,
        Opcode::Sthbrx => DataKind::Half,
        Opcode::Sthu => DataKind::Half,
        Opcode::Sthux => DataKind::Half,
        Opcode::Sthx => DataKind::Half,
        Opcode::Stw => DataKind::Word,
        Opcode::Stwbrx => DataKind::Word,
        Opcode::Stwcx_ => DataKind::Word,
        Opcode::Stwu => DataKind::Word,
        Opcode::Stwux => DataKind::Word,
        Opcode::Stwx => DataKind::Word,
        _ => DataKind::Unknown,
    }
}

fn generate_special_symbol(obj: &mut ObjInfo, addr: u32, name: &str) -> Result<SymbolIndex> {
    obj.add_symbol(
        ObjSymbol {
            name: name.to_string(),
            address: addr as u64,
            size: 0,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            ..Default::default()
        },
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obj::{
        ObjArchitecture, ObjKind, ObjReloc, ObjRelocKind, ObjRelocations, ObjSection,
        ObjSectionKind, ObjSymbol, ObjSymbolKind,
    };

    /// .pdata word 1 (packed metadata) should not generate relocations,
    /// even when its value falls in a valid code section address range.
    #[test]
    fn test_process_data_skips_pdata_metadata() {
        // .text at 0x80001000, size 0x2000
        let text_data = vec![0x60u8; 0x2000];
        let text_sec = ObjSection {
            name: ".text".to_string(),
            kind: ObjSectionKind::Code,
            address: 0x80001000,
            size: 0x2000,
            data: text_data,
            align: 4,
            elf_index: 0,
            relocations: Default::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        };

        // .pdata at 0x80004000, two 8-byte entries
        // Entry 0: word0 = 0x80001000 (valid .text addr), word1 = 0x80001500 (looks valid but is metadata)
        // Entry 1: word0 = 0x80001100 (valid .text addr), word1 = 0x80002800 (looks valid but is metadata)
        let mut pdata_data = vec![0u8; 0x10];
        pdata_data[0..4].copy_from_slice(&0x80001000u32.to_be_bytes());
        pdata_data[4..8].copy_from_slice(&0x80001500u32.to_be_bytes()); // metadata, NOT an address
        pdata_data[8..12].copy_from_slice(&0x80001100u32.to_be_bytes());
        pdata_data[12..16].copy_from_slice(&0x80002800u32.to_be_bytes()); // metadata, NOT an address
        let pdata_sec = ObjSection {
            name: ".pdata".to_string(),
            kind: ObjSectionKind::ReadOnlyData,
            address: 0x80004000,
            size: 0x10,
            data: pdata_data,
            align: 4,
            elf_index: 1,
            relocations: Default::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        };

        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "test".to_string(),
            vec![],
            vec![text_sec, pdata_sec],
        );

        let mut tracker = Tracker::new(&obj);
        tracker.process_data(&obj, 1, &obj.sections[1]).unwrap();

        // Word 0 offsets (0x80004000, 0x80004008) should have relocations
        let addr0 = SectionAddress::new(1, 0x80004000);
        let addr8 = SectionAddress::new(1, 0x80004008);
        assert!(
            tracker.relocations.contains_key(&addr0),
            "Word 0 of entry 0 should have a relocation"
        );
        assert!(
            tracker.relocations.contains_key(&addr8),
            "Word 0 of entry 1 should have a relocation"
        );

        // Word 1 offsets (0x80004004, 0x8000400C) should NOT have relocations
        let addr4 = SectionAddress::new(1, 0x80004004);
        let addr_c = SectionAddress::new(1, 0x8000400C);
        assert!(
            !tracker.relocations.contains_key(&addr4),
            "Word 1 of entry 0 (metadata) should NOT have a relocation"
        );
        assert!(
            !tracker.relocations.contains_key(&addr_c),
            "Word 1 of entry 1 (metadata) should NOT have a relocation"
        );
    }

    /// Existing source relocations in executable inputs should not panic in debug mode.
    #[test]
    fn test_process_data_tolerates_existing_source_relocation() {
        let text_sec = ObjSection {
            name: ".text".to_string(),
            kind: ObjSectionKind::Code,
            address: 0x80001000,
            size: 0x100,
            data: vec![0x60u8; 0x100],
            align: 4,
            elf_index: 0,
            relocations: Default::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        };

        let mut data_bytes = vec![0u8; 4];
        data_bytes[0..4].copy_from_slice(&0x80001020u32.to_be_bytes());
        let data_sec = ObjSection {
            name: ".data".to_string(),
            kind: ObjSectionKind::Data,
            address: 0x80002000,
            size: 4,
            data: data_bytes,
            align: 4,
            elf_index: 1,
            relocations: Default::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        };

        let symbol = ObjSymbol {
            name: "fn_target".to_string(),
            address: 0x80001020,
            section: Some(0),
            kind: ObjSymbolKind::Function,
            ..Default::default()
        };

        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "test".to_string(),
            vec![symbol],
            vec![text_sec, data_sec],
        );
        obj.sections[1].relocations = ObjRelocations::new(vec![(
            0x80002000,
            ObjReloc {
                kind: ObjRelocKind::Absolute,
                target_symbol: 0,
                addend: 0,
                module: None,
            },
        )])
        .expect("relocation setup should succeed");

        let mut tracker = Tracker::new(&obj);
        tracker
            .process_data(&obj, 1, &obj.sections[1])
            .expect("process_data should not panic on existing source relocation");

        let from = SectionAddress::new(1, 0x80002000);
        let reloc = tracker
            .relocations
            .get(&from)
            .expect("tracker should still record the relocation target");
        match reloc {
            Relocation::Absolute(RelocationTarget::Address(target)) => {
                assert_eq!(*target, SectionAddress::new(0, 0x80001020));
            }
            _ => panic!("expected absolute relocation to .text target"),
        }
    }

    /// REGRESSION, task 161: the executor must not walk out of the function it
    /// was given and evaluate the next function's instructions against the
    /// previous function's bounds.
    ///
    /// This reproduces the dc3 `hostip.obj` shape measured in
    /// `docs/sessions/2026-08-12-splitter-reloc-addend/findings/T2-rel14-rootcause.md`
    /// exactly, at toy addresses:
    ///
    /// ```text
    ///   fn_a  [0x1000, 0x1010)      declared size 0x10
    ///     0x1000  b   +0x40         -> fn_c; StepResult::Jump seeds
    ///                                  possible_missed_branches with 0x1004
    ///     0x1004  nop
    ///     0x1008  nop
    ///     0x100C  0x00000000        inter-function padding; StepResult::Illegal
    ///                                  returns Continue, so the block does NOT end
    ///   fn_b  [0x1010, 0x1040)      a DIFFERENT function, never passed to the tracker
    ///     0x1018  beq +0x10         -> 0x1028, entirely inside fn_b
    /// ```
    ///
    /// Walking the `possible_missed_branches` entry at 0x1004 runs 0x1004, 0x1008,
    /// through the pad at 0x100C and into fn_b. `function_start`/`function_end`
    /// still say `[0x1000, 0x1010)`, so `is_function_addr` answers `false` for
    /// both of fn_b's in-range branch destinations and the intra-function `beq`
    /// at 0x1018 is given a `Rel14` — the exact defect that put a bogus
    /// `PpcRel14 -> Curl_resolv_unlock (+0x34)` in `hostip.obj .text+0x53c`.
    ///
    /// Without `enclosing_function_bounds` feeding `is_function_addr` in
    /// `instruction_callback`, this test fails on the second assertion with
    /// `0:0x1018 -> Rel14(Address(0:0x1028))`.
    #[test]
    fn walk_does_not_escape_function_end_into_the_next_function() {
        const NOP: u32 = 0x6000_0000;
        let words: [u32; 20] = [
            // fn_a [0x1000, 0x1010)
            0x4800_0040, // 0x1000  b +0x40 -> fn_c at 0x1040 (leaves fn_a: Rel24)
            NOP,         // 0x1004
            NOP,         // 0x1008
            0x0000_0000, // 0x100C  padding word -> StepResult::Illegal
            // fn_b [0x1010, 0x1040) -- must not be touched by fn_a's walk
            NOP,         // 0x1010
            NOP,         // 0x1014
            0x4182_0010, // 0x1018  beq +0x10 -> 0x1028, INSIDE fn_b
            NOP,         // 0x101C
            NOP,         // 0x1020
            NOP,         // 0x1024
            NOP,         // 0x1028
            NOP,         // 0x102C
            NOP,         // 0x1030
            NOP,         // 0x1034
            NOP,         // 0x1038
            0x4E80_0020, // 0x103C  blr
            // fn_c [0x1040, 0x1050)
            NOP,         // 0x1040
            NOP,         // 0x1044
            NOP,         // 0x1048
            0x4E80_0020, // 0x104C  blr
        ];
        let data: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let text_sec = ObjSection {
            name: ".text".to_string(),
            kind: ObjSectionKind::Code,
            address: 0x1000,
            size: data.len() as u64,
            data,
            align: 4,
            elf_index: 0,
            relocations: Default::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: Default::default(),
        };

        let mk = |name: &str, address: u64, size: u64| ObjSymbol {
            name: name.to_string(),
            address,
            section: Some(0),
            size,
            size_known: true,
            kind: ObjSymbolKind::Function,
            ..Default::default()
        };
        let fn_a = mk("fn_a", 0x1000, 0x10);
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "runaway".to_string(),
            vec![fn_a.clone(), mk("fn_b", 0x1010, 0x30), mk("fn_c", 0x1040, 0x10)],
            vec![text_sec],
        );

        let mut tracker = Tracker::new(&obj);
        // ONLY fn_a is analysed. Anything the tracker records at an address >=
        // 0x1010 was produced by a walk that left fn_a.
        tracker.process_function(&obj, &fn_a).expect("process_function should succeed");

        // Positive control: the in-bounds analysis still happens. The `b` at
        // 0x1000 genuinely leaves fn_a and must still be relocated, otherwise a
        // test that simply analysed nothing would pass.
        let branch_out = SectionAddress::new(0, 0x1000);
        assert!(
            matches!(
                tracker.relocations.get(&branch_out),
                Some(Relocation::Rel24(RelocationTarget::Address(t)))
                    if *t == SectionAddress::new(0, 0x1040)
            ),
            "the tail branch out of fn_a must still be recorded as Rel24 -> 0x1040, got {:?}",
            tracker.relocations.get(&branch_out)
        );

        let escaped: Vec<_> = tracker
            .relocations
            .range(SectionAddress::new(0, 0x1010)..)
            .map(|(addr, reloc)| format!("{addr} -> {reloc:?}"))
            .collect();
        assert!(
            escaped.is_empty(),
            "the walk of fn_a [0x1000,0x1010) escaped into fn_b and recorded {} \
             relocation(s) against fn_a's bounds: {:?}",
            escaped.len(),
            escaped
        );
    }
}
