use std::{
    collections::{btree_map, BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::{bail, ensure, Context, Result};
// use ppc750cl::{Ins, Opcode};
use powerpc::{Ins, Opcode};

use crate::{
    analysis::{
        cfa::{FunctionInfo, SectionAddress},
        disassemble,
        executor::{ExecCbData, ExecCbResult, Executor},
        uniq_jump_table_entries,
        vm::{section_address_for, BranchTarget, JumpTableType, StepResult, VM},
        RelocationTarget,
    },
    obj::{ObjInfo, ObjKind, ObjSection, ObjSymbolKind},
};

#[derive(Debug, Default, Clone)]
pub struct FunctionSlices {
    pub blocks: BTreeMap<SectionAddress, Option<SectionAddress>>,
    pub branches: BTreeMap<SectionAddress, Vec<SectionAddress>>,
    pub function_references: BTreeSet<SectionAddress>,
    pub jump_table_references: BTreeMap<SectionAddress, u32>,
    pub prologue: Option<SectionAddress>,
    pub epilogue: Option<SectionAddress>,
    // Either a block or tail call
    pub possible_blocks: BTreeMap<SectionAddress, Box<VM>>,
    pub has_conditional_blr: bool,
    pub has_rfi: bool,
    pub finalized: bool,
    pub has_r1_load: bool, // Possibly instead of a prologue
    pub possible_explore_cap_hits: u32,
    pub unvisited_seed_cap_hits: u32,
    pub total_block_cap_hits: u32,
    pub rejected_unvisited_seed_count: u32,
    pub ic_count: u64,
}

pub enum TailCallResult {
    Not,
    Is,
    Possible,
    Error(anyhow::Error),
}

type BlockRange = Range<SectionAddress>;

type InsCheck = dyn Fn(Ins) -> bool;

const MAX_POSSIBLE_BLOCK_EXPLORES_PER_FUNCTION: usize = 512;
const MAX_UNVISITED_SEEDS_PER_FUNCTION: usize = 128;
const MAX_TOTAL_DISCOVERED_BLOCKS_PER_FUNCTION: usize = 4096;
/// Hard cap on instruction-callback invocations during a single
/// `FunctionSlices::analyze` call. Guards against pathological VM-state
/// explosions on Xbox 360 binaries (jump tables and VMX128-heavy regions can
/// cause runaway exploration). Reasonable functions fit in well under 100k.
const MAX_INSTRUCTION_CALLBACKS_PER_FUNCTION: u64 = 5_000_000;

const UNVISITED_SEED_REASON_PDATA_RANGE: u32 = 1 << 0;
const UNVISITED_SEED_REASON_GAP_BOUNDARY: u32 = 1 << 1;
const UNVISITED_SEED_REASON_PROLOGUE_OR_EPILOGUE: u32 = 1 << 2;

/// Stop searching for prologue/epilogue sequences if the next instruction
/// is a branch or uses r0 or r1.
fn is_end_of_seq(next: &Ins) -> bool {
    next.is_branch()
        || next
            .defs()
            .iter()
            .chain(next.uses().iter())
            .any(|a| matches!(a, powerpc::Argument::GPR(powerpc::GPR(0 | 1))))
}

fn is_function_terminator(ins: &Ins) -> bool {
    // blr
    if ins.is_blr() {
        return true;
    }
    // b (not bl/bla)
    if ins.op == Opcode::B && (ins.code & 1) == 0 {
        return true;
    }
    // rfi
    if ins.op == Opcode::Rfi {
        return true;
    }
    // addi r1, r1, SIMM
    if ins.op == Opcode::Addi && ins.field_rd() == 1 && ins.field_ra() == 1 {
        return true;
    }
    // lwz r1, d(rN), N != r1
    if ins.op == Opcode::Lwz && ins.field_rd() == 1 && ins.field_ra() != 1 {
        return true;
    }
    false
}

#[inline(always)]
fn check_sequence(
    section: &ObjSection,
    addr: SectionAddress,
    ins: Option<Ins>,
    sequence: &[(&InsCheck, &InsCheck)],
) -> Result<bool> {
    let ins = ins
        .or_else(|| disassemble(section, addr.address))
        .with_context(|| format!("Failed to disassemble instruction at {addr:#010X}"))?;
    for &(first, second) in sequence {
        if !first(ins) {
            continue;
        }
        let mut current_addr = addr.address + 4;
        while let Some(next) = disassemble(section, current_addr) {
            if second(next) {
                return Ok(true);
            }
            if is_end_of_seq(&next) {
                // If we hit a branch or an instruction that uses r0 or r1, stop searching.
                break;
            }
            current_addr += 4;
        }
    }
    Ok(false)
}

// xbox prologue sequences:
// mfspr r12, LR / stw r12, -0x8(r1)
// mfspr r12, LR / bl saveregintrinsic
// subi r31, r12, XXXX / mfspr r12, LR (unwinds)
fn check_prologue_sequence(
    section: &ObjSection,
    addr: SectionAddress,
    ins: Option<Ins>,
) -> Result<bool> {
    #[inline(always)]
    fn is_mflr(ins: Ins) -> bool {
        // mfspr r0, LR
        ins.op == Opcode::Mfspr && ins.field_rd() == 12 && ins.field_spr() == 8
    }
    #[inline(always)]
    fn is_stwu(ins: Ins) -> bool {
        // stwu[x] r1, d(r1)
        matches!(ins.op, Opcode::Stwu | Opcode::Stwux) && ins.field_rs() == 1 && ins.field_ra() == 1
    }
    #[inline(always)]
    fn is_stw(ins: Ins) -> bool {
        // stw r0, d(r1)
        ins.op == Opcode::Stw && ins.field_rs() == 0 && ins.field_ra() == 1
    }
    #[inline(always)]
    fn is_bl(ins: Ins) -> bool {
        ins.op == Opcode::B && ins.field_lk()
    }
    #[inline(always)]
    fn is_subi(ins: Ins) -> bool {
        ins.op == Opcode::Addi && ins.field_simm() < 0 && ins.field_simm() != -0x8000
    }
    check_sequence(
        section,
        addr,
        ins,
        &[(&is_mflr, &is_stw), (&is_mflr, &is_bl), (&is_subi, &is_mflr)],
    )
}

fn check_epilogue_sequence(
    section: &ObjSection,
    addr: SectionAddress,
    ins: Option<Ins>,
) -> Result<bool> {
    #[inline(always)]
    fn is_mtlr(ins: Ins) -> bool {
        // mtspr LR, r0
        ins.op == Opcode::Mtspr && ins.field_rs() == 12 && ins.field_spr() == 8
    }
    #[inline(always)]
    fn is_addi(ins: Ins) -> bool {
        // addi r1, r1, SIMM
        ins.op == Opcode::Addi && ins.field_rd() == 1 && ins.field_ra() == 1
    }
    #[inline(always)]
    fn is_or(ins: Ins) -> bool {
        // or r1, rA, rB
        ins.op == Opcode::Or && ins.field_rd() == 1
    }
    check_sequence(
        section,
        addr,
        ins,
        &[(&is_mtlr, &is_addi), (&is_mtlr, &is_or), (&is_or, &is_mtlr)],
    )
}

impl FunctionSlices {
    pub fn end(&self) -> Option<SectionAddress> {
        self.blocks.last_key_value().and_then(|(_, &end)| end)
    }

    pub fn start(&self) -> Option<SectionAddress> {
        self.blocks.first_key_value().map(|(&start, _)| start)
    }

    pub fn add_block_start(&mut self, addr: SectionAddress) -> bool {
        if !self.blocks.contains_key(&addr)
            && self.blocks.len() >= MAX_TOTAL_DISCOVERED_BLOCKS_PER_FUNCTION
        {
            self.total_block_cap_hits += 1;
            log::debug!(
                "Block discovery cap reached ({}) while adding {:#010X}",
                MAX_TOTAL_DISCOVERED_BLOCKS_PER_FUNCTION,
                addr
            );
            return false;
        }

        // Slice previous block.
        if let Some((_, end)) = self.blocks.range_mut(..addr).next_back() {
            if let Some(last_end) = *end {
                if last_end > addr {
                    *end = Some(addr);
                    self.blocks.insert(addr, Some(last_end));
                    return false;
                }
            }
        }
        // Otherwise, insert with no end.
        match self.blocks.entry(addr) {
            btree_map::Entry::Vacant(e) => {
                e.insert(None);
                true
            }
            btree_map::Entry::Occupied(_) => false,
        }
    }

    fn check_prologue(
        &mut self,
        section: &ObjSection,
        addr: SectionAddress,
        ins: Ins,
    ) -> Result<()> {
        #[inline(always)]
        fn is_lwz(ins: Ins) -> bool {
            // lwz r1, d(r)
            ins.op == Opcode::Lwz && ins.field_rd() == 1
        }

        if is_lwz(ins) {
            self.has_r1_load = true;
            return Ok(()); // Possibly instead of a prologue
        }
        if check_prologue_sequence(section, addr, Some(ins))? {
            if let Some(prologue) = self.prologue {
                let invalid_seq = if prologue == addr {
                    false
                } else if prologue > addr {
                    true
                } else {
                    // Check if any instruction between the two prologues is a function terminator.
                    let mut current_addr = prologue.address + 4;
                    loop {
                        if current_addr == addr.address {
                            break false;
                        }
                        let next = disassemble(section, current_addr).with_context(|| {
                            format!("Failed to disassemble {current_addr:#010X}")
                        })?;
                        if is_function_terminator(&next) {
                            break true;
                        }
                        current_addr += 4;
                    }
                };
                if invalid_seq {
                    bail!("Found multiple functions inside a symbol: {:#010X} and {:#010X}. Check symbols.txt?", prologue, addr)
                }
            } else {
                self.prologue = Some(addr);
            }
        }
        Ok(())
    }

    fn check_epilogue(
        &mut self,
        section: &ObjSection,
        addr: SectionAddress,
        ins: Ins,
    ) -> Result<()> {
        #[inline(always)]
        fn is_mtlr(ins: Ins) -> bool {
            // mtspr LR, r0
            ins.op == Opcode::Mtspr && ins.field_rs() == 12 && ins.field_spr() == 8
        }
        #[inline(always)]
        fn is_addi(ins: Ins) -> bool {
            // addi r1, r1, SIMM
            ins.op == Opcode::Addi && ins.field_rd() == 1 && ins.field_ra() == 1
        }
        #[inline(always)]
        fn is_or(ins: Ins) -> bool {
            // or r1, rA, rB
            ins.op == Opcode::Or && ins.field_rd() == 1
        }

        if check_sequence(
            section,
            addr,
            Some(ins),
            &[(&is_mtlr, &is_addi), (&is_mtlr, &is_or), (&is_or, &is_mtlr)],
        )? {
            if let Some(epilogue) = self.epilogue {
                if epilogue != addr {
                    bail!("Found duplicate epilogue: {:#010X} and {:#010X}", epilogue, addr)
                }
            } else {
                self.epilogue = Some(addr);
            }
        }
        Ok(())
    }

    fn is_known_function(
        &self,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
        addr: SectionAddress,
    ) -> Option<SectionAddress> {
        if self.function_references.contains(&addr) {
            return Some(addr);
        }
        if let Some((&fn_addr, info)) = known_functions.range(..=addr).next_back() {
            if fn_addr == addr || info.end.is_some_and(|end| addr < end) {
                return Some(fn_addr);
            }
        }
        None
    }

    fn instruction_callback(
        &mut self,
        data: ExecCbData,
        obj: &ObjInfo,
        function_start: SectionAddress,
        function_end: Option<SectionAddress>,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
    ) -> Result<ExecCbResult<bool>> {
        let ExecCbData { executor, vm, result, ins_addr, section, ins, block_start } = data;

        // Hard cap on instruction callbacks per function. RB3 retail's first
        // .text function (and a handful of others) trip a runaway VM state
        // explosion that we haven't fully diagnosed; capping the work lets
        // analysis make progress on the rest of the binary. Functions that
        // hit the cap fall back to pdata-derived bounds via the "Not a
        // function" path (which preserves info.end from pdata in cfa.rs).
        self.ic_count = self.ic_count.wrapping_add(1);
        if self.ic_count > MAX_INSTRUCTION_CALLBACKS_PER_FUNCTION {
            log::warn!(
                "Bailing on function {} after {} instruction callbacks (cap hit at {})",
                function_start, self.ic_count, ins_addr
            );
            return Ok(ExecCbResult::End(false));
        }

        // no need to check for prologues/epilogues in MSVC
        // if a func came from pdata, it not only has a prologue/epilogue, but a known confirmed ending

        if !self.has_conditional_blr && is_conditional_blr(ins) {
            self.has_conditional_blr = true;
        }
        if !self.has_rfi && ins.op == Opcode::Rfi {
            self.has_rfi = true;
        }
        // If control flow hits a block we thought may be a tail call,
        // we know it isn't.
        if self.possible_blocks.contains_key(&ins_addr) {
            self.possible_blocks.remove(&ins_addr);
        }
        if let Some(fn_addr) = self.is_known_function(known_functions, ins_addr) {
            if fn_addr != function_start {
                // debug!, not warn!: this is a recovered condition on a path we
                // take deliberately, and on an XEX it is overwhelmingly benign.
                // Measured on RB3 retail (45410914): 8,564 sites, of which 8,563
                // start at an 8-byte EH prefix (a .text + .rdata pointer pair
                // MSVC emits ahead of a function) and 8,412 reach the real
                // function exactly 8 bytes later. Walking two pointer-words and
                // arriving at the function they precede is the expected outcome,
                // not a warning — and at warn! it survived RUST_LOG=warn, so it
                // was the single largest class a downstream project could not
                // filter out without also hiding real warnings.
                log::debug!(
                    "Control flow from {} hit known function {} (instruction: {})",
                    function_start,
                    fn_addr,
                    ins_addr
                );
                // if we know the function end from pdata, just end the block here and continue processing
                return match function_end {
                    Some(end) => {
                        // Don't record a block that starts at or past
                        // function_end. block_start lives outside our
                        // function (we got here only because the speculative
                        // pass or gap-detection pushed past pdata bounds),
                        // and a zero/negative-width [block_start, end] entry
                        // wedges first_disconnected_block into an
                        // infinite-no-progress loop.
                        if block_start < end {
                            self.blocks.insert(block_start, Some(end));
                        }
                        Ok(ExecCbResult::EndBlock)
                    }
                    None => Ok(ExecCbResult::End(false)),
                };
            }
        }

        match result {
            StepResult::Continue | StepResult::LoadStore { .. } => {
                let next_address = ins_addr + 4;
                // If we already visited the next address, connect the blocks and end
                if executor.visited(section.address as u32, next_address)
                    || self.blocks.contains_key(&next_address)
                {
                    self.blocks.insert(block_start, Some(next_address));
                    self.branches.insert(ins_addr, vec![next_address]);
                    Ok(ExecCbResult::EndBlock)
                } else if function_end.is_some_and(|end| next_address >= end) {
                    self.blocks.insert(block_start, Some(next_address));
                    Ok(ExecCbResult::EndBlock)
                } else {
                    Ok(ExecCbResult::Continue)
                }
            }
            StepResult::Illegal => {
                if ins.code == 0 {
                    log::debug!("Hit zeroed padding @ {:#010X}", ins_addr);
                    Ok(ExecCbResult::End(false))
                } else {
                    log::debug!("Illegal instruction @ {:#010X}", ins_addr);
                    Ok(ExecCbResult::Continue)
                }
            }
            StepResult::Jump(target) => match target {
                BranchTarget::Unknown
                | BranchTarget::Address(RelocationTarget::External)
                | BranchTarget::JumpTable {
                    jump_table_address: RelocationTarget::External, ..
                } => {
                    // Likely end of function
                    let next_addr = ins_addr + 4;
                    self.blocks.insert(block_start, Some(next_addr));
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::Return => {
                    self.blocks.insert(block_start, Some(ins_addr + 4));
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::Address(RelocationTarget::Address(addr)) => {
                    // End of block
                    self.blocks.insert(block_start, Some(ins_addr + 4));
                    self.branches.insert(ins_addr, vec![addr]);
                    if addr == ins_addr {
                        // Infinite loop
                    } else if addr >= function_start
                        && (matches!(function_end, Some(known_end) if addr < known_end)
                            || matches!(self.end(), Some(end) if addr < end)
                            || addr < ins_addr)
                    {
                        // If target is within known function bounds, jump
                        if self.add_block_start(addr) {
                            return Ok(ExecCbResult::Jump(addr));
                        }
                    } else if let Some(fn_addr) = self.is_known_function(known_functions, addr) {
                        ensure!(fn_addr != function_start); // Sanity check
                        self.function_references.insert(fn_addr);
                    } else if addr.section != ins_addr.section
                        // If this branch has zeroed padding after it, assume tail call.
                        || matches!(section.data_range(ins_addr.address, ins_addr.address + 4), Ok(data) if data == [0u8; 4])
                    {
                        self.function_references.insert(addr);
                    } else if function_end.is_some_and(|end| addr >= end) {
                        // pdata (Xbox 360 .pdata or equivalent) gave us an
                        // authoritative function end; an unconditional
                        // forward branch past that end is a tail call to
                        // an out-of-line block or sibling function, not a
                        // possibly-internal block. Treating it as a
                        // possible_block lets the speculative pass trace
                        // past function_end and create blocks beyond it,
                        // which then drives first_disconnected_block into
                        // a degenerate gap that can't be bridged.
                        self.function_references.insert(addr);
                    } else {
                        self.possible_blocks.insert(addr, vm.clone_all());
                    }
                    Ok(ExecCbResult::EndBlock)
                }
                BranchTarget::JumpTable {
                    jump_table_type: jt,
                    jump_table_address: RelocationTarget::Address(address),
                    size,
                } => {
                    log::debug!(
                        "Fetching {} jump table entries @ {} with size {:?}",
                        if jt == JumpTableType::Absolute { "absolute" } else { "relative" },
                        address,
                        size
                    );

                    // Get actual entries and size FIRST, before calculating block end
                    let (entries, actual_size) = uniq_jump_table_entries(
                        obj,
                        address,
                        jt,
                        size,
                        ins_addr,
                        function_start,
                        function_end.or_else(|| self.end()),
                    )?;
                    log::debug!("-> actual size {}: {:?}", actual_size, entries);

                    // Only inline jump tables (immediately after bctr) extend block end.
                    // External jump tables in data sections should not affect block end.
                    let is_inline =
                        jt == JumpTableType::Absolute && address.address == ins_addr.address + 4;
                    let next_addr_size = if is_inline { actual_size } else { 0 };

                    // End of block - now uses actual size for inline tables
                    let next_address = ins_addr + 4 + next_addr_size;
                    self.blocks.insert(block_start, Some(next_address));

                    let max_block = self
                        .blocks
                        .keys()
                        .next_back()
                        .copied()
                        .unwrap_or(next_address)
                        .max(next_address);
                    if entries.iter().any(|&addr| addr > function_start && addr <= max_block)
                        && !entries.iter().any(|&addr| {
                            self.is_known_function(known_functions, addr)
                                .is_some_and(|fn_addr| fn_addr != function_start)
                        })
                    {
                        self.jump_table_references.insert(address, actual_size);
                        let mut branches = vec![];
                        for addr in entries {
                            branches.push(addr);
                            if self.add_block_start(addr) {
                                executor.push(addr, vm.clone_all(), true);
                            }
                        }
                        self.branches.insert(ins_addr, branches);
                    } else {
                        // If the table doesn't contain the next address,
                        // it could be a function jump table instead.
                        // Entries past a pdata-known function_end are
                        // sibling functions, not possibly-internal blocks
                        // (same rationale as the unconditional-branch
                        // path above).
                        for entry in entries {
                            if function_end.is_some_and(|end| entry >= end) {
                                self.function_references.insert(entry);
                            } else {
                                self.possible_blocks.insert(entry, vm.clone_all());
                            }
                        }
                    }
                    Ok(ExecCbResult::EndBlock)
                }
            },
            StepResult::Branch(branches) => {
                // End of block
                self.blocks.insert(block_start, Some(ins_addr + 4));

                let mut out_branches = vec![];
                for branch in branches {
                    match branch.target {
                        BranchTarget::Address(RelocationTarget::Address(addr)) => {
                            let known = self.is_known_function(known_functions, addr);
                            if let Some(fn_addr) = known {
                                if fn_addr != function_start {
                                    self.function_references.insert(fn_addr);
                                    continue;
                                }
                            }
                            if branch.link {
                                // See if any existing functions contain this address,
                                // since this could be a label inside a larger function.
                                let last_function = obj
                                    .symbols
                                    .for_section_range(addr.section, ..addr.address)
                                    .rfind(|(_, symbol)| symbol.kind == ObjSymbolKind::Function);
                                match last_function {
                                    Some((_, symbol))
                                        if symbol.address + symbol.size > addr.address as u64 =>
                                    {
                                        // Set the function reference to the start of the function
                                        self.function_references.insert(SectionAddress::new(
                                            addr.section,
                                            symbol.address as u32,
                                        ))
                                    }
                                    _ => self.function_references.insert(addr),
                                };
                            } else {
                                // MSVC likes to end functions with bl sometimes
                                // this lil hack will stop a new block from being added
                                // if the current addr goes beyond our known function end addr
                                // this should help our funcs from pdata that end in bl's
                                if function_end.is_none_or(|end| addr < end) {
                                    out_branches.push(addr);
                                    if self.add_block_start(addr) {
                                        executor.push(addr, branch.vm, true);
                                    }
                                }
                            }
                        }
                        BranchTarget::JumpTable {
                            jump_table_type: _,
                            jump_table_address: address,
                            size,
                        } => {
                            bail!(
                                "Conditional jump table unsupported @ {:#010X} -> {:?} size {:#X?}",
                                ins_addr,
                                address,
                                size
                            );
                        }
                        _ => continue,
                    }
                }
                if !out_branches.is_empty() {
                    self.branches.insert(ins_addr, out_branches);
                }
                Ok(ExecCbResult::EndBlock)
            }
        }
    }

    pub fn analyze(
        &mut self,
        obj: &ObjInfo,
        start: SectionAddress,
        function_start: SectionAddress,
        function_end: Option<SectionAddress>,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
        vm: Option<Box<VM>>,
    ) -> Result<bool> {
        if !self.add_block_start(start) {
            return Ok(true);
        }

        let mut executor = Executor::new(obj);
        executor.push(start, vm.unwrap_or_else(|| VM::new_from_obj(obj)), false);
        let result = executor.run(obj, |data| {
            self.instruction_callback(data, obj, function_start, function_end, known_functions)
        })?;
        if matches!(result, Some(b) if !b) {
            return Ok(false);
        }

        // Visit unreachable blocks
        while let Some((first, _)) = self.first_disconnected_block() {
            let vm = self.possible_blocks.remove(&first.start);
            executor.push(first.end, vm.unwrap_or_else(|| VM::new_from_obj(obj)), true);

            match executor.run(obj, |data| {
                self.instruction_callback(data, obj, function_start, function_end, known_functions)
            })? {
                Some(true) => continue,
                Some(false) => return Ok(false),
                None => break,
            }

            // let result = executor.run(obj, |data| {
            //     self.instruction_callback(data, obj, function_start, function_end, known_functions)
            // })?;
            // if matches!(result, Some(b) if !b) {
            //     return Ok(false);
            // }
        }

        let mut possible_block_explores = 0usize;
        let mut unvisited_seed_count = 0usize;

        // Speculatively follow possible_blocks entries.
        // These are forward branches that couldn't be proven internal during Pass 1
        // (because they're beyond the currently-known function end). Common case:
        // bctrl (opaque indirect call) followed by b <epilogue>, where the epilogue
        // is a forward branch to code that restores the stack and returns.
        // Following these entries extends the function bounds, which may reveal gaps
        // (between the branch and its target) that contain unreachable but valid code
        // such as switch dispatch blocks or tail blocks.
        loop {
            if possible_block_explores >= MAX_POSSIBLE_BLOCK_EXPLORES_PER_FUNCTION {
                self.possible_explore_cap_hits += 1;
                let dropped = self.possible_blocks.len();
                self.possible_blocks.clear();
                log::debug!(
                    "Reached possible-block exploration cap ({}) for function {:#010X}; dropped {} unresolved candidates",
                    MAX_POSSIBLE_BLOCK_EXPLORES_PER_FUNCTION,
                    function_start,
                    dropped
                );
                break;
            }
            let Some((&addr, _)) = self.possible_blocks.first_key_value() else { break };
            possible_block_explores += 1;
            let vm = self.possible_blocks.remove(&addr).unwrap();
            if !self.add_block_start(addr) {
                continue;
            }
            executor.push(addr, vm, true);
            if matches!(
                executor.run(obj, |data| {
                    self.instruction_callback(
                        data,
                        obj,
                        function_start,
                        function_end,
                        known_functions,
                    )
                })?,
                Some(false)
            ) {
                return Ok(false);
            }
            // Block processed. Re-run gap detection since function bounds may have extended.
            while let Some((first, _)) = self.first_disconnected_block() {
                let gap_vm = self.possible_blocks.remove(&first.start);
                executor.push(first.end, gap_vm.unwrap_or_else(|| VM::new_from_obj(obj)), true);
                if matches!(
                    executor.run(obj, |data| {
                        self.instruction_callback(
                            data,
                            obj,
                            function_start,
                            function_end,
                            known_functions,
                        )
                    })?,
                    Some(false)
                ) {
                    return Ok(false);
                }
            }
        }

        // Scan for unvisited code inside the current function range. This catches
        // .pdata-covered helper/handler blocks with no CFG edge from entry.
        let scan_end = self.scan_end(obj, function_start, function_end, known_functions);
        let mut scan_cursor = function_start;
        while let Some(candidate) = self.next_unvisited_candidate(obj, scan_cursor, scan_end) {
            if unvisited_seed_count >= MAX_UNVISITED_SEEDS_PER_FUNCTION {
                self.unvisited_seed_cap_hits += 1;
                log::debug!(
                    "Reached unvisited-seed cap ({}) for function {:#010X}",
                    MAX_UNVISITED_SEEDS_PER_FUNCTION,
                    function_start
                );
                break;
            }
            let reason_flags =
                self.unvisited_seed_reason_flags(obj, candidate, function_start, function_end)?;
            if reason_flags == 0 {
                self.rejected_unvisited_seed_count += 1;
                log::debug!(
                    "Rejected unvisited seed @ {:#010X} in function {:#010X}: no corroborators",
                    candidate,
                    function_start
                );
                scan_cursor = candidate + 4;
                continue;
            }

            if self.add_block_start(candidate) {
                unvisited_seed_count += 1;
                log::debug!(
                    "Accepted unvisited seed @ {:#010X} in function {:#010X} with reason flags {:#X}",
                    candidate,
                    function_start,
                    reason_flags
                );
                executor.push(candidate, VM::new_from_obj(obj), true);
                if matches!(
                    executor.run(obj, |data| {
                        self.instruction_callback(
                            data,
                            obj,
                            function_start,
                            function_end,
                            known_functions,
                        )
                    })?,
                    Some(false)
                ) {
                    return Ok(false);
                }

                // Re-run disconnected/possible block processing after each seeded block.
                while let Some((first, _)) = self.first_disconnected_block() {
                    let gap_vm = self.possible_blocks.remove(&first.start);
                    executor.push(first.end, gap_vm.unwrap_or_else(|| VM::new_from_obj(obj)), true);
                    if matches!(
                        executor.run(obj, |data| {
                            self.instruction_callback(
                                data,
                                obj,
                                function_start,
                                function_end,
                                known_functions,
                            )
                        })?,
                        Some(false)
                    ) {
                        return Ok(false);
                    }
                }

                loop {
                    if possible_block_explores >= MAX_POSSIBLE_BLOCK_EXPLORES_PER_FUNCTION {
                        self.possible_explore_cap_hits += 1;
                        let dropped = self.possible_blocks.len();
                        self.possible_blocks.clear();
                        log::debug!(
                            "Reached possible-block exploration cap ({}) for function {:#010X}; dropped {} unresolved candidates",
                            MAX_POSSIBLE_BLOCK_EXPLORES_PER_FUNCTION,
                            function_start,
                            dropped
                        );
                        break;
                    }
                    let Some((&addr, _)) = self.possible_blocks.first_key_value() else { break };
                    possible_block_explores += 1;
                    let vm = self.possible_blocks.remove(&addr).unwrap();
                    if !self.add_block_start(addr) {
                        continue;
                    }
                    executor.push(addr, vm, true);
                    if matches!(
                        executor.run(obj, |data| {
                            self.instruction_callback(
                                data,
                                obj,
                                function_start,
                                function_end,
                                known_functions,
                            )
                        })?,
                        Some(false)
                    ) {
                        return Ok(false);
                    }
                    while let Some((first, _)) = self.first_disconnected_block() {
                        let gap_vm = self.possible_blocks.remove(&first.start);
                        executor.push(
                            first.end,
                            gap_vm.unwrap_or_else(|| VM::new_from_obj(obj)),
                            true,
                        );
                        if matches!(
                            executor.run(obj, |data| {
                                self.instruction_callback(
                                    data,
                                    obj,
                                    function_start,
                                    function_end,
                                    known_functions,
                                )
                            })?,
                            Some(false)
                        ) {
                            return Ok(false);
                        }
                    }
                }
            }

            scan_cursor = self.block_end_containing(candidate).unwrap_or(candidate + 4);
        }

        if self.possible_explore_cap_hits > 0
            || self.unvisited_seed_cap_hits > 0
            || self.total_block_cap_hits > 0
            || self.rejected_unvisited_seed_count > 0
        {
            log::debug!(
                "Function {:#010X} analysis counters: possible_cap_hits={}, unvisited_cap_hits={}, total_block_cap_hits={}, rejected_unvisited_seeds={}",
                function_start,
                self.possible_explore_cap_hits,
                self.unvisited_seed_cap_hits,
                self.total_block_cap_hits,
                self.rejected_unvisited_seed_count
            );
        }

        // Visit trailing blocks
        if let Some(known_end) = function_end {
            'outer: loop {
                let Some(mut end) = self.end() else {
                    log::warn!("Trailing block analysis failed @ {:#010X}", function_start);
                    break;
                };
                loop {
                    if end >= known_end {
                        break 'outer;
                    }
                    // Skip nops
                    match disassemble(&obj.sections[end.section], end.address) {
                        Some(ins) => {
                            if ins.op != Opcode::Illegal && !is_nop(ins) {
                                break;
                            }
                        }
                        _ => break,
                    }
                    end += 4;
                }
                executor.push(end, VM::new_from_obj(obj), true);
                match executor.run(obj, |data| {
                    self.instruction_callback(
                        data,
                        obj,
                        function_start,
                        function_end,
                        known_functions,
                    )
                })? {
                    Some(true) => continue,
                    Some(false) => return Ok(false),
                    None => break 'outer,
                }
            }
        }

        // Sanity check. Malformed seeds / branch targets can leave an out-of-bounds
        // block start behind (especially on older split baselines). Prune those
        // instead of aborting the entire XEX split. Still fail on unresolved
        // in-range blocks, which indicate a real analysis bug.
        let mut invalid_block_starts = Vec::new();
        for (&start, &end) in &self.blocks {
            if end.is_some() {
                continue;
            }
            let section = &obj.sections[start.section];
            if !section.contains(start.address) {
                log::warn!(
                    "Dropping out-of-bounds unfinished block @ {:#010X} in section {} ({:#010X}-{:#010X})",
                    start,
                    section.name,
                    section.address,
                    section.address + section.size
                );
                invalid_block_starts.push(start);
                continue;
            }
            ensure!(false, "Failed to finalize block @ {start:#010X}");
        }
        for start in invalid_block_starts {
            self.blocks.remove(&start);
            self.branches.remove(&start);
            self.possible_blocks.remove(&start);
        }

        Ok(true)
    }

    pub fn can_finalize(&self) -> bool {
        self.possible_blocks.is_empty()
    }

    pub fn finalize(
        &mut self,
        obj: &ObjInfo,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
    ) -> Result<()> {
        ensure!(!self.finalized, "Already finalized");
        ensure!(self.can_finalize(), "Can't finalize");

        match (self.prologue, self.epilogue, self.has_r1_load) {
            (Some(_), Some(_), _) | (None, None, _) => {}
            (Some(_), None, _) => {
                // Likely __noreturn
            }
            (None, Some(e), false) => {
                log::warn!("{:#010X?}", self);
                bail!("Unpaired epilogue {:#010X}", e);
            }
            (None, Some(_), true) => {
                // Possible stack setup
            }
        }

        let Some(end) = self.end() else {
            bail!("Can't finalize function without known end: {:#010X?}", self.start())
        };
        // TODO: rework to make compatible with relocatable objects
        if obj.kind == ObjKind::Executable {
            match (
                (end.section, &obj.sections[end.section]),
                obj.sections.at_address(end.address - 4),
            ) {
                ((section_index, section), Ok((other_section_index, _other_section)))
                    if section_index == other_section_index =>
                {
                    // FIXME this is real bad
                    if !self.has_conditional_blr {
                        let ins_addr = end - 4;
                        if let Some(ins) = disassemble(section, ins_addr.address) {
                            if ins.op == Opcode::B {
                                if let Some(RelocationTarget::Address(target)) = ins
                                    .branch_dest(ins_addr.address)
                                    .and_then(|addr| section_address_for(obj, ins_addr, addr))
                                {
                                    if self.function_references.contains(&target) {
                                        for branches in self.branches.values() {
                                            if branches.len() > 1
                                                && branches.contains(
                                                    self.blocks.last_key_value().unwrap().0,
                                                )
                                            {
                                                self.has_conditional_blr = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // MWCC optimization sometimes leaves an unreachable blr
                    // after generating a conditional blr in the function.
                    if self.has_conditional_blr
                        && matches!(disassemble(section, end.address - 4), Some(ins) if !ins.is_blr())
                        && matches!(disassemble(section, end.address), Some(ins) if ins.is_blr())
                        && !known_functions.contains_key(&end)
                    {
                        log::trace!("Found trailing blr @ {:#010X}, merging with function", end);
                        self.blocks.insert(end, Some(end + 4));
                    }

                    // Some functions with rfi also include a trailing nop
                    if self.has_rfi
                        && matches!(disassemble(section, end.address), Some(ins) if is_nop(ins))
                        && !known_functions.contains_key(&end)
                    {
                        log::trace!("Found trailing nop @ {:#010X}, merging with function", end);
                        self.blocks.insert(end, Some(end + 4));
                    }
                }
                _ => {}
            }
        }

        self.finalized = true;

        Ok(())
    }

    pub fn check_tail_call(
        &mut self,
        obj: &ObjInfo,
        addr: SectionAddress,
        function_start: SectionAddress,
        function_end: Option<SectionAddress>,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
        vm: Option<Box<VM>>,
    ) -> TailCallResult {
        // TODO: check if jump target is a reg intrinsic, as if it is, it might *not* be a tail call
        // you'd also have to check if there are visited addresses that go beyond the addr of the jump instruction

        // If this function came from .pdata, prefer the known bounds over tail-call heuristics.
        if obj.pdata_funcs.contains(&function_start) {
            return TailCallResult::Not;
        }

        // If jump target is already a known block or within known function bounds, not a tail call.
        if self.blocks.contains_key(&addr) {
            return TailCallResult::Not;
        }
        if let Some(function_end) = function_end {
            if addr >= function_start && addr < function_end {
                return TailCallResult::Not;
            }
        }
        // If there's a prologue in the current function, not a tail call.
        if self.prologue.is_some() {
            return TailCallResult::Not;
        }
        // If jump target is before the start of the function, known tail call.
        if addr < function_start {
            return TailCallResult::Is;
        }
        // If the jump target is in a different section, known tail call.
        if addr.section != function_start.section {
            return TailCallResult::Is;
        }
        // If the jump target has 0'd padding before it, known tail call.
        let target_section = &obj.sections[addr.section];
        if matches!(target_section.data_range(addr.address - 4, addr.address), Ok(data) if data == [0u8; 4])
        {
            return TailCallResult::Is;
        }
        // If we're not sure where the function ends yet, mark as possible tail call.
        // let end = self.end();
        if function_end.is_none() {
            return TailCallResult::Possible;
        }
        // If jump target is known to be a function, or there's a function in between
        // this and the jump target, known tail call.
        if self.function_references.range(function_start + 4..=addr).next().is_some()
            || known_functions.range(function_start + 4..=addr).next().is_some()
        {
            return TailCallResult::Is;
        }
        // If we haven't discovered a prologue yet, and one exists between the function
        // start and the jump target, known tail call.
        if self.prologue.is_none() {
            let mut current_address = function_start;
            while current_address < addr {
                match check_prologue_sequence(target_section, current_address, None) {
                    Ok(true) => {
                        log::debug!(
                            "Prologue discovered @ {}; known tail call: {}",
                            current_address,
                            addr
                        );
                        return TailCallResult::Is;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        log::warn!("Error while checking prologue sequence: {}", e);
                        return TailCallResult::Error(e);
                    }
                }
                current_address += 4;
            }
        }
        // Perform CFA on jump target to determine more
        let mut slices = FunctionSlices {
            function_references: self.function_references.clone(),
            ..Default::default()
        };
        if let Ok(result) =
            slices.analyze(obj, addr, function_start, function_end, known_functions, vm)
        {
            // If analysis failed, assume tail call.
            if !result {
                log::warn!("Tail call analysis failed for {:#010X}", addr);
                return TailCallResult::Is;
            }
            // If control flow jumps below the entry point, not a tail call.
            let start = slices.start().unwrap();
            if start < addr {
                log::trace!("Tail call possibility eliminated: {:#010X} < {:#010X}", start, addr);
                return TailCallResult::Not;
            }
            // If control flow includes another possible tail call, we know both are not tail calls.
            if let Some(end) = slices.end() {
                // TODO idk if wrapping this is right
                let other_blocks = self
                    .possible_blocks
                    .range(start + 4..end)
                    .map(|(&addr, _)| addr)
                    .collect::<Vec<SectionAddress>>();
                if !other_blocks.is_empty() {
                    for other_addr in other_blocks {
                        log::trace!("Logically eliminating {:#010X}", other_addr);
                        self.possible_blocks.remove(&other_addr);
                        // self.add_block_start(oth);
                    }
                    log::trace!("While analyzing {:#010X}", addr);
                    return TailCallResult::Not;
                }
            }
            // If we discovered a function prologue, known tail call.
            if slices.prologue.is_some() || slices.has_r1_load {
                log::trace!("Prologue discovered; known tail call: {:#010X}", addr);
                return TailCallResult::Is;
            }
        }
        // If all else fails, try again later.
        TailCallResult::Possible
    }

    pub fn first_disconnected_block(&self) -> Option<(BlockRange, BlockRange)> {
        let mut iter = self.blocks.iter().peekable();
        loop {
            let ((first_begin, first_end), (second_begin, second_end)) =
                match (iter.next(), iter.peek()) {
                    (Some((&b1s, &Some(b1e))), Some(&(&b2s, &Some(b2e)))) => {
                        ((b1s, b1e), (b2s, b2e))
                    }
                    (Some(_), Some(_)) => continue,
                    _ => break None,
                };
            if second_begin > first_end {
                break Some((first_begin..first_end, second_begin..second_end));
            }
        }
    }

    fn block_end_containing(&self, addr: SectionAddress) -> Option<SectionAddress> {
        let (&start, &end) = self.blocks.range(..=addr).next_back()?;
        let end = end?;
        if addr >= start && addr < end {
            Some(end)
        } else {
            None
        }
    }

    fn jump_table_end_containing(&self, addr: SectionAddress) -> Option<SectionAddress> {
        let (&jt_addr, &size) = self.jump_table_references.range(..=addr).next_back()?;
        if jt_addr.section != addr.section {
            return None;
        }
        let jt_end = jt_addr + size;
        if addr >= jt_addr && addr < jt_end {
            Some(jt_end)
        } else {
            None
        }
    }

    fn is_adjacent_to_block_gap_boundary(&self, candidate: SectionAddress) -> bool {
        if let Some((_, &Some(prev_end))) = self.blocks.range(..=candidate).next_back() {
            if prev_end == candidate {
                return true;
            }
        }
        let next_addr = candidate + 4;
        if let Some((&next_start, _)) = self.blocks.range(next_addr..).next() {
            if next_start == next_addr {
                return true;
            }
        }
        false
    }

    fn unvisited_seed_reason_flags(
        &self,
        obj: &ObjInfo,
        candidate: SectionAddress,
        function_start: SectionAddress,
        function_end: Option<SectionAddress>,
    ) -> Result<u32> {
        let mut reason_flags = 0u32;

        if obj.pdata_funcs.contains(&function_start)
            && function_end.is_some_and(|end| candidate >= function_start && candidate < end)
        {
            reason_flags |= UNVISITED_SEED_REASON_PDATA_RANGE;
        }

        if self.is_adjacent_to_block_gap_boundary(candidate) {
            reason_flags |= UNVISITED_SEED_REASON_GAP_BOUNDARY;
        }

        let section = &obj.sections[candidate.section];
        if let Some(ins) = disassemble(section, candidate.address) {
            if check_prologue_sequence(section, candidate, Some(ins))?
                || check_epilogue_sequence(section, candidate, Some(ins))?
            {
                reason_flags |= UNVISITED_SEED_REASON_PROLOGUE_OR_EPILOGUE;
            }
        }

        Ok(reason_flags)
    }

    fn scan_end(
        &self,
        obj: &ObjInfo,
        function_start: SectionAddress,
        function_end: Option<SectionAddress>,
        known_functions: &BTreeMap<SectionAddress, FunctionInfo>,
    ) -> SectionAddress {
        let section = &obj.sections[function_start.section];
        let section_start = SectionAddress::new(function_start.section, section.address as u32);
        let section_end = section_start + section.size as u32;

        let mut end = function_end.unwrap_or(section_end);
        if end > section_end {
            end = section_end;
        }

        // No known end: don't scan across the next known function boundary.
        if function_end.is_none() {
            if let Some((&next_start, _)) =
                known_functions.range(function_start + 4..section_end).next()
            {
                if next_start.section == function_start.section && next_start < end {
                    end = next_start;
                }
            }
        }
        end
    }

    fn next_unvisited_candidate(
        &self,
        obj: &ObjInfo,
        mut addr: SectionAddress,
        end: SectionAddress,
    ) -> Option<SectionAddress> {
        while addr < end {
            if let Some(block_end) = self.block_end_containing(addr) {
                addr = block_end;
                continue;
            }
            if let Some(jt_end) = self.jump_table_end_containing(addr) {
                addr = jt_end;
                continue;
            }
            let ins = disassemble(&obj.sections[addr.section], addr.address)?;
            if ins.op != Opcode::Illegal && ins.code != 0 && !is_nop(ins) {
                return Some(addr);
            }
            addr += 4;
        }
        None
    }
}

#[inline]
fn is_conditional_blr(ins: Ins) -> bool {
    ins.op == Opcode::Bclr && ins.field_bo() & 0b10100 != 0b10100
}

#[inline]
fn is_nop(ins: Ins) -> bool {
    // ori r0, r0, 0
    ins.code == 0x60000000
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        FunctionSlices, TailCallResult, MAX_POSSIBLE_BLOCK_EXPLORES_PER_FUNCTION,
        MAX_TOTAL_DISCOVERED_BLOCKS_PER_FUNCTION,
    };
    use crate::{
        analysis::{cfa::SectionAddress, vm::VM},
        obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind},
    };

    fn make_code_section(name: &str, base_addr: u32, instructions: &[u32]) -> ObjSection {
        let data: Vec<u8> = instructions.iter().flat_map(|ins| ins.to_be_bytes()).collect();
        ObjSection {
            name: name.into(),
            kind: ObjSectionKind::Code,
            address: base_addr as u64,
            size: data.len() as u64,
            data,
            align: 4,
            ..Default::default()
        }
    }

    fn build_tail_call_fixture(marked_in_pdata: bool) -> (ObjInfo, SectionAddress, SectionAddress) {
        let code_section = make_code_section(".text", 0x1000, &[0x6000_0000; 0x20]);
        let other_code_section = make_code_section(".text$x", 0x2000, &[0x6000_0000; 4]);
        let function_start = SectionAddress::new(0, 0x1008);
        let function_end = SectionAddress::new(0, 0x1040);

        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "tail-call-fixture".into(),
            vec![],
            vec![code_section, other_code_section],
        );
        if marked_in_pdata {
            obj.pdata_funcs.push(function_start);
        }
        (obj, function_start, function_end)
    }

    #[test]
    fn tail_call_guard_pdata_known_function_returns_not() {
        let (obj, function_start, function_end) = build_tail_call_fixture(true);
        let mut slices = FunctionSlices::default();
        let known_functions = BTreeMap::new();
        let cross_section_target = SectionAddress::new(1, 0x2000);

        let result = slices.check_tail_call(
            &obj,
            cross_section_target,
            function_start,
            Some(function_end),
            &known_functions,
            None,
        );

        assert!(matches!(result, TailCallResult::Not));
    }

    #[test]
    fn tail_call_non_pdata_path_preserves_existing_heuristic() {
        let (obj, function_start, function_end) = build_tail_call_fixture(false);
        let mut slices = FunctionSlices::default();
        let known_functions = BTreeMap::new();
        let cross_section_target = SectionAddress::new(1, 0x2000);

        let result = slices.check_tail_call(
            &obj,
            cross_section_target,
            function_start,
            Some(function_end),
            &known_functions,
            None,
        );

        assert!(matches!(result, TailCallResult::Is));
    }

    #[test]
    fn tail_call_guard_pdata_precedes_all_other_heuristics() {
        let (mut obj, function_start, function_end) = build_tail_call_fixture(true);
        let before_function_target = SectionAddress::new(0, 0x1004);
        let known_functions = BTreeMap::new();

        let mut slices = FunctionSlices::default();
        let guarded_result = slices.check_tail_call(
            &obj,
            before_function_target,
            function_start,
            Some(function_end),
            &known_functions,
            None,
        );
        assert!(matches!(guarded_result, TailCallResult::Not));

        obj.pdata_funcs.clear();
        let mut slices_without_guard = FunctionSlices::default();
        let heuristic_result = slices_without_guard.check_tail_call(
            &obj,
            before_function_target,
            function_start,
            Some(function_end),
            &known_functions,
            None,
        );
        assert!(matches!(heuristic_result, TailCallResult::Is));
    }

    #[test]
    fn speculative_possible_block_exploration_honors_cap() {
        let instruction_count = MAX_POSSIBLE_BLOCK_EXPLORES_PER_FUNCTION + 256;
        let code_section =
            make_code_section(".text", 0x3000, &vec![0x4E80_0020; instruction_count]);
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "possible-cap".into(),
            vec![],
            vec![code_section],
        );

        let mut slices = FunctionSlices::default();
        for i in 1..(MAX_POSSIBLE_BLOCK_EXPLORES_PER_FUNCTION + 128) {
            let addr = SectionAddress::new(0, 0x3000 + (i as u32 * 4));
            slices.possible_blocks.insert(addr, VM::new_from_obj(&obj));
        }

        let function_start = SectionAddress::new(0, 0x3000);
        let analyzed = slices
            .analyze(
                &obj,
                function_start,
                function_start,
                Some(function_start + 4),
                &BTreeMap::new(),
                None,
            )
            .expect("analysis should not error");
        assert!(analyzed);
        assert!(slices.possible_explore_cap_hits > 0);
        assert!(slices.blocks.len() <= MAX_TOTAL_DISCOVERED_BLOCKS_PER_FUNCTION);
    }

    #[test]
    fn unvisited_seed_discovers_detached_helper_in_pdata_range() {
        let instructions = [
            0x4E80_0020, // blr
            0x6000_0000,
            0x6000_0000,
            0x6000_0000,
            0x4E80_0020, // detached helper blr at +0x10
            0x6000_0000,
            0x6000_0000,
            0x6000_0000,
        ];
        let code_section = make_code_section(".text", 0x4000, &instructions);
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "pdata-detached".into(),
            vec![],
            vec![code_section],
        );

        let function_start = SectionAddress::new(0, 0x4000);
        obj.pdata_funcs.push(function_start);
        let function_end = SectionAddress::new(0, 0x4020);

        let mut slices = FunctionSlices::default();
        let analyzed = slices
            .analyze(
                &obj,
                function_start,
                function_start,
                Some(function_end),
                &BTreeMap::new(),
                None,
            )
            .expect("analysis should not error");
        assert!(analyzed);
        assert!(slices.blocks.contains_key(&SectionAddress::new(0, 0x4010)));
    }

    #[test]
    fn unvisited_seed_rejects_embedded_data_without_corroborator() {
        let instructions = [
            0x4E80_0020, // blr
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
            0x6042_0001, // ori r2, r2, 1 (data-like legal instruction)
            0x0000_0000,
            0x0000_0000,
            0x0000_0000,
        ];
        let code_section = make_code_section(".text", 0x5000, &instructions);
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "embedded-data".into(),
            vec![],
            vec![code_section],
        );

        let function_start = SectionAddress::new(0, 0x5000);
        let mut slices = FunctionSlices::default();
        let analyzed = slices
            .analyze(&obj, function_start, function_start, None, &BTreeMap::new(), None)
            .expect("analysis should not error");
        assert!(analyzed);
        assert!(!slices.blocks.contains_key(&SectionAddress::new(0, 0x5010)));
        assert!(slices.rejected_unvisited_seed_count > 0);
    }

    #[test]
    fn add_block_start_caps_total_discovered_blocks() {
        let mut slices = FunctionSlices::default();
        for i in 0..(MAX_TOTAL_DISCOVERED_BLOCKS_PER_FUNCTION + 64) {
            let _ = slices.add_block_start(SectionAddress::new(0, 0x6000 + (i as u32 * 4)));
        }
        assert_eq!(slices.blocks.len(), MAX_TOTAL_DISCOVERED_BLOCKS_PER_FUNCTION);
        assert!(slices.total_block_cap_hits > 0);
    }

    // Regression test for the RB3 retail XEX hang observed at seed
    // 0x82273B58 (dtk xex split stuck at ~99% CPU, no progress, 5+ minutes).
    //
    // Chain of events:
    //   1. Function A spans [0x1000, 0x1040] per pdata. A has a forward
    //      unconditional branch to 0x1080 — past function_end — which lands
    //      in possible_blocks.
    //   2. Another known function B starts exactly at 0x1040 (== A's
    //      function_end). On Xbox 360 .text this is the common case:
    //      pdata-driven adjacent functions.
    //   3. The speculative pass pops 0x1080 from possible_blocks and traces
    //      it, creating a block [0x1080, 0x1084] past function_end.
    //   4. The post-speculative gap-detection loop sees a gap between the
    //      last in-function block (ending at function_end) and the new
    //      out-of-function block, and pushes the executor at first.end =
    //      function_end = 0x1040.
    //   5. The executor starts a block walk at 0x1040, where
    //      is_known_function reports function B. The "control flow hit a
    //      known function" branch in instruction_callback then inserts
    //      blocks[block_start = 0x1040] = Some(function_end = 0x1040) — a
    //      ZERO-WIDTH block.
    //   6. The inner gap-detection loop now returns the zero-width block
    //      as `first`. It pushes the executor at first.end = first.start =
    //      0x1040, but that address is already visited — executor.run
    //      returns Ok(None) without doing any work. blocks/possible_blocks
    //      are unchanged, so the same gap is returned on the next
    //      iteration. Infinite loop.
    //
    // With the fix in place, analyze() terminates promptly. We run it on a
    // worker thread guarded by a 10-second deadline: a healthy run is
    // sub-millisecond, while the bug hangs forever.
    #[test]
    fn gap_detection_terminates_when_pdata_neighbor_sits_at_function_end() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        use std::thread;
        use std::time::{Duration, Instant};

        use crate::analysis::cfa::FunctionInfo;

        // Instructions (relative to base 0x1000):
        //   0x1000: b 0x1080   (forward branch past function_end → possible_blocks)
        //   0x1004..0x107C:    nops (executor will trace through these from 0x1004,
        //                       so the gap between blocks closes naturally)
        //   0x1080:            blr  (epilogue for the out-of-bounds tail block)
        let nop: u32 = 0x6000_0000;
        let blr: u32 = 0x4E80_0020;
        let b_to_0x1080_from_0x1000: u32 = 0x4800_0080; // I-form, +0x80 offset, no AA/LK
        let mut words = vec![nop; 0x21];
        words[0] = b_to_0x1080_from_0x1000;
        words[0x20] = blr;

        let code_section = make_code_section(".text", 0x1000, &words);
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "rb3-xenon-hang-repro".into(),
            vec![],
            vec![code_section],
        );

        let function_start = SectionAddress::new(0, 0x1000);
        let function_end = SectionAddress::new(0, 0x1040);

        // Function B (a separate known function) starts at A's function_end.
        let mut known_functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
        known_functions.insert(
            SectionAddress::new(0, 0x1040),
            FunctionInfo {
                analyzed: false,
                end: Some(SectionAddress::new(0, 0x1080)),
                slices: None,
            },
        );

        // Run analyze on a worker thread so we can enforce a deadline.
        // Use a flag to abandon the thread if it hangs — we can't kill it,
        // but at least the test fails fast and reports the bug.
        let finished = Arc::new(AtomicBool::new(false));
        let finished_for_thread = finished.clone();
        let handle = thread::Builder::new()
            .name("hang-repro-worker".into())
            .spawn(move || {
                let mut slices = FunctionSlices::default();
                let result = slices.analyze(
                    &obj,
                    function_start,
                    function_start,
                    Some(function_end),
                    &known_functions,
                    None,
                );
                finished_for_thread.store(true, Ordering::Release);
                (result, slices)
            })
            .expect("spawn worker");

        let deadline = Instant::now() + Duration::from_secs(10);
        while !finished.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(
            finished.load(Ordering::Acquire),
            "FunctionSlices::analyze did not terminate within 10s — gap \
             detection is stuck on a zero-width block at function_end. \
             See test comment for the chain of events."
        );
        let (result, slices) = handle.join().expect("worker panicked");
        let analyzed = result.expect("analyze should not error");
        assert!(analyzed, "analyze returned Ok(false)");

        // The fix is structural: branches past function_end go to
        // function_references (tail call), so the speculative pass never
        // touches 0x1080 and no out-of-function block is ever created.
        // Verify that:
        //   - 0x1080 is recorded as a function reference, not an internal block
        //   - blocks contain no entries at or past function_end
        //   - blocks contain no zero-width entries
        assert!(
            slices.function_references.contains(&SectionAddress::new(0, 0x1080)),
            "branch past function_end should be a function reference; \
             got function_references={:?}",
            slices.function_references
        );
        for (&start, &end_opt) in &slices.blocks {
            assert!(
                start < function_end,
                "block {start} starts at or past function_end {function_end}"
            );
            if let Some(end) = end_opt {
                assert!(start < end, "zero/negative-width block [{start}..{end}]");
                assert!(
                    end <= function_end,
                    "block [{start}..{end}] extends past function_end {function_end}"
                );
            }
        }
    }
}
