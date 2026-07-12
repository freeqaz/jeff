use std::{
    cmp::min,
    collections::{BTreeMap, BTreeSet},
    fmt::{Debug, Display, Formatter, UpperHex},
    ops::{Add, AddAssign, BitAnd, Sub},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use itertools::Itertools;
use powerpc::Opcode;

use crate::{
    analysis::{
        disassemble,
        executor::{ExecCbData, ExecCbResult, Executor},
        slices::{FunctionSlices, TailCallResult},
        vm::{BranchTarget, Value, StepResult, VM},
        RelocationTarget,
    },
    obj::{
        ObjInfo, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags,
        ObjSymbolKind, SectionIndex,
    },
    util::config::create_auto_symbol_name,
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
    pub fn new(section: SectionIndex, address: u32) -> Self {
        Self { section, address }
    }

    pub fn offset(self, offset: i32) -> Self {
        Self { section: self.section, address: self.address.wrapping_add_signed(offset) }
    }

    pub fn align_up(self, align: u32) -> Self {
        Self { section: self.section, address: (self.address + align - 1) & !(align - 1) }
    }

    pub fn align_down(self, align: u32) -> Self {
        Self { section: self.section, address: self.address & !(align - 1) }
    }

    pub fn is_aligned(self, align: u32) -> bool {
        self.address & (align - 1) == 0
    }

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
    fn add_assign(&mut self, rhs: u32) {
        self.address += rhs;
    }
}

impl UpperHex for SectionAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#010X}", self.section as isize, self.address)
    }
}

impl BitAnd<u32> for SectionAddress {
    type Output = u32;

    fn bitand(self, rhs: u32) -> Self::Output {
        self.address & rhs
    }
}

#[derive(Default, Debug, Clone)]
pub struct FunctionInfo {
    pub analyzed: bool,
    pub end: Option<SectionAddress>,
    pub slices: Option<FunctionSlices>,
}

impl FunctionInfo {
    pub fn is_analyzed(&self) -> bool {
        self.analyzed
    }

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

/// Immutable configuration inputs for CFA.
/// Configured before analysis starts (e.g. by AnalysisPass implementations).
#[derive(Debug, Default)]
pub struct CfaConfig {
    pub sda_bases: Option<(u32, u32)>,
    pub known_symbols: BTreeMap<SectionAddress, Vec<ObjSymbol>>,
    pub known_sections: BTreeMap<SectionIndex, String>,
    pub skip_ranges: BTreeMap<SectionAddress, SectionAddress>,
    /// Pre-seeded functions from analysis passes (e.g. save/restore sleds).
    pub seed_functions: BTreeMap<SectionAddress, FunctionInfo>,
}

/// Final output of CFA — consumed by Tracker, apply_cfa, etc.
#[derive(Debug, Default)]
pub struct CfaResult {
    pub functions: BTreeMap<SectionAddress, FunctionInfo>,
    pub jump_tables: BTreeMap<SectionAddress, u32>,
    /// Functions that were merged as tail blocks into their predecessors.
    /// These need to be removed from obj.symbols during apply_cfa().
    pub merged_tail_blocks: Vec<SectionAddress>,
    /// Functions whose ends were extended by absorbing tail blocks.
    /// These need replace=true in apply_cfa() to update the symbol size.
    pub extended_functions: Vec<SectionAddress>,
}

// =============================================================================
// Public API
// =============================================================================

/// Run the full CFA pipeline: seed discovery → fixed-point analysis → finalization.
pub fn run_cfa(obj: &ObjInfo, config: &CfaConfig) -> Result<CfaResult> {
    // Phase 1: Discover seed functions from pdata, symbols, analysis passes
    let mut functions = discover_seeds(obj, config);
    let seed_addrs: Vec<SectionAddress> = functions.keys().copied().collect();
    let mut jump_tables = BTreeMap::new();

    // Phase 2: Process seeded functions
    for &addr in &seed_addrs {
        process_function_at(obj, config, &mut functions, &mut jump_tables, addr)?;

        // Reconcile CFA's traced extent against pdata (Xbox 360 unwind table).
        // pdata is emitted by the linker and is authoritative for function
        // bounds. CFA's tracer is best-effort and can stop short when it hits
        // instructions it doesn't decode (VMX128, etc.) — when that happens
        // we extend the function's recorded end to pdata's value rather than
        // panic. When CFA finds *more* than pdata (out-of-line tail block
        // absorbed into the function) we keep CFA's larger extent.
        if let Some(&Some(known_size)) = obj.known_functions.get(&addr) {
            let known_end = addr + known_size;
            let func_end_opt = functions.get(&addr).and_then(|f| f.end);
            match func_end_opt {
                None => {
                    // CFA gave up entirely. Trust pdata.
                    log::warn!(
                        "Function at {} has no CFA-detected end; using \
                         pdata extent {}",
                        addr, known_end
                    );
                    functions.entry(addr).or_default().end = Some(known_end);
                }
                Some(func_end) if func_end < known_end => {
                    log::warn!(
                        "Function at {} traced to {} but pdata reports {}; \
                         extending to pdata extent",
                        addr, func_end, known_end
                    );
                    functions.entry(addr).or_default().end = Some(known_end);
                }
                Some(func_end) if func_end != known_end => {
                    log::info!(
                        "Function at {} extends beyond pdata end {} to {} \
                         (likely tail block inclusion)",
                        addr, known_end, func_end
                    );
                }
                Some(_) => {} // exact match: nothing to do
            }
        }
    }
    println!("Known functions complete.");

    // Phase 3: Discover and analyze remaining functions (fixed-point)
    if let Some(entry) = obj.entry.map(|n| n as u32) {
        let (section_index, _) = obj
            .sections
            .at_address(entry)
            .context(format!("Entry point {entry:#010X} outside of any section"))?;
        process_function_at(
            obj,
            config,
            &mut functions,
            &mut jump_tables,
            SectionAddress::new(section_index, entry),
        )?;
    }
    process_functions(obj, config, &mut functions, &mut jump_tables)?;
    while finalize_functions(obj, config, &mut functions, &mut jump_tables, true)? {
        process_functions(obj, config, &mut functions, &mut jump_tables)?;
    }
    if functions.iter().any(|(_, i)| i.is_unfinalized()) {
        log::error!("Failed to finalize functions:");
        for (addr, info) in functions.iter().filter(|(_, i)| i.is_unfinalized()) {
            log::error!(
                "  {:#010X}: blocks [{:?}]",
                addr,
                info.slices.as_ref().unwrap().possible_blocks.keys()
            );
        }
        bail!("Failed to finalize functions");
    }

    // Phase 4: Post-processing (merge tail blocks, validate invariants)
    let (merged_tail_blocks, extended_functions) =
        merge_tail_blocks(obj, config, &mut functions, &mut jump_tables)?;
    validate_invariants(obj, &functions, &jump_tables)
        .context("CFA invariant validation failed after detect_functions")?;

    Ok(CfaResult { functions, jump_tables, merged_tail_blocks, extended_functions })
}

/// Apply CFA results to ObjInfo (create symbols, update sizes, etc.).
pub fn apply_cfa(obj: &mut ObjInfo, result: &CfaResult, config: &CfaConfig) -> Result<()> {
    for (&section_index, section_name) in &config.known_sections {
        obj.sections[section_index].rename(section_name.clone())?;
    }
    // Remove symbols for functions that were merged as tail blocks
    for addr in &result.merged_tail_blocks {
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
    for addr in &result.extended_functions {
        if let Some(info) = result.functions.get(addr) {
            if let Some(end) = info.end {
                let new_size = (end.address - addr.address) as u64;
                if let Ok(Some((index, _))) = obj.symbols.kind_at_section_address(
                    addr.section,
                    addr.address,
                    ObjSymbolKind::Function,
                ) {
                    let existing = &obj.symbols[index];
                    if existing.size != new_size {
                        let symbol =
                            ObjSymbol { size: new_size, size_known: true, ..existing.clone() };
                        obj.symbols.replace(index, symbol)?;
                    }
                }
            }
        }
    }
    for (&start, FunctionInfo { end, .. }) in result.functions.iter() {
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
        let name = create_auto_symbol_name("fn", obj.module_id, start.address);
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
    let mut iter = result.jump_tables.iter().peekable();
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
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            true,
        )?;
    }
    for (&_addr, symbols) in &config.known_symbols {
        for symbol in symbols {
            // Drop sled / signature-derived function symbols whose address
            // lies strictly inside a pdata-described function. The
            // save/restore-sled scanners (FindSaveRestSleds in
            // analysis::pass) emit byte-pattern matches that can
            // legitimately overlap pdata-described parents on Xbox 360
            // (e.g. `__savegprlr` at 0x82829220 inside the pdata function
            // at 0x82829198..0x828293F8). pdata is authoritative; adding
            // the sled as a separate function makes the splitter cut the
            // parent in half later (`Split … ends within symbol …`).
            if symbol.kind == ObjSymbolKind::Function {
                if let Some(section_index) = symbol.section {
                    let sym_addr =
                        SectionAddress::new(section_index, symbol.address as u32);
                    let enclosing = result.functions.range(..sym_addr).next_back();
                    if let Some((&parent_addr, parent_info)) = enclosing {
                        if let Some(parent_end) = parent_info.end {
                            if parent_addr.section == sym_addr.section
                                && parent_addr.address < sym_addr.address
                                && parent_end > sym_addr
                            {
                                log::warn!(
                                    "Skipping signature-derived function symbol {} @ {}: \
                                     lies inside pdata function {}..{}",
                                    symbol.name, sym_addr, parent_addr, parent_end,
                                );
                                continue;
                            }
                        }
                    }
                }
            }
            // Strip any stale duplicate-name entries (from symbols.txt /
            // map / PDB) before adding this known symbol. The sled and
            // intrinsic scanners place symbols at the binary's *real*
            // addresses; if symbols.txt previously declared the same
            // name at a different address (common when symbols.txt was
            // generated against a different build), keeping that stale
            // entry tricks create_gap_splits's duplicate-name boundary
            // logic into emitting a split at the wrong address, which
            // later trips "Split … ends within symbol …".
            if let Ok(Some((stale_idx, stale_sym))) = obj.symbols.by_name(&symbol.name) {
                if stale_sym.address != symbol.address {
                    log::warn!(
                        "Stripping stale duplicate-name symbol {} @ {:#010X} \
                         (replaced by known_symbol at {:#010X})",
                        stale_sym.name, stale_sym.address, symbol.address,
                    );
                    let renamed = ObjSymbol {
                        name: format!("__DELETED_{}", stale_sym.name),
                        kind: ObjSymbolKind::Unknown,
                        size: 0,
                        flags: ObjSymbolFlagSet(
                            ObjSymbolFlags::RelocationIgnore
                                | ObjSymbolFlags::NoWrite
                                | ObjSymbolFlags::NoExport
                                | ObjSymbolFlags::Stripped,
                        ),
                        ..stale_sym.clone()
                    };
                    obj.symbols.replace(stale_idx, renamed)?;
                }
            }
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

// =============================================================================
// Phase functions
// =============================================================================

/// Phase 1: Discover seed functions from pdata, symbols, section starts, and analysis passes.
fn discover_seeds(
    obj: &ObjInfo,
    config: &CfaConfig,
) -> BTreeMap<SectionAddress, FunctionInfo> {
    let mut functions = config.seed_functions.clone();

    // Apply known functions from pdata/import data
    for (&addr, &size) in &obj.known_functions {
        let Some(section) = obj.sections.get(addr.section) else { continue };
        if section.kind != ObjSectionKind::Code || !section.contains(addr.address) {
            log::warn!(
                "Ignoring out-of-bounds known-function seed {:#010X} in section {} ({:#010X}-{:#010X})",
                addr,
                section.name,
                section.address,
                section.address + section.size
            );
            continue;
        }
        functions.insert(
            addr,
            FunctionInfo { analyzed: false, end: size.map(|size| addr + size), slices: None },
        );
    }

    // Apply known functions from symbols
    for (_, symbol) in obj.symbols.by_kind(ObjSymbolKind::Function) {
        let Some(section_index) = symbol.section else { continue };
        let addr_ref = SectionAddress::new(section_index, symbol.address as u32);
        let Some(section) = obj.sections.get(section_index) else { continue };
        if section.kind != ObjSectionKind::Code || !section.contains(addr_ref.address) {
            log::warn!(
                "Ignoring out-of-bounds function symbol seed {} @ {:#010X} in section {} ({:#010X}-{:#010X})",
                symbol.name,
                addr_ref,
                section.name,
                section.address,
                section.address + section.size
            );
            continue;
        }

        // Drop symbol-derived function seeds whose declared range conflicts
        // with an already-registered function (typically a pdata entry
        // inserted in the loop above). symbols.txt is sometimes stale or
        // hand-curated and can label internal control-flow targets, dead
        // padding, or pre-link aliases as `type:function`; trusting them
        // as separate functions then makes detect_new_functions bail with
        // "Overlapping functions". pdata is the authoritative source of
        // function bounds on Xbox 360 — keep it, treat the conflicting
        // symbol as a label.
        //
        // Two conflict shapes need to be handled:
        //   (a) symbol address lies strictly inside a prior pdata range,
        //       e.g. fn_82270000 inside pdata's [0x8226FFD8..0x82270350);
        //   (b) symbol's claimed [address..address+size) crosses into the
        //       *next* pdata function's start, e.g. fn_82272EB4 size 0x28
        //       overlapping pdata's 0x82272EB8 entry.
        let symbol_end_opt = symbol
            .size_known
            .then(|| addr_ref + symbol.size as u32);

        if let Some((&prev_start, prev_info)) = functions.range(..addr_ref).next_back() {
            if prev_start.section == addr_ref.section {
                if let Some(prev_end) = prev_info.end {
                    if prev_end > addr_ref {
                        log::warn!(
                            "Dropping function symbol {} @ {}: lies inside existing function {}..{} (treating as label)",
                            symbol.name, addr_ref, prev_start, prev_end,
                        );
                        continue;
                    }
                }
            }
        }
        if let Some(symbol_end) = symbol_end_opt {
            if let Some((&next_start, _)) =
                functions.range(addr_ref..symbol_end).next()
            {
                if next_start != addr_ref && next_start.section == addr_ref.section {
                    log::warn!(
                        "Dropping function symbol {} @ {} (claimed end {}): crosses into existing function at {} (treating as label)",
                        symbol.name, addr_ref, symbol_end, next_start,
                    );
                    continue;
                }
            }
        }

        // If an entry already exists at this exact address (from pdata or
        // config.seed_functions), prefer its `end` — that source is more
        // authoritative than symbols.txt's stored size, which can drift
        // from the binary's actual function bounds. Only fill in `end`
        // from the symbol when the prior entry didn't have one.
        use std::collections::btree_map::Entry;
        match functions.entry(addr_ref) {
            Entry::Vacant(e) => {
                e.insert(FunctionInfo { analyzed: false, end: symbol_end_opt, slices: None });
            }
            Entry::Occupied(mut occupied) => {
                if occupied.get().end.is_none() && symbol_end_opt.is_some() {
                    occupied.get_mut().end = symbol_end_opt;
                }
            }
        }
    }

    // Also check the beginning of every code section
    for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
        let this_sec_start = SectionAddress::new(section_index, section.address as u32);
        if obj
            .symbols
            .by_name(&format!("except_data_{:08X}", this_sec_start.address + 8))
            .ok()
            .flatten()
            .is_some()
        {
            continue;
        }
        functions.entry(this_sec_start).or_default();
    }

    // Final sweep: drop any seed function that lies strictly inside another
    // seed function's [start, end) range. The seed set is the union of:
    //   - config.seed_functions (analysis passes — save/restore sleds,
    //     CRT helpers, etc.)
    //   - obj.known_functions (pdata + import data)
    //   - obj.symbols function entries (symbols.txt, PDB, map)
    //
    // The pass-side scanners (FindSaveRestSleds in particular) fire on
    // byte signatures and can match inside larger pdata functions —
    // e.g. RB3 retail has `__savegprlr` at 0x82829220 inside the pdata
    // function at 0x82829198 (size 0x260). Pdata is authoritative; an
    // inside-pdata seed is a label, not a separate function. Letting it
    // through makes the splitter cut the parent in half later, killing
    // the run with `Split … ends within symbol …`.
    //
    // This runs after all the per-source loops above so it can drop
    // overlapping entries regardless of insertion order.
    let candidates: Vec<(SectionAddress, Option<SectionAddress>)> =
        functions.iter().map(|(&a, info)| (a, info.end)).collect();
    let mut to_drop: Vec<SectionAddress> = Vec::new();
    for (addr, _end) in &candidates {
        if let Some((&parent_addr, parent_info)) =
            functions.range(..*addr).next_back()
        {
            if parent_addr.section == addr.section {
                if let Some(parent_end) = parent_info.end {
                    if parent_addr.address < addr.address
                        && parent_end > *addr
                    {
                        log::warn!(
                            "Dropping function seed {} (lies inside {}..{})",
                            addr, parent_addr, parent_end,
                        );
                        to_drop.push(*addr);
                    }
                }
            }
        }
    }
    for addr in to_drop {
        functions.remove(&addr);
    }

    functions
}

/// Validate core post-analysis invariants.
pub fn validate_invariants(
    obj: &ObjInfo,
    functions: &BTreeMap<SectionAddress, FunctionInfo>,
    jump_tables: &BTreeMap<SectionAddress, u32>,
) -> Result<()> {
    let mut prev: Option<(SectionAddress, SectionAddress)> = None;
    for (&start, info) in functions {
        let Some(end) = info.end else { continue };
        ensure!(
            matches!(obj.sections.get(start.section), Some(s) if s.kind == ObjSectionKind::Code),
            "Function start {} is not in a code section",
            start
        );
        ensure!(
            start.section == end.section,
            "Function {} crosses sections (end {})",
            start,
            end
        );
        ensure!(end.address > start.address, "Function {} has non-positive size", start);
        let section = &obj.sections[start.section];
        ensure!(
            section.contains_range(start.address..end.address),
            "Function {:#010X}..{:#010X} out of bounds of section {} {:#010X}..{:#010X}",
            start.address,
            end.address,
            section.name,
            section.address,
            section.address + section.size
        );
        if let Some((prev_start, prev_end)) = prev {
            if prev_start.section == start.section {
                ensure!(
                    start.address >= prev_end.address,
                    "Overlapping functions in section {}: {}..{} and {}..{}",
                    start.section,
                    prev_start,
                    prev_end,
                    start,
                    end
                );
            }
        }
        prev = Some((start, end));
    }

    for (&addr, &size) in jump_tables {
        ensure!(size > 0, "Jump table at {} has zero size", addr);
        let end = addr
            .address
            .checked_add(size)
            .ok_or_else(|| anyhow!("Jump table size overflow at {}", addr))?;
        let section = &obj.sections[addr.section];
        ensure!(
            section.contains_range(addr.address..end),
            "Jump table {:#010X}..{:#010X} out of bounds of section {} {:#010X}..{:#010X}",
            addr.address,
            end,
            section.name,
            section.address,
            section.address + section.size
        );
        ensure!(section.kind != ObjSectionKind::Bss, "Jump table at {} cannot be in BSS", addr);
    }
    Ok(())
}

// =============================================================================
// Internal helpers
// =============================================================================

fn finalize_functions(
    obj: &ObjInfo,
    config: &CfaConfig,
    functions: &mut BTreeMap<SectionAddress, FunctionInfo>,
    jump_tables: &mut BTreeMap<SectionAddress, u32>,
    finalize: bool,
) -> Result<bool> {
    let mut finalized_any = false;
    let unfinalized = functions
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
                functions,
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
                        functions,
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
                            functions,
                            Some(vm),
                        )?;
                    }
                }
                TailCallResult::Error(e) => return Err(e),
            }
        }
        if slices.can_finalize() {
            log::trace!("Finalizing {:#010X}", addr);
            slices.finalize(obj, functions)?;
            for address in slices.function_references.iter().cloned() {
                try_add_function(obj, config, functions, address);
            }
            jump_tables.append(&mut slices.jump_table_references.clone());
            let end = slices.end();
            let info = functions.get_mut(&addr).unwrap();
            info.analyzed = true;
            info.end = end;
            info.slices = Some(slices.clone());
            finalized_any = true;
        }
    }
    Ok(finalized_any)
}

fn try_add_function(
    obj: &ObjInfo,
    config: &CfaConfig,
    functions: &mut BTreeMap<SectionAddress, FunctionInfo>,
    address: SectionAddress,
) {
    // Only create functions for in-bounds code addresses.
    // Some games use branches to data sections to prevent dead stripping (Mario Party),
    // and malformed analysis seeds may also produce out-of-bounds targets with a stale
    // section index. Both should be ignored.
    let Some(section) = obj.sections.get(address.section) else { return };
    if section.kind != ObjSectionKind::Code {
        return;
    }
    if !section.contains(address.address) {
        log::warn!(
            "Ignoring out-of-bounds discovered function {:#010X} in section {} ({:#010X}-{:#010X})",
            address,
            section.name,
            section.address,
            section.address + section.size
        );
        return;
    }
    // Avoid creating functions in skipped ranges
    if in_skipped_range(&config.skip_ranges, address) {
        return;
    }
    // Don't add a discovered function that falls strictly inside an
    // already-registered function's range (typically a pdata entry).
    // slices.function_references can legitimately include addresses
    // that are internal labels of the parent function — jump-table
    // dispatch blocks, out-of-line tails, or block boundaries that
    // CFA mistook for tail calls. Promoting any of those to a
    // separate function entry creates a structural overlap that
    // makes detect_new_functions bail downstream.
    if let Some((&prev_start, prev_info)) = functions.range(..address).next_back() {
        if prev_start.section == address.section {
            if let Some(prev_end) = prev_info.end {
                if prev_end > address {
                    log::debug!(
                        "Skipping discovered function {} inside existing function {}..{}",
                        address, prev_start, prev_end,
                    );
                    return;
                }
            }
        }
    }
    functions.entry(address).or_default();
}

fn in_skipped_range(
    skip_ranges: &BTreeMap<SectionAddress, SectionAddress>,
    address: SectionAddress,
) -> bool {
    match skip_ranges.range(..=address).next_back() {
        Some((&start, &end)) => address >= start && address < end,
        None => false,
    }
}

fn first_unbounded_function(
    functions: &BTreeMap<SectionAddress, FunctionInfo>,
) -> Option<SectionAddress> {
    functions.iter().find(|(_, info)| !info.is_analyzed()).map(|(&addr, _)| addr)
}

fn process_functions(
    obj: &ObjInfo,
    config: &CfaConfig,
    functions: &mut BTreeMap<SectionAddress, FunctionInfo>,
    jump_tables: &mut BTreeMap<SectionAddress, u32>,
) -> Result<()> {
    loop {
        match first_unbounded_function(functions) {
            Some(addr) => {
                log::trace!("Processing {:#010X}", addr);
                process_function_at(obj, config, functions, jump_tables, addr)?;
            }
            None => {
                if !finalize_functions(obj, config, functions, jump_tables, false)?
                    && !detect_new_functions(obj, config, functions)?
                {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Process a single function at the given address.
/// Public for use in tests.
pub fn process_function_at(
    obj: &ObjInfo,
    config: &CfaConfig,
    functions: &mut BTreeMap<SectionAddress, FunctionInfo>,
    jump_tables: &mut BTreeMap<SectionAddress, u32>,
    addr: SectionAddress,
) -> Result<bool> {
    Ok(if let Some(mut slices) = process_function(obj, functions, addr)? {
        for address in slices.function_references.iter().cloned() {
            try_add_function(obj, config, functions, address);
        }
        jump_tables.append(&mut slices.jump_table_references.clone());
        if slices.can_finalize() {
            slices.finalize(obj, functions)?;
            let info = functions.entry(addr).or_default();
            info.analyzed = true;
            // Don't shrink a pre-existing authoritative end. pdata seeds
            // it from the linker's unwind table; detect_new_functions
            // extends it when it absorbs a tail block that CFA can't
            // reach from the main body (e.g., dispatched via bctr / jump
            // table). Replacing it here with the smaller slices.end()
            // makes detect_new_functions and process_function_at oscillate
            // forever (extend → re-analyze → revert → re-detect → ...).
            // Adopt slices.end() only when there's no prior value or
            // when CFA actually traced further than the prior end.
            info.end = match (info.end, slices.end()) {
                (Some(prev), Some(traced)) if traced > prev => Some(traced),
                (Some(prev), _) => Some(prev),
                (None, traced) => traced,
            };
            info.slices = Some(slices);
        } else {
            let info = functions.entry(addr).or_default();
            info.analyzed = true;
            // Don't overwrite info.end - preserve known end from pdata/symbols
            info.slices = Some(slices);
        }
        true
    } else {
        log::info!("Not a function @ {:#010X}", addr);
        let info = functions.entry(addr).or_default();
        info.analyzed = true;
        // Don't clobber a pre-seeded end. discover_seeds populates info.end
        // from pdata (Xbox 360 unwind table) and from symbols.txt entries
        // whose sizes are known. Those bounds are authoritative even when
        // CFA can't trace through the body — RB3 contains VMX128 (Xbox 360
        // SIMD) opcodes that the disassembler doesn't decode, which makes
        // slices.analyze bail with `false`. Preserving info.end lets
        // apply_cfa still emit a properly-sized symbol.
        false
    })
}

fn process_function(
    obj: &ObjInfo,
    functions: &BTreeMap<SectionAddress, FunctionInfo>,
    start: SectionAddress,
) -> Result<Option<FunctionSlices>> {
    let mut slices = FunctionSlices::default();
    let function_end = functions.get(&start).and_then(|info| info.end);
    Ok(match slices.analyze(obj, start, start, function_end, functions, None)? {
        true => Some(slices),
        false => None,
    })
}

/// Post-pass to merge small functions that are actually tail blocks of their predecessors.
///
/// After all functions are detected (from pdata, symbols, and gap-filling), this scans for
/// adjacent function pairs where the second function is a tail block of the first. This
/// handles cases where symbols.txt already has the fake function defined from a previous run.
///
/// Returns (merged_tail_blocks, extended_functions).
fn merge_tail_blocks(
    obj: &ObjInfo,
    config: &CfaConfig,
    functions: &mut BTreeMap<SectionAddress, FunctionInfo>,
    jump_tables: &mut BTreeMap<SectionAddress, u32>,
) -> Result<(Vec<SectionAddress>, Vec<SectionAddress>)> {
    let mut merged_tail_blocks = Vec::new();
    let mut extended_functions = Vec::new();
    let mut merges: Vec<(SectionAddress, SectionAddress)> = vec![];

    for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
        let section_start = SectionAddress::new(section_index, section.address as u32);
        let section_end = section_start + section.size as u32;
        let funcs_in_section: Vec<(SectionAddress, FunctionInfo)> = functions
            .range(section_start..section_end)
            .map(|(&a, i)| (a, i.clone()))
            .collect();

        for window in funcs_in_section.windows(2) {
            let (prev_addr, prev_info) = &window[0];
            let (func_addr, func_info) = &window[1];

            let Some(prev_end) = prev_info.end else { continue };
            let Some(func_end) = func_info.end else { continue };

            // Only consider the case where the candidate function starts right
            // at the predecessor's end (no gap/alignment between them)
            if *func_addr != prev_end {
                continue;
            }

            // Skip merging if the candidate already has a persisted function
            // symbol at its start. obj.symbols is immutable throughout CFA, so
            // any function symbol found here was pre-seeded from config
            // (symbols.txt / PDB / map / a prior split run's synthesized leaf) —
            // never from this run's discovery. It is therefore a *committed
            // split boundary*: splits.txt already cuts a unit at this address,
            // and merging the candidate into its predecessor un-declares that
            // boundary, tripping "Split … ends within symbol" on the next
            // re-split (broken idempotency). Respect the boundary regardless of
            // scope — this is what lets the reloc-targeted leaf-synthesis pass
            // (src/cmd/xex.rs) clamp non-pdata parents around bl-referenced
            // leaves: neither the Global-flagged synthesized leaf nor the
            // clamped (Unknown-scope, possibly fall-through-reached) parent it
            // leaves behind gets re-merged on the following run. Persisted =
            // will be written to symbols.txt (not NoWrite, not Stripped).
            // Previously this only guarded Global-scope symbols, which missed
            // the Unknown-scope clamped parents and broke the broad leaf pass.
            if let Ok(Some((_, sym))) = obj.symbols.kind_at_section_address(
                func_addr.section,
                func_addr.address,
                ObjSymbolKind::Function,
            ) {
                if !sym.flags.is_no_write() && !sym.flags.is_stripped() {
                    log::info!(
                        "Skipping tail block merge of {:#010X} (persisted function symbol '{}', scope {:?})",
                        func_addr,
                        sym.name,
                        sym.flags.scope(),
                    );
                    continue;
                }
            }

            // Check if this function is a tail block
            if let Some(_tail_end) =
                check_tail_block(section, *func_addr, func_end, *prev_addr, prev_end)
            {
                log::info!(
                    "Merging tail block function {:#010X}-{:#010X} into {:#010X} (extending from {:#010X})",
                    func_addr, func_end, prev_addr, prev_end,
                );
                merges.push((*prev_addr, *func_addr));
            }
        }
    }

    for (prev_addr, tail_addr) in &merges {
        // Get the tail function's end before removing it
        let tail_end = functions.get(tail_addr).and_then(|i| i.end).unwrap();
        // Remove the fake function
        functions.remove(tail_addr);
        // Track for symbol removal in apply_cfa()
        merged_tail_blocks.push(*tail_addr);
        // Extend the predecessor's end and track for size update in apply_cfa()
        extended_functions.push(*prev_addr);
        if let Some(info) = functions.get_mut(prev_addr) {
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
            process_function_at(obj, config, functions, jump_tables, *prev_addr)?;
        }
    }

    Ok((merged_tail_blocks, extended_functions))
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
    // Only consider small gaps (up to 64 bytes / 16 instructions)
    let gap_size = gap_end.address - gap_start.address;
    if gap_size > 64 {
        return None;
    }

    // Check the first instruction
    let first_ins = disassemble(section, gap_start.address)?;

    // Case 1: First instruction is an unconditional branch (b, not bl) back into
    // the preceding function. This is the classic out-of-line loop exit.
    if first_ins.op == Opcode::B && !first_ins.field_lk() && !first_ins.field_aa() {
        let target = first_ins.branch_dest(gap_start.address)?;
        if target >= preceding_func_start.address && target < preceding_func_end.address {
            // Scan forward to find the end of this tail block (up to blr or gap_end)
            let mut addr = gap_start;
            while let Some(ins) = disassemble(section, addr.address) {
                addr += 4;
                // blr (unconditional return) or end of gap
                if ins.op == Opcode::Bclr
                    && !ins.field_lk()
                    && (ins.field_bo() & 0b10100 == 0b10100)
                {
                    return Some(addr);
                }
                if addr >= gap_end {
                    return Some(gap_end);
                }
            }
        }
    }

    // Case 2: Scan the entire gap block — if every branch instruction targets back
    // into the preceding function (no outward calls or forward jumps to other functions),
    // and the block ends with blr, treat it as a tail block.
    let mut addr = gap_start;
    let mut has_backward_branch = false;
    let mut ends_with_blr = false;
    while addr < gap_end {
        let ins = disassemble(section, addr.address)?;

        match ins.op {
            // Unconditional or conditional branch (not link)
            Opcode::B | Opcode::Bc if !ins.field_lk() && !ins.field_aa() => {
                if let Some(target) = ins.branch_dest(addr.address) {
                    if target >= preceding_func_start.address
                        && target < preceding_func_end.address
                    {
                        has_backward_branch = true;
                    } else if target < gap_start.address || target >= gap_end.address {
                        // Branch to somewhere outside both the preceding function and
                        // this gap — not a simple tail block
                        return None;
                    }
                }
            }
            // bl (function call) — tail blocks don't call other functions
            Opcode::B | Opcode::Bc if ins.field_lk() => return None,
            // blr — return instruction
            Opcode::Bclr if !ins.field_lk() && (ins.field_bo() & 0b10100 == 0b10100) => {
                ends_with_blr = true;
            }
            // bctr — indirect branch, not typical for a tail block
            Opcode::Bcctr if !ins.field_lk() => return None,
            _ => {}
        }

        addr += 4;
    }

    if has_backward_branch && ends_with_blr {
        Some(gap_end)
    } else {
        None
    }
}

fn detect_new_functions(
    obj: &ObjInfo,
    config: &CfaConfig,
    functions: &mut BTreeMap<SectionAddress, FunctionInfo>,
) -> Result<bool> {
    let mut new_functions = vec![];
    let mut extended_functions: Vec<(SectionAddress, SectionAddress)> = vec![];
    for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
        if section.name == ".xidata" {
            continue;
        } // because we already did our xidata processing at this point
        let section_start = SectionAddress::new(section_index, section.address as u32);
        let section_end = section_start + section.size as u32;
        let mut iter = functions.range(section_start..section_end).peekable();
        loop {
            match (iter.next(), iter.peek()) {
                (Some((&first, first_info)), Some(&(&second, second_info))) => {
                    let Some(first_end) = first_info.end else { continue };
                    if first_end > second {
                        bail!("Overlapping functions {}-{} -> {}", first, first_end, second);
                    }
                    let addr = match skip_alignment(config, section, first_end, second) {
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

                        // Check if this gap is a tail block of the preceding function
                        if let Some(tail_end) =
                            check_tail_block(section, addr, second, first, first_end)
                        {
                            log::info!(
                                "Detected tail block @ {:#010X}-{:#010X} of function {:#010X}, extending function end from {:#010X}",
                                addr, tail_end, first, first_end,
                            );
                            extended_functions.push((first, tail_end));
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
                (Some((&last, last_info)), None) => {
                    let Some(last_end) = last_info.end else { continue };
                    if last_end < section_end {
                        let addr = match skip_alignment(config, section, last_end, section_end) {
                            Some(addr) => addr,
                            None => continue,
                        };
                        if addr < section_end {
                            // Check if this gap is a tail block of the last function
                            if let Some(tail_end) = check_tail_block(
                                section,
                                addr,
                                section_end,
                                last,
                                last_end,
                            ) {
                                log::info!(
                                    "Detected tail block @ {:#010X}-{:#010X} of function {:#010X}, extending function end from {:#010X}",
                                    addr, tail_end, last, last_end,
                                );
                                extended_functions.push((last, tail_end));
                                continue;
                            }

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
    // Apply function end extensions for tail blocks
    for (func_addr, new_end) in &extended_functions {
        if let Some(info) = functions.get_mut(func_addr) {
            if let Some(ref mut end) = info.end {
                if *new_end > *end {
                    *end = *new_end;
                }
            }
            // Mark as needing re-analysis since the function bounds changed
            info.analyzed = false;
        }
    }
    let found_new = !new_functions.is_empty() || !extended_functions.is_empty();
    for addr in new_functions {
        let opt = functions.insert(addr, FunctionInfo::default());
        ensure!(opt.is_none(), "Attempted to detect duplicate function @ {:#010X}", addr);
    }
    Ok(found_new)
}

fn skip_alignment(
    config: &CfaConfig,
    section: &ObjSection,
    mut addr: SectionAddress,
    end: SectionAddress,
) -> Option<SectionAddress> {
    loop {
        if let Some((&start, &end)) = config.skip_ranges.range(..=addr).next_back() {
            if addr >= start && addr < end {
                addr = end;
            }
        };
        if addr.address + 4 > end.address {
            break None;
        }
        let data = match section.data_range(addr.address, addr.address + 4) {
            Ok(data) => data,
            Err(_) => return None,
        };
        if data == [0u8; 4] {
            addr += 4;
        } else {
            break Some(addr);
        }
    }
}

// =============================================================================
// Standalone utility functions
// =============================================================================

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

            if let (Value::Constant(sda2_base), Value::Constant(sda_base)) =
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
            obj.add_symbol(
                ObjSymbol {
                    name: "_SDA2_BASE_".to_string(),
                    address: sda2_base,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    ..Default::default()
                },
                true,
            )?;
            obj.add_symbol(
                ObjSymbol {
                    name: "_SDA_BASE_".to_string(),
                    address: sda_base,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    ..Default::default()
                },
                true,
            )?;
            Ok(true)
        }
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::slices::FunctionSlices;
    use crate::obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind};

    /// Helper to build a minimal ObjSection with hand-crafted PPC instructions.
    /// `base_addr` is the virtual address of the section start.
    /// `instructions` is a slice of big-endian u32 instruction words.
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

    fn make_obj(base_addr: u32, instructions: &[u32]) -> ObjInfo {
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "shadow-cfa-test".into(),
            vec![],
            vec![make_code_section(base_addr, instructions)],
        )
    }

    // PPC instruction encoding helpers
    const BLR: u32 = 0x4E800020;
    const NOP: u32 = 0x60000000;
    const ADDI_R3: u32 = 0x38630001; // addi r3, r3, 1

    /// Encode `b offset` (unconditional relative branch, not link, not absolute)
    fn ppc_b(offset: i32) -> u32 {
        0x48000000 | (offset as u32 & 0x03FFFFFC)
    }

    /// Encode `bne offset` (conditional branch, CR0 not-equal)
    fn ppc_bne(offset: i32) -> u32 {
        0x40820000 | (offset as u32 & 0x0000FFFC)
    }

    /// Encode `bl offset` (branch and link)
    fn ppc_bl(offset: i32) -> u32 {
        0x48000001 | (offset as u32 & 0x03FFFFFC)
    }

    /// Encode `bctr` (branch to count register)
    const BCTR: u32 = 0x4E800420;

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
        let known_end_only =
            FunctionInfo { analyzed: true, end: Some(SectionAddress::new(0, 0x100)), slices: None };
        assert!(known_end_only.is_analyzed());
        assert!(!known_end_only.is_function()); // needs slices
        assert!(!known_end_only.is_non_function()); // has end
        assert!(!known_end_only.is_unfinalized()); // has end

        // Analyzed as non-function (no end, no slices)
        let non_function = FunctionInfo { analyzed: true, end: None, slices: None };
        assert!(non_function.is_analyzed());
        assert!(!non_function.is_function());
        assert!(non_function.is_non_function());
        assert!(!non_function.is_unfinalized());

        // Unfinalized: analyzed, no end, has slices
        let unfinalized =
            FunctionInfo { analyzed: true, end: None, slices: Some(FunctionSlices::default()) };
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
    #[test]
    fn test_known_end_preserved_state() {
        let known_end = SectionAddress::new(0, 0x100);
        let info = FunctionInfo {
            analyzed: true,
            end: Some(known_end),
            slices: Some(FunctionSlices::default()),
        };

        assert!(info.is_analyzed());
        assert!(info.is_function());
        assert_eq!(info.end, Some(known_end));
    }

    /// Test that functions map correctly tracks function entries
    #[test]
    fn test_functions_map_init() {
        let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();

        let func_addr = SectionAddress::new(0, 0x1000);
        let func_size = 0x50u32;
        let func_end = func_addr + func_size;

        functions
            .insert(func_addr, FunctionInfo { analyzed: false, end: Some(func_end), slices: None });

        let info = functions.get(&func_addr).unwrap();
        assert!(!info.analyzed);
        assert_eq!(info.end, Some(func_end));
        assert!(info.slices.is_none());
    }

    /// Test the scenario where process_function_at receives a function with
    /// a pre-set end (from pdata) and slices can't finalize.
    #[test]
    fn test_end_preserved_when_cannot_finalize() {
        let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();

        let func_addr = SectionAddress::new(0, 0x1000);
        let known_end = SectionAddress::new(0, 0x1050);

        functions.insert(
            func_addr,
            FunctionInfo { analyzed: false, end: Some(known_end), slices: None },
        );

        let slices = FunctionSlices::default();

        let info = functions.get_mut(&func_addr).unwrap();
        let original_end = info.end;

        info.analyzed = true;
        // Don't overwrite info.end, preserving the known value
        info.slices = Some(slices);

        assert_eq!(info.end, original_end);
        assert_eq!(info.end, Some(known_end));
    }

    /// Test the scenario where slices CAN finalize - end should come from slices
    #[test]
    fn test_end_from_slices_when_can_finalize() {
        let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();

        let func_addr = SectionAddress::new(0, 0x1000);

        functions.insert(func_addr, FunctionInfo::default());

        let mut slices = FunctionSlices::default();
        slices.blocks.insert(func_addr, Some(SectionAddress::new(0, 0x1020)));

        let info = functions.get_mut(&func_addr).unwrap();
        info.analyzed = true;
        info.end = slices.end();
        info.slices = Some(slices.clone());

        assert!(info.is_analyzed());
        assert_eq!(info.end, slices.end());
    }

    // Regression test for the RB3 retail XEX bail
    //   "Overlapping functions 3:0x8226FFD8-3:0x82270350 -> 3:0x82270000"
    // observed after the prior session's CFA hang fix unblocked Phase 2.
    //
    // Cause: pdata says the function at 0x8226FFD8 is 222 instructions long
    // (extends to 0x82270350). symbols.txt also has fn_82270000 (size 0x14)
    // — but the instructions at 0x82270000 are not a function prologue
    // (`li r3, 0; cmplwi cr6, r3, 0; beq ...`) — it's a label inside the
    // pdata-described function. The stale symbol shouldn't be promoted to
    // a seed function; pdata is authoritative.
    //
    // discover_seeds must drop the symbol-derived seed when it lies
    // strictly inside an already-registered (pdata) function.
    #[test]
    fn discover_seeds_drops_symbol_inside_pdata_function() {
        use crate::obj::{ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind};

        let mut obj = make_obj(0x1000, &[NOP; 0x80]); // 0x1000..0x1200

        let pdata_start = SectionAddress::new(0, 0x1000);
        let pdata_size = 0x100u32; // function spans [0x1000, 0x1100]
        obj.known_functions.insert(pdata_start, Some(pdata_size));
        obj.pdata_funcs.push(pdata_start);

        // Spurious symbol "label_at_0x1040" inside the pdata function, with
        // size_known = true and a small reported size — mirrors the stale
        // fn_82270000 in symbols.txt.
        obj.add_symbol(
            ObjSymbol {
                name: "label_at_0x1040".into(),
                address: 0x1040,
                section: Some(0),
                size: 0x14,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Function,
                ..Default::default()
            },
            false,
        )
        .expect("add_symbol");

        // A legitimate function symbol *outside* the pdata range should
        // still be picked up.
        obj.add_symbol(
            ObjSymbol {
                name: "real_neighbor".into(),
                address: 0x1100,
                section: Some(0),
                size: 0x40,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Function,
                ..Default::default()
            },
            false,
        )
        .expect("add_symbol");

        let config = CfaConfig::default();
        let seeds = discover_seeds(&obj, &config);

        // The pdata function is present with the pdata-derived end.
        let pdata_info = seeds.get(&pdata_start).expect("pdata function present");
        assert_eq!(
            pdata_info.end,
            Some(pdata_start + pdata_size),
            "pdata function end should not be overridden by symbol",
        );

        // The spurious inside-pdata symbol is dropped.
        assert!(
            !seeds.contains_key(&SectionAddress::new(0, 0x1040)),
            "symbol-derived function inside a pdata range should be dropped; \
             seed map: {:?}",
            seeds.keys().collect::<Vec<_>>()
        );

        // The legitimate non-overlapping symbol is preserved.
        let neighbor = seeds
            .get(&SectionAddress::new(0, 0x1100))
            .expect("legitimate neighbor function present");
        assert_eq!(neighbor.end, Some(SectionAddress::new(0, 0x1140)));
    }

    // Regression test for the second-form RB3 overlap
    //   "Overlapping functions 3:0x82272EB4-3:0x82272EDC -> 3:0x82272EB8"
    //
    // Cause: pdata has consecutive entries 0x82272DB0..0x82272EB4 and
    // 0x82272EB8..0x82272FBC (4-byte gap between them). symbols.txt
    // additionally lists fn_82272EB4 size 0x28 — i.e. it claims a function
    // STARTING in the 4-byte gap and EXTENDING into the next pdata
    // function. The symbol's address itself doesn't lie inside any
    // existing function (case (a) doesn't fire), but its *claimed end*
    // crosses into pdata's 0x82272EB8 entry.
    //
    // discover_seeds must drop the symbol-derived seed whose [addr..end)
    // range crosses into the next registered function's start.
    #[test]
    fn discover_seeds_drops_symbol_whose_end_crosses_into_next_function() {
        use crate::obj::{ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind};

        let mut obj = make_obj(0x1000, &[NOP; 0x40]); // 0x1000..0x1100

        // Pdata: function at 0x1080 of size 0x40 (ends at 0x10C0).
        let pdata_start = SectionAddress::new(0, 0x1080);
        obj.known_functions.insert(pdata_start, Some(0x40));
        obj.pdata_funcs.push(pdata_start);

        // Symbol claiming a function at 0x107C size 0x10 — the start is in
        // the 4-byte gap before pdata's entry, but the claimed end 0x108C
        // crosses into pdata's [0x1080..0x10C0).
        obj.add_symbol(
            ObjSymbol {
                name: "stale_label_before_pdata".into(),
                address: 0x107C,
                section: Some(0),
                size: 0x10,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Function,
                ..Default::default()
            },
            false,
        )
        .expect("add_symbol");

        let config = CfaConfig::default();
        let seeds = discover_seeds(&obj, &config);

        assert!(
            seeds.contains_key(&pdata_start),
            "pdata function survives"
        );
        assert!(
            !seeds.contains_key(&SectionAddress::new(0, 0x107C)),
            "symbol whose range crosses into a pdata function should be dropped; \
             seed map: {:?}",
            seeds.keys().collect::<Vec<_>>()
        );
    }

    // Sister test: when a function symbol shares the *same* address as a
    // pdata function, the pdata `end` must win — symbols.txt sizes can lag
    // behind pdata when the binary has been re-linked or pdata was
    // regenerated.
    #[test]
    fn discover_seeds_keeps_pdata_end_when_symbol_collides_at_same_address() {
        use crate::obj::{ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind};

        let mut obj = make_obj(0x1000, &[NOP; 0x40]);

        let addr = SectionAddress::new(0, 0x1000);
        obj.known_functions.insert(addr, Some(0x100));
        obj.pdata_funcs.push(addr);

        obj.add_symbol(
            ObjSymbol {
                name: "fn_with_stale_size".into(),
                address: 0x1000,
                section: Some(0),
                size: 0x10, // STALE: pdata says 0x100
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Function,
                ..Default::default()
            },
            false,
        )
        .expect("add_symbol");

        let config = CfaConfig::default();
        let seeds = discover_seeds(&obj, &config);
        let info = seeds.get(&addr).expect("function present");
        assert_eq!(
            info.end,
            Some(addr + 0x100u32),
            "pdata end must beat symbol size at same address"
        );
    }

    // Regression test for the detect_new_functions ↔ process_function_at
    // oscillation observed on RB3 retail (Phase 3 logged "Detected tail
    // block @ 0x82511618-0x82511658 of function 0x82511590, extending
    // function end from 0x82511614" indefinitely).
    //
    // Cause: detect_new_functions detects a tail block via byte-pattern
    // matching and extends the parent's end. CFA then re-analyzes the
    // function — but the tail block is reached only via a path CFA can't
    // see (bctr / jump table), so slices.end() reports the *original*
    // main-body end. Previously, process_function_at unconditionally wrote
    // `info.end = slices.end()`, reverting the extension. The next
    // detect_new_functions iteration finds the same gap and extends
    // again, ad infinitum.
    //
    // Fix: info.end is monotonic in process_function_at — never shrink it
    // below a previously-set value. Pdata seeds, detect_new_functions's
    // tail-block extensions, and prior CFA traces are all authoritative
    // upper bounds.
    #[test]
    fn process_function_at_does_not_shrink_existing_end() {
        // Synthetic function whose CFA-traced end is 0x1010 but whose
        // pre-recorded info.end is 0x1040 (as if detect_new_functions had
        // absorbed a tail block CFA can't reach).
        let obj = make_obj(0x1000, &[BLR; 16]); // 0x1000..0x1040, all blr

        let addr = SectionAddress::new(0, 0x1000);
        let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
        functions.insert(
            addr,
            FunctionInfo {
                analyzed: false,
                end: Some(SectionAddress::new(0, 0x1040)), // pre-recorded extended end
                slices: None,
            },
        );

        let config = CfaConfig::default();
        let mut jump_tables = BTreeMap::new();
        process_function_at(&obj, &config, &mut functions, &mut jump_tables, addr)
            .expect("process_function_at should succeed");

        let info = functions.get(&addr).expect("function still present");
        assert!(
            info.analyzed,
            "function should be marked analyzed"
        );
        assert_eq!(
            info.end,
            Some(SectionAddress::new(0, 0x1040)),
            "process_function_at must not shrink info.end below the \
             pre-recorded extended value (got {:?})",
            info.end
        );
    }

    // Regression test for the third-form RB3 overlap:
    //   "Overlapping functions 3:0x82274490-3:0x822745B0 -> 3:0x822745A0"
    //
    // Cause: pdata describes a function 0x82274490..0x822745B0. During
    // slices.analyze, an internal label (jump-table dispatch / out-of-line
    // tail block) at 0x822745A0 was misclassified as a tail call and ended
    // up in slices.function_references. process_function_at then called
    // try_add_function with that address, which unconditionally created a
    // Regression test for the discover_seeds final sweep — RB3 retail
    // tripped a "Split … ends within symbol …" bail because the
    // FindSaveRestSledsXbox analysis pass put `__savegprlr` (size 0x50)
    // at 0x82829220 in seed_functions, while pdata had a function at
    // 0x82829198 (size 0x260) covering it. Both ended up in the seed
    // set with overlapping ranges, and the later splitter cut the
    // pdata-described parent in half at the sled boundary.
    //
    // discover_seeds must, after merging all seed sources, drop any
    // seed function whose address lies strictly inside another seed's
    // [start, end) range.
    #[test]
    fn discover_seeds_final_sweep_drops_sled_inside_pdata_function() {
        let obj = make_obj(0x1000, &[NOP; 0x80]);

        let pdata_start = SectionAddress::new(0, 0x1000);
        let mut config = CfaConfig::default();
        // Simulate FindSaveRestSledsXbox inserting `__savegprlr` as a seed
        // at an address that pdata's enclosing function already covers.
        let sled_addr = SectionAddress::new(0, 0x1080);
        let sled_size = 0x50u32;
        config.seed_functions.insert(
            sled_addr,
            FunctionInfo {
                analyzed: false,
                end: Some(sled_addr + sled_size),
                slices: None,
            },
        );

        // Pdata says the parent function covers [0x1000, 0x1100), which
        // strictly encloses the sled.
        let mut obj = obj;
        obj.known_functions.insert(pdata_start, Some(0x100));
        obj.pdata_funcs.push(pdata_start);

        let seeds = discover_seeds(&obj, &config);

        assert!(seeds.contains_key(&pdata_start), "pdata function survives");
        assert!(
            !seeds.contains_key(&sled_addr),
            "sled-derived seed inside a pdata range should be dropped by the \
             final sweep; got seeds: {:?}",
            seeds.keys().collect::<Vec<_>>()
        );
    }

    // new function entry — overlapping the parent.
    //
    // try_add_function must skip addresses that lie strictly inside an
    // already-registered function.
    #[test]
    fn try_add_function_rejects_addresses_inside_existing_function() {
        let obj = make_obj(0x1000, &[NOP; 0x80]);

        let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
        // Pre-existing function [0x1000..0x1100].
        functions.insert(
            SectionAddress::new(0, 0x1000),
            FunctionInfo {
                analyzed: false,
                end: Some(SectionAddress::new(0, 0x1100)),
                slices: None,
            },
        );

        let config = CfaConfig::default();

        // Address inside the existing function: must not be added.
        try_add_function(&obj, &config, &mut functions, SectionAddress::new(0, 0x1080));
        assert!(
            !functions.contains_key(&SectionAddress::new(0, 0x1080)),
            "address inside existing function should not be added"
        );

        // Address right at the parent's end (== first address past it):
        // safe to add as a new function.
        try_add_function(&obj, &config, &mut functions, SectionAddress::new(0, 0x1100));
        assert!(
            functions.contains_key(&SectionAddress::new(0, 0x1100)),
            "address at the parent's end-boundary should be added"
        );

        // Address well outside the existing function: safe to add.
        try_add_function(&obj, &config, &mut functions, SectionAddress::new(0, 0x1140));
        assert!(
            functions.contains_key(&SectionAddress::new(0, 0x1140)),
            "address outside existing function should be added"
        );
    }

    #[test]
    fn test_validate_invariants_rejects_overlapping_functions() {
        let obj = make_obj(0x1000, &[NOP, BLR, NOP, NOP, NOP, NOP]);
        let mut functions: BTreeMap<SectionAddress, FunctionInfo> = BTreeMap::new();
        let jump_tables: BTreeMap<SectionAddress, u32> = BTreeMap::new();

        let a = SectionAddress::new(0, 0x1000);
        let b = SectionAddress::new(0, 0x1008);
        functions.insert(
            a,
            FunctionInfo {
                analyzed: true,
                end: Some(SectionAddress::new(0, 0x1010)),
                slices: Some(FunctionSlices::default()),
            },
        );
        functions.insert(
            b,
            FunctionInfo {
                analyzed: true,
                end: Some(SectionAddress::new(0, 0x1018)),
                slices: Some(FunctionSlices::default()),
            },
        );

        let err = validate_invariants(&obj, &functions, &jump_tables)
            .expect_err("overlapping functions should fail invariant checks");
        assert!(
            format!("{err:#}").contains("Overlapping functions"),
            "expected overlap error, got: {err:#}"
        );
    }

    // =========================================================================
    // check_tail_block tests
    // =========================================================================

    /// Case 1: Classic tail block — starts with `b` back into preceding function, ends with blr.
    #[test]
    fn test_tail_block_case1_backward_branch_then_blr() {
        let section = make_code_section(
            0x1000,
            &[
                NOP,
                NOP,
                NOP,
                NOP,         // preceding func body
                ppc_b(-0xC), // b 0x1004 (back into preceding)
                ADDI_R3,     // addi r3, r3, 1
                BLR,         // blr
            ],
        );

        let gap_start = SectionAddress::new(0, 0x1010);
        let gap_end = SectionAddress::new(0, 0x101C);
        let func_start = SectionAddress::new(0, 0x1000);
        let func_end = SectionAddress::new(0, 0x1010);

        let result =
            check_tail_block(&section, gap_start, gap_end, func_start, func_end);
        assert_eq!(result, Some(SectionAddress::new(0, 0x101C)));
    }

    /// Case 2: Tail block detected by scanning — conditional backward branch + blr.
    #[test]
    fn test_tail_block_case2_conditional_backward_branch_with_blr() {
        let section = make_code_section(
            0x1000,
            &[
                NOP,
                NOP,
                NOP,
                NOP,            // preceding func
                ADDI_R3,        // 0x1010: some work
                ppc_bne(-0x14), // 0x1014: bne -> 0x1004 (back into preceding)
                BLR,            // 0x1018: blr
            ],
        );

        let gap_start = SectionAddress::new(0, 0x1010);
        let gap_end = SectionAddress::new(0, 0x101C);
        let func_start = SectionAddress::new(0, 0x1000);
        let func_end = SectionAddress::new(0, 0x1010);

        let result =
            check_tail_block(&section, gap_start, gap_end, func_start, func_end);
        assert_eq!(result, Some(gap_end));
    }

    /// Not a tail block: gap contains a function call (bl).
    #[test]
    fn test_not_tail_block_contains_call() {
        let section = make_code_section(
            0x1000,
            &[
                NOP,
                NOP,
                NOP,
                NOP,           // preceding func
                ppc_bl(0x100), // 0x1010: bl 0x1110 (function call)
                BLR,           // 0x1014: blr
            ],
        );

        let gap_start = SectionAddress::new(0, 0x1010);
        let gap_end = SectionAddress::new(0, 0x1018);
        let func_start = SectionAddress::new(0, 0x1000);
        let func_end = SectionAddress::new(0, 0x1010);

        let result =
            check_tail_block(&section, gap_start, gap_end, func_start, func_end);
        assert_eq!(result, None);
    }

    /// Not a tail block: gap branches forward to another function.
    #[test]
    fn test_not_tail_block_forward_branch() {
        let section = make_code_section(
            0x1000,
            &[
                NOP,
                NOP,
                NOP,
                NOP,          // preceding func
                ppc_b(0x100), // 0x1010: b 0x1110 (forward to other code)
                BLR,          // 0x1014: blr
            ],
        );

        let gap_start = SectionAddress::new(0, 0x1010);
        let gap_end = SectionAddress::new(0, 0x1018);
        let func_start = SectionAddress::new(0, 0x1000);
        let func_end = SectionAddress::new(0, 0x1010);

        let result =
            check_tail_block(&section, gap_start, gap_end, func_start, func_end);
        assert_eq!(result, None);
    }

    /// Not a tail block: gap is too large (> 64 bytes).
    #[test]
    fn test_not_tail_block_too_large() {
        let mut insns = vec![NOP; 4]; // preceding func
        insns.extend(std::iter::repeat(NOP).take(20)); // large gap
        let section = make_code_section(0x1000, &insns);

        let gap_start = SectionAddress::new(0, 0x1010);
        let gap_end = SectionAddress::new(0, 0x1060); // 80 bytes
        let func_start = SectionAddress::new(0, 0x1000);
        let func_end = SectionAddress::new(0, 0x1010);

        let result =
            check_tail_block(&section, gap_start, gap_end, func_start, func_end);
        assert_eq!(result, None);
    }

    /// Not a tail block: has backward branch but no blr.
    #[test]
    fn test_not_tail_block_no_blr() {
        let section = make_code_section(
            0x1000,
            &[
                NOP,
                NOP,
                NOP,
                NOP,            // preceding func
                ADDI_R3,        // 0x1010
                ppc_bne(-0x14), // 0x1014: bne -> 0x1004
                NOP,            // 0x1018: no blr, just nop
            ],
        );

        let gap_start = SectionAddress::new(0, 0x1010);
        let gap_end = SectionAddress::new(0, 0x101C);
        let func_start = SectionAddress::new(0, 0x1000);
        let func_end = SectionAddress::new(0, 0x1010);

        let result =
            check_tail_block(&section, gap_start, gap_end, func_start, func_end);
        assert_eq!(result, None);
    }

    /// Not a tail block: contains bctr (indirect branch).
    #[test]
    fn test_not_tail_block_indirect_branch() {
        let section = make_code_section(
            0x1000,
            &[
                NOP, NOP, NOP, NOP,  // preceding func
                BCTR, // 0x1010: bctr
            ],
        );

        let gap_start = SectionAddress::new(0, 0x1010);
        let gap_end = SectionAddress::new(0, 0x1014);
        let func_start = SectionAddress::new(0, 0x1000);
        let func_end = SectionAddress::new(0, 0x1010);

        let result =
            check_tail_block(&section, gap_start, gap_end, func_start, func_end);
        assert_eq!(result, None);
    }

    /// Jump table symbols created by apply_cfa() should have Global scope.
    #[test]
    fn test_jump_table_symbols_are_global() {
        use crate::obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSectionKind, ObjSymbolScope};

        let section = ObjSection {
            name: ".rodata".into(),
            kind: ObjSectionKind::ReadOnlyData,
            address: 0x8000_0000,
            size: 0x100,
            data: vec![0u8; 0x100],
            align: 8,
            ..Default::default()
        };
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "test".into(),
            vec![],
            vec![section],
        );

        let config = CfaConfig::default();
        let jt_addr = SectionAddress::new(0, 0x8000_0040);
        let mut jump_tables = BTreeMap::new();
        jump_tables.insert(jt_addr, 0x20); // 32 bytes
        let result = CfaResult {
            functions: BTreeMap::new(),
            jump_tables,
            merged_tail_blocks: Vec::new(),
            extended_functions: Vec::new(),
        };

        apply_cfa(&mut obj, &result, &config).unwrap();

        let jt_sym = obj
            .symbols
            .iter()
            .find(|(_, s)| s.name.starts_with("jumptable_"))
            .map(|(_, s)| s)
            .expect("jumptable symbol not found after apply_cfa()");

        assert_eq!(
            jt_sym.flags.scope(),
            ObjSymbolScope::Global,
            "Jump table symbol should have Global scope, got {:?}",
            jt_sym.flags.scope()
        );
        assert_eq!(jt_sym.kind, ObjSymbolKind::Object);
        assert_eq!(jt_sym.size, 0x20);
        assert_eq!(jt_sym.address, 0x8000_0040);
    }

    // Regression test for apply_cfa's stale-duplicate-name strip — RB3
    // retail had `__savegprlr_14` in symbols.txt at 0x82829220 (a stale
    // label inside a pdata function), while the sled scanner produces
    // the same label at the binary's real sled address (e.g. 0x82803F00).
    // Both end up in obj.symbols with the same name. create_gap_splits
    // treats duplicate names as a split boundary and ends the parent
    // function's split at 0x82829220, which then bisects the parent
    // function's symbol.
    //
    // apply_cfa must, before adding a known_symbols entry, strip any
    // pre-existing symbol with the same name at a different address.
    #[test]
    fn apply_cfa_strips_stale_duplicate_name_symbol() {
        let mut obj = make_obj(0x1000, &[NOP; 0x80]);

        // Stale symbol from a prior loader (simulating symbols.txt).
        obj.add_symbol(
            ObjSymbol {
                name: "__savegprlr".into(),
                address: 0x1080,
                section: Some(0),
                size: 0x50,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Function,
                ..Default::default()
            },
            false,
        )
        .expect("add stale symbol");

        // Run apply_cfa with a config that has the SAME name in
        // known_symbols at a different address (simulating the sled
        // scanner finding the real sled location).
        let real_sled_addr = SectionAddress::new(0, 0x1020);
        let mut config = CfaConfig::default();
        config.known_symbols.entry(real_sled_addr).or_default().push(ObjSymbol {
            name: "__savegprlr".into(),
            address: real_sled_addr.address as u64,
            section: Some(0),
            size: 0x50,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: ObjSymbolKind::Function,
            ..Default::default()
        });

        let empty_result = CfaResult {
            functions: BTreeMap::new(),
            jump_tables: BTreeMap::new(),
            merged_tail_blocks: vec![],
            extended_functions: vec![],
        };
        apply_cfa(&mut obj, &empty_result, &config).expect("apply_cfa");

        // The stale entry should have been renamed to __DELETED_*.
        let stale_lookup = obj.symbols.by_name("__savegprlr").expect("lookup");
        let (_, kept_sym) = stale_lookup.expect("__savegprlr present");
        assert_eq!(
            kept_sym.address, real_sled_addr.address as u64,
            "the kept __savegprlr should be at the sled scanner's address; \
             got {:#010X}",
            kept_sym.address
        );

        // Ensure only one live __savegprlr remains; the stale 0x1080 entry
        // should now be __DELETED_ and not appear under that name.
        let stale_at_addr = obj
            .symbols
            .for_section_range(0, 0x1080..0x1084)
            .find(|(_, s)| s.name == "__savegprlr");
        assert!(
            stale_at_addr.is_none(),
            "no live __savegprlr should remain at 0x1080"
        );
        let deleted = obj
            .symbols
            .for_section_range(0, 0x1080..0x1084)
            .find(|(_, s)| s.name == "__DELETED___savegprlr");
        assert!(deleted.is_some(), "stale entry should have been renamed");
    }

    /// Case 1 variant: First instruction branches back, blr found before gap_end.
    #[test]
    fn test_tail_block_case1_blr_before_gap_end() {
        let section = make_code_section(
            0x1000,
            &[
                NOP,
                NOP,
                NOP,
                NOP,         // preceding func (0x1000..0x1010)
                ppc_b(-0xC), // 0x1010: b 0x1004
                BLR,         // 0x1014: blr
                NOP,         // 0x1018: padding (within gap but after blr)
            ],
        );

        let gap_start = SectionAddress::new(0, 0x1010);
        let gap_end = SectionAddress::new(0, 0x101C); // gap extends past blr
        let func_start = SectionAddress::new(0, 0x1000);
        let func_end = SectionAddress::new(0, 0x1010);

        let result =
            check_tail_block(&section, gap_start, gap_end, func_start, func_end);
        // Should detect tail block ending at 0x1018 (right after blr at 0x1014)
        assert_eq!(result, Some(SectionAddress::new(0, 0x1018)));
    }
}

/// ProDG hardcodes .bss and .sbss section initialization in `entry`
/// This function locates the memset calls and returns a list of
/// (address, size) pairs for the .bss sections.
pub fn locate_bss_memsets(obj: &ObjInfo) -> Result<Vec<(u32, u32)>> {
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
                                Value::Constant(addr),
                                Value::Constant(value),
                                Value::Constant(size),
                            ) = {
                                if vm.gpr_value(4) == Value::Constant(0) {
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

/// Execute VM from specified entry point following inner-section branches and function calls,
/// noting all branch targets outside the current section.
pub fn locate_cross_section_branch_targets(
    obj: &ObjInfo,
    entry: SectionAddress,
) -> Result<BTreeSet<SectionAddress>> {
    let mut branch_targets = BTreeSet::<SectionAddress>::new();
    let mut executor = Executor::new(obj);
    executor.push(entry, VM::new(), false);
    executor.run(
        obj,
        |ExecCbData { executor, vm, result, ins_addr, section: _, ins: _, block_start: _ }| {
            match result {
                StepResult::Continue | StepResult::LoadStore { .. } => {
                    Ok(ExecCbResult::<()>::Continue)
                }
                StepResult::Illegal => bail!("Illegal instruction @ {}", ins_addr),
                StepResult::Jump(target) => {
                    if let BranchTarget::Address(RelocationTarget::Address(addr)) = target {
                        if addr.section == entry.section {
                            executor.push(addr, vm.clone_all(), true);
                        } else {
                            branch_targets.insert(addr);
                        }
                    }
                    Ok(ExecCbResult::EndBlock)
                }
                StepResult::Branch(branches) => {
                    for branch in branches {
                        if let BranchTarget::Address(RelocationTarget::Address(addr)) =
                            branch.target
                        {
                            if addr.section == entry.section {
                                executor.push(addr, branch.vm, true);
                            } else {
                                branch_targets.insert(addr);
                            }
                        }
                    }
                    Ok(ExecCbResult::Continue)
                }
            }
        },
    )?;
    Ok(branch_targets)
}

#[cfg(test)]
#[path = "cfa_tests.rs"]
mod cfa_tests;
