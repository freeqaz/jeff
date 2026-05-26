use std::collections::BTreeMap;

use anyhow::{bail, ensure, Result};
use flagset::FlagSet;
use itertools::Itertools;
use memchr::memmem;

use crate::{
    analysis::cfa::{CfaConfig, FunctionInfo, SectionAddress},
    obj::{
        ObjInfo, ObjKind, ObjRelocKind, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind, SectionIndex,
    },
};

pub trait AnalysisPass {
    fn execute(config: &mut CfaConfig, obj: &ObjInfo) -> Result<()>;
}

pub struct FindTRKInterruptVectorTable {}

pub const TRK_TABLE_HEADER: &str = "Metrowerks Target Resident Kernel for PowerPC";
pub const TRK_TABLE_SIZE: u32 = 0x1F34; // always?

// TRK_MINNOW_DOLPHIN.a __exception.s
// NOTE: This pass reads seed_functions looking for analyzed non-functions.
// It was designed for mid-pipeline use in the DOL path and may not find
// matches when called before analysis (xex path doesn't use this pass).
impl AnalysisPass for FindTRKInterruptVectorTable {
    fn execute(config: &mut CfaConfig, obj: &ObjInfo) -> Result<()> {
        for (&start, _) in
            config.seed_functions.iter().filter(|(_, info)| info.analyzed && info.end.is_none())
        {
            let section = &obj.sections[start.section];
            let data = match section.data_range(start.address, 0) {
                Ok(ret) => ret,
                Err(_) => continue,
            };
            let trk_table_bytes = TRK_TABLE_HEADER.as_bytes();
            if data.starts_with(trk_table_bytes) && data[trk_table_bytes.len()] == 0 {
                log::debug!("Found gTRKInterruptVectorTable @ {:#010X}", start);
                config.known_symbols.entry(start).or_default().push(ObjSymbol {
                    name: "gTRKInterruptVectorTable".to_string(),
                    address: start.address as u64,
                    section: Some(start.section),
                    size_known: true,
                    flags: ObjSymbolFlagSet(FlagSet::from(ObjSymbolFlags::Global)),
                    ..Default::default()
                });
                let end = start + TRK_TABLE_SIZE;
                config.known_symbols.entry(end).or_default().push(ObjSymbol {
                    name: "gTRKInterruptVectorTableEnd".to_string(),
                    address: end.address as u64,
                    section: Some(start.section),
                    size_known: true,
                    flags: ObjSymbolFlagSet(FlagSet::from(ObjSymbolFlags::Global)),
                    ..Default::default()
                });

                return Ok(());
            }
        }
        log::debug!("gTRKInterruptVectorTable not found");
        Ok(())
    }
}

pub struct FindSaveRestSleds {}

#[allow(clippy::type_complexity)]
const SLEDS: [([u8; 8], &str, &str, u32, u32, u32); 6] = [
    ([0xd9, 0xcb, 0xff, 0x70, 0xd9, 0xeb, 0xff, 0x78], "__save_fpr", "_savefpr_", 14, 32, 4),
    ([0xc9, 0xcb, 0xff, 0x70, 0xc9, 0xeb, 0xff, 0x78], "__restore_fpr", "_restfpr_", 14, 32, 4),
    ([0x91, 0xcb, 0xff, 0xb8, 0x91, 0xeb, 0xff, 0xbc], "__save_gpr", "_savegpr_", 14, 32, 4),
    ([0x81, 0xcb, 0xff, 0xb8, 0x81, 0xeb, 0xff, 0xbc], "__restore_gpr", "_restgpr_", 14, 32, 4),
    ([0x39, 0x80, 0xff, 0x40, 0x7e, 0x8c, 0x01, 0xce], "_savevr", "_savev", 20, 32, 8),
    ([0x39, 0x80, 0xff, 0x40, 0x7e, 0x8c, 0x00, 0xce], "_restorevr", "_restv", 20, 32, 8),
];

// Runtime.PPCEABI.H.a runtime.c
impl AnalysisPass for FindSaveRestSleds {
    fn execute(config: &mut CfaConfig, obj: &ObjInfo) -> Result<()> {
        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            for (needle, func, label, reg_start, reg_end, step_size) in SLEDS {
                let Some(pos) = memmem::find(&section.data, &needle) else {
                    continue;
                };
                let start = SectionAddress::new(section_index, section.address as u32 + pos as u32);
                log::debug!("Found {} @ {:#010X}", func, start);
                let sled_size = (reg_end - reg_start) * step_size + 4 /* blr */;
                config.seed_functions.insert(start, FunctionInfo {
                    analyzed: false,
                    end: Some(start + sled_size),
                    slices: None,
                });
                config.known_symbols.entry(start).or_default().push(ObjSymbol {
                    name: func.to_string(),
                    address: start.address as u64,
                    section: Some(start.section),
                    size: sled_size as u64,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Function,
                    ..Default::default()
                });
                for i in reg_start..reg_end {
                    let addr = start + (i - reg_start) * step_size;
                    config.known_symbols.entry(addr).or_default().push(ObjSymbol {
                        name: format!("{label}{i}"),
                        address: addr.address as u64,
                        section: Some(start.section),
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(())
    }
}

pub struct FindSaveRestSledsXbox {}

#[allow(clippy::type_complexity)]
const SLEDS_XBOX: [([u8; 8], &str, &str, u32, u32, u32); 8] = [
    ([0xf9, 0xc1, 0xff, 0x68, 0xf9, 0xe1, 0xff, 0x70], "__savegprlr", "__savegprlr_", 14, 32, 4),
    ([0xe9, 0xc1, 0xff, 0x68, 0xe9, 0xe1, 0xff, 0x70], "__restgprlr", "__restgprlr_", 14, 32, 4),
    ([0xd9, 0xcc, 0xff, 0x70, 0xd9, 0xec, 0xff, 0x78], "__savefpr", "__savefpr_", 14, 32, 4),
    ([0xc9, 0xcc, 0xff, 0x70, 0xc9, 0xec, 0xff, 0x78], "__restfpr", "__restfpr_", 14, 32, 4),
    ([0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x61, 0xce], "__savevmx", "__savevmx_", 14, 32, 8),
    ([0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x61, 0xcb], "__savevmx_upper", "__savevmx_", 64, 128, 8),
    ([0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x60, 0xce], "__restvmx", "__restvmx_", 14, 32, 8),
    ([0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x60, 0xcb], "__restvmx_upper", "__restvmx_", 64, 128, 8),
];

// Runtime.PPCEABI.H.a runtime.c
impl AnalysisPass for FindSaveRestSledsXbox {
    fn execute(config: &mut CfaConfig, obj: &ObjInfo) -> Result<()> {
        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            for (needle, func, label, reg_start, reg_end, step_size) in SLEDS_XBOX {
                let Some(pos) = memmem::find(&section.data, &needle) else {
                    continue;
                };
                let start = SectionAddress::new(section_index, section.address as u32 + pos as u32);
                log::debug!("Found {} @ {:#010X}", func, start);

                // save/restore gpr/fpr/vmx should've been found in pdata
                if !func.contains("_upper") {
                    assert!(obj.known_functions.contains_key(&start),
                        "Could not find reg intrinsic from pdata. Is that even possible for an xex?");
                }
                // add known symbols for them
                if obj.known_functions.contains_key(&start) {
                    let known_func_size = obj.known_functions.get(&start).unwrap().unwrap();
                    config.known_symbols.entry(start).or_default().push(ObjSymbol {
                        name: func.to_string(),
                        address: start.address as u64,
                        section: Some(start.section),
                        size: known_func_size as u64,
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                        kind: ObjSymbolKind::Function,
                        ..Default::default()
                    });
                }
                for i in reg_start..reg_end {
                    let addr = start + (i - reg_start) * step_size;
                    config.known_symbols.entry(addr).or_default().push(ObjSymbol {
                        name: format!("{label}{i}"),
                        address: addr.address as u64,
                        section: Some(start.section),
                        size_known: true,
                        flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// FindXboxVtables — rb3-xenon enhancement (NOT for upstream yet)
// =============================================================================
//
// Scans .rdata-kind sections for runs of u32 big-endian values that point
// into a single .text section's known_functions map. Each accepted run is
// surfaced two ways:
//   - A synthetic `vftable_<addr>` ObjSymbol pushed onto CfaConfig.known_symbols
//     so CFA treats the function-pointer payload as authoritative seeds.
//   - A `VtableCandidate` record returned from `execute_collect` for the
//     proposed_splits.txt writer in util/proposed_splits.rs.
//
// FP-mitigation filters per the rb3-xenon plan:
//   * 8-byte alignment of run start (vtables are pointer-aligned in MSVC).
//   * 64 KB cap on the implied .text hull (drops cross-TU inherited cases).
//   * No overlap with CfaConfig.skip_ranges (existing jump-table regions).

/// One detected vtable candidate. Buffered for downstream consumers
/// (e.g. proposed_splits.txt emitter).
#[derive(Debug, Clone)]
pub struct VtableCandidate {
    pub rdata_addr: SectionAddress,
    pub fn_count: u32,
    /// Virtuals in vtable order.
    pub fn_addrs: Vec<SectionAddress>,
    /// (low, high_exclusive) over fn_addrs, inflated by size of last fn.
    pub text_hull: (SectionAddress, SectionAddress),
    /// 0x19930521 or 0x19930522 within +/-0x40 of rdata_addr, if any.
    pub eh_magic_nearby: Option<u32>,
}

pub struct FindXboxVtables {}

impl FindXboxVtables {
    pub const MIN_RUN: u32 = 4;
    pub const MAX_TEXT_HULL: u32 = 0x10000;
    pub const EH_PROBE_RANGE: i32 = 0x40;
    /// Required alignment of vtable start in .rdata. MSVC emits vftables
    /// pointer-aligned. On Xbox 360 (PPC32) pointers are 4-byte; the plan
    /// suggested trying 8 first, but empirically that drops recall to ~6% on
    /// RB3 retail (~157/2741), so we use 4 to match actual layout.
    pub const VTABLE_ALIGN: u32 = 4;

    /// Returns the collected candidates so the caller (xex.rs split/disasm path)
    /// can also write them to proposed_splits.txt. The known_symbols side-effect
    /// happens regardless of whether the result is consumed.
    pub fn execute_collect(
        config: &mut CfaConfig,
        obj: &ObjInfo,
    ) -> Result<Vec<VtableCandidate>> {
        let start_time = std::time::Instant::now();
        let mut drop_short = 0u32;
        let mut drop_align = 0u32;
        let mut drop_skip = 0u32;
        let mut drop_hull = 0u32;

        // Precompute (section_idx, base_addr, end_exclusive) for every text
        // section so we can identify which one a candidate fn pointer belongs to
        // without iterating obj.sections for each u32.
        let text_sections: Vec<(SectionIndex, u32, u32)> = obj
            .sections
            .by_kind(ObjSectionKind::Code)
            .map(|(idx, sec)| {
                let base = sec.address as u32;
                (idx, base, base.wrapping_add(sec.size as u32))
            })
            .collect();

        if text_sections.is_empty() {
            log::debug!("FindXboxVtables: no code sections, skipping");
            return Ok(Vec::new());
        }

        let mut candidates: Vec<VtableCandidate> = Vec::new();

        for (rdata_idx, section) in obj.sections.by_kind(ObjSectionKind::ReadOnlyData) {
            let section_base = section.address as u32;
            let data = &section.data;
            let usable_len = data.len() & !3; // 4-byte aligned

            // Pre-collect EH-magic offsets in this section for quick neighborhood
            // probes. Cheap: ~10 KB on RB3 retail rdata.
            let eh_magic_offsets: Vec<u32> = (0..usable_len)
                .step_by(4)
                .filter_map(|i| {
                    let v = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                    if v == 0x19930521 || v == 0x19930522 {
                        Some(section_base + i as u32)
                    } else {
                        None
                    }
                })
                .collect();
            let eh_set: BTreeMap<u32, u32> = eh_magic_offsets
                .iter()
                .map(|&addr| {
                    let off = (addr - section_base) as usize;
                    let v = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                    (addr, v)
                })
                .collect();

            // Walk the section in 4-byte words and accumulate runs.
            let mut run_start_off: Option<usize> = None;
            let mut run_text_sec: SectionIndex = 0;
            let mut run_fns: Vec<SectionAddress> = Vec::new();

            let mut i = 0usize;
            while i < usable_len {
                let v = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                // Identify which (if any) text section contains v.
                let hit = text_sections
                    .iter()
                    .find(|(_, base, end)| v >= *base && v < *end)
                    .and_then(|(idx, _, _)| {
                        let sa = SectionAddress::new(*idx, v);
                        if obj.known_functions.contains_key(&sa) {
                            Some(sa)
                        } else {
                            None
                        }
                    });

                let extends_run = match (run_start_off, &hit) {
                    (Some(_), Some(sa)) => sa.section == run_text_sec,
                    _ => false,
                };

                if extends_run {
                    run_fns.push(hit.unwrap());
                } else {
                    // Run terminated (or never started). Emit if it qualifies.
                    Self::maybe_emit(
                        config,
                        &mut candidates,
                        obj,
                        rdata_idx,
                        section_base,
                        run_start_off,
                        &run_fns,
                        &eh_set,
                        &mut drop_short,
                        &mut drop_align,
                        &mut drop_skip,
                        &mut drop_hull,
                    );

                    if let Some(sa) = hit {
                        run_start_off = Some(i);
                        run_text_sec = sa.section;
                        run_fns.clear();
                        run_fns.push(sa);
                    } else {
                        run_start_off = None;
                        run_fns.clear();
                    }
                }

                i += 4;
            }

            // Flush trailing run.
            Self::maybe_emit(
                config,
                &mut candidates,
                obj,
                rdata_idx,
                section_base,
                run_start_off,
                &run_fns,
                &eh_set,
                &mut drop_short,
                &mut drop_align,
                &mut drop_skip,
                &mut drop_hull,
            );
        }

        log::info!(
            "FindXboxVtables: emitted {} vtable candidate(s) in {:?} \
             (dropped: short={} align={} skip={} hull={})",
            candidates.len(),
            start_time.elapsed(),
            drop_short,
            drop_align,
            drop_skip,
            drop_hull,
        );

        Ok(candidates)
    }

    /// Validate one accumulated run and, if it passes filters, push it onto
    /// `candidates` AND register a synthetic `vftable_<addr>` known_symbol.
    #[allow(clippy::too_many_arguments)]
    fn maybe_emit(
        config: &mut CfaConfig,
        candidates: &mut Vec<VtableCandidate>,
        obj: &ObjInfo,
        rdata_idx: SectionIndex,
        section_base: u32,
        run_start_off: Option<usize>,
        run_fns: &[SectionAddress],
        eh_set: &BTreeMap<u32, u32>,
        drop_short: &mut u32,
        drop_align: &mut u32,
        drop_skip: &mut u32,
        drop_hull: &mut u32,
    ) {
        let run_start_off = match run_start_off {
            Some(o) => o,
            None => return,
        };
        let run_len = run_fns.len() as u32;
        if run_len < Self::MIN_RUN {
            *drop_short += 1;
            return;
        }

        let rdata_addr = SectionAddress::new(rdata_idx, section_base + run_start_off as u32);

        // Alignment filter — MSVC vftables are pointer-aligned (8 on x64, 4 on
        // PPC32, but empirical signal supports 8-byte). Conservative for FP.
        if !rdata_addr.is_aligned(Self::VTABLE_ALIGN) {
            *drop_align += 1;
            return;
        }

        // Skip-range exclusion — never overlap a recorded jump-table region.
        // skip_ranges is BTreeMap<start, end_exclusive>. Find the entry with
        // largest start <= rdata_addr; check for half-open interval overlap.
        let cand_end = rdata_addr + run_len * 4;
        if Self::overlaps_skip_range(&config.skip_ranges, rdata_addr, cand_end) {
            *drop_skip += 1;
            return;
        }

        // Compute text hull. If we can't recover the last fn's size, fall back
        // to 4 (one instruction) — known to under-estimate the hull but fine
        // for the cap check.
        let first_fn = *run_fns.first().unwrap();
        let last_fn = *run_fns.last().unwrap();
        let last_fn_size = obj
            .known_functions
            .get(&last_fn)
            .and_then(|sz| *sz)
            .unwrap_or(4);
        let hull_start = run_fns.iter().min().copied().unwrap_or(first_fn);
        let hull_end_inclusive_addr = run_fns
            .iter()
            .max()
            .copied()
            .unwrap_or(last_fn);
        let hull_end = SectionAddress::new(
            hull_end_inclusive_addr.section,
            hull_end_inclusive_addr.address.saturating_add(last_fn_size),
        );

        if hull_end.section != hull_start.section {
            // Should be impossible — run terminates on section mismatch — but
            // defend anyway.
            return;
        }
        let hull_bytes = hull_end.address.saturating_sub(hull_start.address);
        if hull_bytes > Self::MAX_TEXT_HULL {
            *drop_hull += 1;
            log::debug!(
                "FindXboxVtables: dropping vtable @ {:#010X} (text hull {:#X} > {:#X})",
                rdata_addr.address, hull_bytes, Self::MAX_TEXT_HULL
            );
            return;
        }

        // Optional EH-magic neighborhood probe (informational only).
        let probe_lo = rdata_addr.address.saturating_sub(Self::EH_PROBE_RANGE as u32);
        let probe_hi = rdata_addr.address.saturating_add(Self::EH_PROBE_RANGE as u32);
        let eh_magic_nearby = eh_set
            .range(probe_lo..=probe_hi)
            .next()
            .map(|(_, v)| *v);

        // Side effect 1: emit vftable_<addr> known_symbol so CFA + downstream
        // treat the run as an authoritative function-pointer array.
        config
            .known_symbols
            .entry(rdata_addr)
            .or_default()
            .push(ObjSymbol {
                name: format!("vftable_{:08X}", rdata_addr.address),
                address: rdata_addr.address as u64,
                section: Some(rdata_addr.section),
                size: (run_len * 4) as u64,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            });

        // Side effect 2: buffer the VtableCandidate for the writer.
        candidates.push(VtableCandidate {
            rdata_addr,
            fn_count: run_len,
            fn_addrs: run_fns.to_vec(),
            text_hull: (hull_start, hull_end),
            eh_magic_nearby,
        });
    }

    fn overlaps_skip_range(
        skip_ranges: &BTreeMap<SectionAddress, SectionAddress>,
        cand_start: SectionAddress,
        cand_end: SectionAddress,
    ) -> bool {
        if let Some((&start, &end)) = skip_ranges.range(..=cand_end).next_back() {
            if start.section == cand_start.section
                && end.section == cand_start.section
                && start.address < cand_end.address
                && end.address > cand_start.address
            {
                return true;
            }
        }
        false
    }
}

impl AnalysisPass for FindXboxVtables {
    fn execute(config: &mut CfaConfig, obj: &ObjInfo) -> Result<()> {
        let _ = Self::execute_collect(config, obj)?;
        Ok(())
    }
}

pub struct FindRelCtorsDtors {}

impl AnalysisPass for FindRelCtorsDtors {
    fn execute(config: &mut CfaConfig, obj: &ObjInfo) -> Result<()> {
        ensure!(obj.kind == ObjKind::Relocatable);

        match (obj.sections.by_name(".ctors")?, obj.sections.by_name(".dtors")?) {
            (Some(_), Some(_)) => return Ok(()),
            (None, None) => {}
            _ => bail!("Only one of .ctors and .dtors has been found?"),
        }

        let possible_sections = obj
            .sections
            .iter()
            .filter(|&(index, section)| {
                if section.section_known
                    || config.known_sections.contains_key(&index)
                    || !matches!(section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData)
                    || section.size < 4
                {
                    return false;
                }

                let mut current_address = section.address as u32;
                let section_end = current_address + section.size as u32;
                while let Some(reloc) = obj.unresolved_relocations.iter().find(|reloc| {
                    reloc.module_id == obj.module_id
                        && reloc.section as SectionIndex == section.elf_index
                        && reloc.address == current_address
                        && reloc.kind == ObjRelocKind::Absolute
                }) {
                    let Some((target_section_index, target_section)) =
                        obj.sections.iter().find(|(_, section)| {
                            section.elf_index == reloc.target_section as SectionIndex
                        })
                    else {
                        return false;
                    };
                    if target_section.kind != ObjSectionKind::Code
                        || !config
                            .seed_functions
                            .contains_key(&SectionAddress::new(target_section_index, reloc.addend))
                    {
                        return false;
                    }
                    current_address += 4;
                    if current_address >= section_end {
                        return false;
                    }
                }
                if current_address + 4 != section_end {
                    return false;
                }
                section.data_range(section_end - 4, section_end).ok() == Some(&[0; 4])
            })
            .collect_vec();

        if possible_sections.len() != 2 {
            log::debug!("Failed to find .ctors and .dtors");
            return Ok(());
        }

        log::debug!(
            "Found .ctors and .dtors: {}, {}",
            possible_sections[0].0,
            possible_sections[1].0
        );
        let ctors_section_index = possible_sections[0].0;
        let ctors_address = SectionAddress::new(ctors_section_index, 0);
        config.known_sections.insert(ctors_section_index, ".ctors".to_string());
        config.known_symbols.entry(ctors_address).or_default().push(ObjSymbol {
            name: "_ctors".to_string(),
            section: Some(ctors_section_index),
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            ..Default::default()
        });

        let dtors_section_index = possible_sections[1].0;
        let dtors_address = SectionAddress::new(dtors_section_index, 0);
        config.known_sections.insert(dtors_section_index, ".dtors".to_string());
        config.known_symbols.entry(dtors_address).or_default().push(ObjSymbol {
            name: "_dtors".to_string(),
            section: Some(dtors_section_index),
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            ..Default::default()
        });

        Ok(())
    }
}

pub struct FindRelRodataData {}

impl AnalysisPass for FindRelRodataData {
    fn execute(config: &mut CfaConfig, obj: &ObjInfo) -> Result<()> {
        ensure!(obj.kind == ObjKind::Relocatable);

        match (obj.sections.by_name(".rodata")?, obj.sections.by_name(".data")?) {
            (None, None) => {}
            _ => return Ok(()),
        }

        let possible_sections = obj
            .sections
            .iter()
            .filter(|&(index, section)| {
                !section.section_known
                    && !config.known_sections.contains_key(&index)
                    && matches!(section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData)
            })
            .collect_vec();

        if possible_sections.len() != 2 {
            log::debug!("Failed to find .rodata and .data");
            return Ok(());
        }

        log::debug!(
            "Found .rodata and .data: {}, {}",
            possible_sections[0].0,
            possible_sections[1].0
        );
        let rodata_section_index = possible_sections[0].0;
        config.known_sections.insert(rodata_section_index, ".rodata".to_string());

        let data_section_index = possible_sections[1].0;
        config.known_sections.insert(data_section_index, ".data".to_string());

        Ok(())
    }
}
