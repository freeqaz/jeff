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

/// How one entry of an Xbox 360 CRT save/restore sled is encoded, so the body
/// can be decoded and checked rather than trusted from an 8-byte needle.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum SledEncoding {
    /// One word per entry: `std`/`ld` (GPR, base r1) or `stfd`/`lfd` (FPR, base
    /// r12). Entry k is entry 0 with the register field (bits 6..10, i.e.
    /// `<< 21`) advanced by k and the signed displacement advanced by 8k.
    Scalar,
    /// Two words per entry: `li r11, disp` followed by a `stvx`/`lvx`-form
    /// store. Entry k advances `disp` by 0x10 and the vector register by one.
    /// The register field is `(k & 0x1F) << 21`; the VMX128 form used by the
    /// v64..v127 half carries bit 5 of the register number in bit 2 of the
    /// word, which is why the `& 0x1F` and the `>> 5` term are separate.
    Vector,
}

struct SledSpec {
    /// First two words of the sled, as bytes — the anchor `memmem` searches for.
    needle: [u8; 8],
    /// Name the XDK CRT gives the whole thunk (`__savegprlr`).
    func: &'static str,
    /// Prefix of the per-register entry names (`__savegprlr_`).
    label: &'static str,
    /// Inclusive-exclusive register range, so `14..32` yields `_14` … `_31`.
    reg_start: u32,
    reg_end: u32,
    enc: SledEncoding,
    /// Exact words expected after the last entry. Verified, and used to size
    /// the thunk when the image has no `.pdata` entry for it.
    tail: &'static [u32],
}

impl SledSpec {
    /// Bytes per register entry.
    fn step(&self) -> u32 {
        match self.enc {
            SledEncoding::Scalar => 4,
            SledEncoding::Vector => 8,
        }
    }

    fn entry_count(&self) -> u32 { self.reg_end - self.reg_start }

    /// Length of the verified body: every entry plus the tail.
    fn body_size(&self) -> u32 { self.entry_count() * self.step() + 4 * self.tail.len() as u32 }
}

const SLEDS_XBOX: [SledSpec; 8] = [
    SledSpec {
        needle: [0xf9, 0xc1, 0xff, 0x68, 0xf9, 0xe1, 0xff, 0x70],
        func: "__savegprlr",
        label: "__savegprlr_",
        reg_start: 14,
        reg_end: 32,
        enc: SledEncoding::Scalar,
        // stw r12, -8(r1) ; blr   — the caller left LR in r12.
        tail: &[0x9181fff8, 0x4e800020],
    },
    SledSpec {
        needle: [0xe9, 0xc1, 0xff, 0x68, 0xe9, 0xe1, 0xff, 0x70],
        func: "__restgprlr",
        label: "__restgprlr_",
        reg_start: 14,
        reg_end: 32,
        enc: SledEncoding::Scalar,
        // lwz r12, -8(r1) ; mtlr r12 ; blr
        tail: &[0x8181fff8, 0x7d8803a6, 0x4e800020],
    },
    SledSpec {
        needle: [0xd9, 0xcc, 0xff, 0x70, 0xd9, 0xec, 0xff, 0x78],
        func: "__savefpr",
        label: "__savefpr_",
        reg_start: 14,
        reg_end: 32,
        enc: SledEncoding::Scalar,
        tail: &[0x4e800020],
    },
    SledSpec {
        needle: [0xc9, 0xcc, 0xff, 0x70, 0xc9, 0xec, 0xff, 0x78],
        func: "__restfpr",
        label: "__restfpr_",
        reg_start: 14,
        reg_end: 32,
        enc: SledEncoding::Scalar,
        tail: &[0x4e800020],
    },
    SledSpec {
        needle: [0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x61, 0xce],
        func: "__savevmx",
        label: "__savevmx_",
        reg_start: 14,
        reg_end: 32,
        enc: SledEncoding::Vector,
        tail: &[0x4e800020],
    },
    SledSpec {
        needle: [0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x61, 0xcb],
        func: "__savevmx_upper",
        label: "__savevmx_",
        reg_start: 64,
        reg_end: 128,
        enc: SledEncoding::Vector,
        tail: &[0x4e800020],
    },
    SledSpec {
        needle: [0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x60, 0xce],
        func: "__restvmx",
        label: "__restvmx_",
        reg_start: 14,
        reg_end: 32,
        enc: SledEncoding::Vector,
        tail: &[0x4e800020],
    },
    SledSpec {
        needle: [0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x60, 0xcb],
        func: "__restvmx_upper",
        label: "__restvmx_",
        reg_start: 64,
        reg_end: 128,
        enc: SledEncoding::Vector,
        tail: &[0x4e800020],
    },
];

/// One save/restore sled located in a code section, with every per-register
/// entry address already checked against the instruction at that address.
#[derive(Clone, Debug)]
pub struct SledMatch {
    /// Family name (`__savegprlr`). Not a per-register entry name.
    pub func: &'static str,
    pub start: SectionAddress,
    /// Length of the verified body (entries + tail). Note this is NOT always
    /// the `.pdata` extent: the v14..v31 and v64..v127 VMX halves are two sleds
    /// inside one `.pdata` function.
    pub size: u32,
    /// `(address, name)` per register, in register order. Entry 0 is at `start`.
    pub entries: Vec<(SectionAddress, String)>,
}

fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// The word (or word pair) entry `k` must contain, derived from entry 0 as it
/// actually appears in the image. Nothing about the stack frame layout is
/// hardcoded — only the shape of the progression, which is the CRT's ABI.
fn sled_expected_words(enc: SledEncoding, first: &[u32], k: u32) -> [u32; 2] {
    match enc {
        SledEncoding::Scalar => [first[0].wrapping_add(k << 21).wrapping_add(k * 8), 0],
        SledEncoding::Vector => [
            first[0].wrapping_add(k * 0x10),
            first[1].wrapping_add((k & 0x1f) << 21).wrapping_add(((k >> 5) & 1) << 2),
        ],
    }
}

/// Locate the Xbox 360 CRT register save/restore sleds by their instruction
/// bodies.
///
/// The 8-byte needle only anchors the search; every remaining entry is then
/// required to be exactly the word the progression predicts, and the tail
/// (`blr`, plus the LR shuffle for the GPR pair) is required to be present. A
/// sled that does not decode is dropped with a warning rather than named, since
/// a wrong name here is worse than no name: it would be compared against the
/// decompiled object's `bl __savegprlr_25` and reported as a mismatch.
pub fn find_save_rest_sleds_xbox(obj: &ObjInfo) -> Vec<SledMatch> {
    let mut out = Vec::new();
    for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
        for spec in &SLEDS_XBOX {
            let Some(pos) = memmem::find(&section.data, &spec.needle) else {
                continue;
            };
            let start = SectionAddress::new(section_index, section.address as u32 + pos as u32);

            let first = [
                read_u32_be(&section.data, pos).unwrap_or(0),
                read_u32_be(&section.data, pos + 4).unwrap_or(0),
            ];
            let words_per_entry = (spec.step() / 4) as usize;

            // Verify every entry body.
            let mut ok = true;
            for k in 0..spec.entry_count() {
                let expected = sled_expected_words(spec.enc, &first, k);
                for w in 0..words_per_entry {
                    let off = pos + (k as usize * words_per_entry + w) * 4;
                    match read_u32_be(&section.data, off) {
                        Some(actual) if actual == expected[w] => {}
                        actual => {
                            log::warn!(
                                "{} @ {:#010X}: entry {}{} word {} is {:?}, expected {:#010X} — \
                                 not naming this sled",
                                spec.func,
                                start,
                                spec.label,
                                spec.reg_start + k,
                                w,
                                actual.map(|a| format!("{a:#010X}")),
                                expected[w],
                            );
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    break;
                }
            }
            if !ok {
                continue;
            }

            // Verify the tail.
            let tail_off = pos + (spec.entry_count() * spec.step()) as usize;
            for (i, &expected) in spec.tail.iter().enumerate() {
                let actual = read_u32_be(&section.data, tail_off + i * 4);
                if actual != Some(expected) {
                    log::warn!(
                        "{} @ {:#010X}: tail word {} is {:?}, expected {:#010X} — not naming \
                         this sled",
                        spec.func,
                        start,
                        i,
                        actual.map(|a| format!("{a:#010X}")),
                        expected,
                    );
                    ok = false;
                    break;
                }
            }
            if !ok {
                continue;
            }

            let entries = (0..spec.entry_count())
                .map(|k| {
                    (start + k * spec.step(), format!("{}{}", spec.label, spec.reg_start + k))
                })
                .collect();
            log::debug!(
                "Found {} @ {:#010X} ({} entries, body {:#x})",
                spec.func,
                start,
                spec.entry_count(),
                spec.body_size()
            );
            out.push(SledMatch {
                func: spec.func,
                start,
                size: spec.body_size(),
                entries,
            });
        }
    }
    out
}

/// Write the sled names straight into the object.
///
/// `FindSaveRestSledsXbox` only seeds `CfaConfig`, which means its names reach
/// the object exclusively through `apply_cfa` — and CFA is skipped entirely
/// when a project sets `symbols_known` (any title with a PDB or a map). On Halo
/// CEA that left all 236 entries unnamed: `load_analyze_xex` drops the PDB's
/// own `__savegprlr_*` publics via `is_reg_intrinsic` precisely because this
/// pass is supposed to re-derive them, so with CFA off nothing named them at
/// all. The relocation tracker then invented `lbl_<addr>` for each, and 68,006
/// call relocations across 2,545 of 3,675 split objects — ~37.8% of every
/// function in the image — could never match a decompiled `bl __savegprlr_25`
/// under objdiff's `name_only` relocation comparison.
///
/// Returns the number of symbols added.
pub fn apply_save_rest_sleds_xbox(obj: &mut ObjInfo) -> Result<usize> {
    let sleds = find_save_rest_sleds_xbox(obj);
    let mut added = 0usize;
    for sled in &sleds {
        // The family symbol names the whole thunk, and only exists as a
        // function when the image says one starts here. The VMX v64..v127 half
        // deliberately gets none: it is the back half of one `.pdata` function,
        // not a function of its own, and `__savevmx_upper` is dtk's label for
        // the search, not a name any linker ever emitted.
        if let Some(&Some(pdata_size)) = obj.known_functions.get(&sled.start) {
            if pdata_size < sled.size {
                log::warn!(
                    "{} @ {:#010X}: .pdata says {:#x} bytes but the body needs {:#x}",
                    sled.func,
                    sled.start,
                    pdata_size,
                    sled.size
                );
            }
            obj.add_symbol(
                ObjSymbol {
                    name: sled.func.to_string(),
                    address: sled.start.address as u64,
                    section: Some(sled.start.section),
                    size: pdata_size as u64,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Function,
                    ..Default::default()
                },
                true,
            )?;
            added += 1;
        }
        for (addr, name) in &sled.entries {
            // Labels, not functions: each entry falls through into the next, so
            // they are 18 (or 64) entry points into one body, and typing them as
            // functions would make every one of them truncate the extent of the
            // thunk that contains it.
            obj.add_symbol(
                ObjSymbol {
                    name: name.clone(),
                    address: addr.address as u64,
                    section: Some(addr.section),
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    ..Default::default()
                },
                true,
            )?;
            added += 1;
        }
    }
    if added > 0 {
        log::info!(
            "Named {} Xbox CRT save/restore sled symbol(s) across {} sled(s)",
            added,
            sleds.len()
        );
    }
    Ok(added)
}

// Runtime.PPCEABI.H.a runtime.c
impl AnalysisPass for FindSaveRestSledsXbox {
    fn execute(config: &mut CfaConfig, obj: &ObjInfo) -> Result<()> {
        for sled in find_save_rest_sleds_xbox(obj) {
            // add known symbols for them
            if let Some(&Some(known_func_size)) = obj.known_functions.get(&sled.start) {
                config.known_symbols.entry(sled.start).or_default().push(ObjSymbol {
                    name: sled.func.to_string(),
                    address: sled.start.address as u64,
                    section: Some(sled.start.section),
                    size: known_func_size as u64,
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    kind: ObjSymbolKind::Function,
                    ..Default::default()
                });
            } else if !sled.func.contains("_upper") {
                // Previously an `assert!`, which turned an unfamiliar image into
                // a panic in the middle of a 40 s split. The sled is still named
                // from its entries; only the family function symbol is lost.
                log::warn!(
                    "{} @ {:#010X} has no .pdata entry; naming its entries anyway",
                    sled.func,
                    sled.start
                );
            }
            for (addr, name) in sled.entries {
                config.known_symbols.entry(addr).or_default().push(ObjSymbol {
                    name,
                    address: addr.address as u64,
                    section: Some(addr.section),
                    size_known: true,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    ..Default::default()
                });
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
        let mut drop_user = 0u32;

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
                        &mut drop_user,
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
                &mut drop_user,
            );
        }

        log::info!(
            "FindXboxVtables: emitted {} vtable candidate(s) in {:?} \
             (dropped: short={} align={} skip={} hull={} user={})",
            candidates.len(),
            start_time.elapsed(),
            drop_short,
            drop_align,
            drop_skip,
            drop_hull,
            drop_user,
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
        drop_user: &mut u32,
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

        // User-symbol overlap exclusion. symbols.txt is authoritative for any
        // address range it covers; if a user-declared (non-synthetic) symbol
        // with a known nonzero size overlaps this candidate range, the
        // heuristic is wrong (it has either found the tail of a longer
        // user-declared vtable, or a sub-vtable inside a multi-inheritance
        // table). Emitting a `vftable_<addr>` here would later trip the
        // splitter's "ends within symbol" check because the synthetic symbol
        // spans across the next split boundary. Suppress entirely — the
        // user-declared symbol already covers this region.
        if Self::overlaps_user_symbol(obj, rdata_addr, cand_end) {
            *drop_user += 1;
            log::debug!(
                "FindXboxVtables: dropping vtable @ {:#010X} (overlaps user-declared symbol)",
                rdata_addr.address,
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

    /// Returns true if any user-declared symbol (i.e. a symbol with a known
    /// nonzero size that is NOT itself a previously-emitted `vftable_<addr>`
    /// synthetic) overlaps the candidate's [cand_start, cand_end) range.
    ///
    /// Two overlap cases are checked:
    ///   1. A symbol starts at or after cand_start but before cand_end.
    ///   2. A symbol starts strictly before cand_start but extends past it.
    fn overlaps_user_symbol(
        obj: &ObjInfo,
        cand_start: SectionAddress,
        cand_end: SectionAddress,
    ) -> bool {
        debug_assert_eq!(cand_start.section, cand_end.section);
        let section = cand_start.section;

        // Case 1: any symbol with address in [cand_start, cand_end).
        let any_inside = obj
            .symbols
            .for_section_range(section, cand_start.address..cand_end.address)
            .any(|(_, s)| Self::is_user_object_symbol(s));
        if any_inside {
            return true;
        }

        // Case 2: a symbol that starts strictly before cand_start but whose
        // size carries it past cand_start (i.e. cand_start lies *inside* an
        // already-declared symbol). Take the closest preceding symbol.
        if let Some((_, prev)) = obj
            .symbols
            .for_section_range(section, ..cand_start.address)
            .rfind(|(_, s)| Self::is_user_object_symbol(s))
        {
            let prev_end = (prev.address as u32).saturating_add(prev.size as u32);
            if prev_end > cand_start.address {
                return true;
            }
        }
        false
    }

    /// A symbol counts as user-declared for overlap purposes if:
    ///   * it has a known nonzero size (so we can reason about its extent),
    ///   * it isn't marked stripped (stripped symbols don't bind ranges),
    ///   * it isn't a synthetic `vftable_<addr>` we'd emit ourselves.
    ///
    /// We deliberately accept any kind (Object, Function, Section, etc.):
    /// if symbols.txt names this range, FindXboxVtables shouldn't
    /// second-guess it.
    fn is_user_object_symbol(s: &ObjSymbol) -> bool {
        s.size_known
            && s.size > 0
            && !s.flags.is_stripped()
            && !s.name.starts_with("vftable_")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::cfa::CfaConfig,
        obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind},
    };

    fn make_test_obj() -> ObjInfo {
        // .text @ 0x82000000 .. 0x82000040 — 16 nop instructions (room for
        // 16 distinct 4-byte function entry points). Function pointers in
        // the .rdata payload point into here.
        let text_bytes: Vec<u8> =
            std::iter::repeat(0x60u8) // 0x60000000 = nop
                .zip(std::iter::repeat([0x00u8, 0x00, 0x00]))
                .take(16)
                .flat_map(|(a, b)| [a, b[0], b[1], b[2]])
                .collect();

        // .rdata @ 0x82200000 .. 0x82200040 — 16 big-endian u32s, each
        // pointing at a unique .text address (0x82000000 + i*4). This gives
        // FindXboxVtables a single 16-pointer "vtable run".
        let mut rdata_bytes = Vec::with_capacity(0x40);
        for i in 0..16u32 {
            let v = 0x8200_0000u32 + i * 4;
            rdata_bytes.extend_from_slice(&v.to_be_bytes());
        }

        let sections = vec![
            ObjSection {
                name: ".text".into(),
                kind: ObjSectionKind::Code,
                address: 0x8200_0000,
                size: text_bytes.len() as u64,
                data: text_bytes,
                align: 4,
                ..Default::default()
            },
            ObjSection {
                name: ".rdata".into(),
                kind: ObjSectionKind::ReadOnlyData,
                address: 0x8220_0000,
                size: rdata_bytes.len() as u64,
                data: rdata_bytes,
                align: 4,
                ..Default::default()
            },
        ];

        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "vtable-test".into(),
            vec![],
            sections,
        );

        // Mark all 16 .text words as known functions so FindXboxVtables's
        // "fn pointer points at known_function" check accepts them.
        let text_idx = 0u32;
        for i in 0..16u32 {
            let sa = SectionAddress::new(text_idx, 0x8200_0000 + i * 4);
            obj.known_functions.insert(sa, Some(4));
        }

        obj
    }

    /// Without a user-declared overlapping symbol, the heuristic should
    /// happily emit a synthetic `vftable_<addr>` for our 16-pointer run.
    #[test]
    fn find_xbox_vtables_emits_when_no_user_symbol() {
        let obj = make_test_obj();
        let mut config = CfaConfig::default();
        let candidates =
            FindXboxVtables::execute_collect(&mut config, &obj).expect("execute_collect");
        assert_eq!(candidates.len(), 1, "expected 1 emitted candidate");
        let key = SectionAddress::new(1, 0x8220_0000);
        assert!(
            config.known_symbols.get(&key).is_some_and(|v| {
                v.iter().any(|s| s.name == "vftable_82200000")
            }),
            "expected vftable_82200000 in known_symbols",
        );
    }

    /// Regression for the DC3 `vftable_8226BC34` false positive: when a
    /// user-declared symbol already names a slice of the candidate run,
    /// FindXboxVtables MUST drop the synthetic instead of emitting one that
    /// would later overlap-collide with the user-declared symbol at split
    /// time.
    ///
    /// Setup mirrors the bug report: the candidate run is 16 pointers
    /// (0x82200000..0x82200040) and a user-declared object symbol covers
    /// the *tail* slice 0x82200010..0x82200040. That alone is the trigger
    /// — but we also test the "candidate starts strictly inside a longer
    /// preceding user symbol" case.
    #[test]
    fn find_xbox_vtables_skips_overlapping_user_symbol() {
        let mut obj = make_test_obj();
        obj.add_symbol(
            ObjSymbol {
                name: "??_7Foo@@6BBar@@@".into(),
                address: 0x8220_0010,
                section: Some(1),
                size: 0x30,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            false,
        )
        .expect("add user symbol");

        let mut config = CfaConfig::default();
        let candidates =
            FindXboxVtables::execute_collect(&mut config, &obj).expect("execute_collect");
        assert!(
            candidates.is_empty(),
            "expected 0 candidates due to user-symbol overlap, got {}",
            candidates.len(),
        );
        let key = SectionAddress::new(1, 0x8220_0000);
        assert!(
            config.known_symbols.get(&key).is_none()
                || !config
                    .known_symbols
                    .get(&key)
                    .unwrap()
                    .iter()
                    .any(|s| s.name.starts_with("vftable_")),
            "no synthetic vftable_<addr> should have been added",
        );
    }

    /// The "candidate start lies inside a longer preceding user symbol"
    /// case: user symbol at 0x82200000 size 0x40 fully covers the run.
    /// We must drop the synthetic.
    #[test]
    fn find_xbox_vtables_skips_when_inside_longer_user_symbol() {
        let mut obj = make_test_obj();
        obj.add_symbol(
            ObjSymbol {
                name: "??_7Whole@@6B@".into(),
                address: 0x8220_0000,
                section: Some(1),
                size: 0x40,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            false,
        )
        .expect("add user symbol");

        let mut config = CfaConfig::default();
        let candidates =
            FindXboxVtables::execute_collect(&mut config, &obj).expect("execute_collect");
        assert!(candidates.is_empty(), "expected 0 candidates");
    }

    /// A user symbol with size 0 or marked stripped must NOT block
    /// emission — these are labels, not range-binding declarations.
    #[test]
    fn find_xbox_vtables_ignores_zero_size_or_stripped_user_symbols() {
        let mut obj = make_test_obj();
        obj.add_symbol(
            ObjSymbol {
                name: "label_inside_vtable".into(),
                address: 0x8220_0010,
                section: Some(1),
                size: 0,
                size_known: false,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind: ObjSymbolKind::Object,
                ..Default::default()
            },
            false,
        )
        .expect("add label");

        let mut config = CfaConfig::default();
        let candidates =
            FindXboxVtables::execute_collect(&mut config, &obj).expect("execute_collect");
        assert_eq!(candidates.len(), 1, "zero-size label should not block emission");
    }
}
