use std::{
    collections::BTreeMap,
    fs,
    fs::{DirBuilder, File},
    io::{BufWriter, Write},
    time::UNIX_EPOCH,
};

use anyhow::{bail, ensure, Context, Ok, Result};
use argp::FromArgs;
use chrono::FixedOffset;
use itertools::Itertools;
use object::{
    read::pe::PeFile32,
    write::{Object, Relocation, SectionId, Symbol, SymbolId, SymbolSection},
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags, SymbolKind,
    SymbolScope,
};
use tracing::{debug, info};
use typed_path::{Utf8NativePath, Utf8NativePathBuf};
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    analysis::{
        cfa::{CfaConfig, SectionAddress, run_cfa, apply_cfa},
        objects::{detect_objects, detect_strings},
        pass::{AnalysisPass, FindSaveRestSledsXbox, FindXboxVtables, VtableCandidate},
        tracker::Tracker,
    },
    cmd::dol::{
        apply_add_relocations, apply_block_relocations, ModuleConfig, OutputConfig, OutputModule,
        OutputUnit, ProjectConfig,
    },
    obj::{
        best_match_for_reloc, ObjInfo, ObjKind, ObjRelocKind, ObjSectionKind, ObjSections,
        ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjSymbolScope, SectionIndex,
        SymbolIndex,
    },
    util::{
        asm::write_asm,
        config::{apply_splits_file, apply_symbols_file, write_splits_file, write_symbols_file},
        dep::DepFile,
        file::{buf_writer, FileReadInfo},
        map_exe::{apply_map_file_exe, is_reg_intrinsic, process_map_exe},
        path::native_path,
        proposed_splits::write_proposed_splits,
        split::{split_obj, update_splits},
        xex::{
            coff_path_for_unit, extract_exe, genuine_except_data_set, list_exe_sections,
            process_xex, write_coff, XexCompression, XexEncryption, XexInfo,
        },
        xpdb::try_parse_pdb,
    },
    vfs::open_file,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing Xex files.
#[argp(subcommand, name = "xex")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Disasm(DisasmArgs),
    Extract(ExtractArgs),
    Info(InfoArgs),
    Map(MapArgs),
    Pdb(PdbArgs),
    Split(SplitArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Disassembles an Xex file.
#[argp(subcommand, name = "disasm")]
pub struct DisasmArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file
    xex_file: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// output file (.o) or directory (.elf)
    out: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Extracts an exe from an Xex file.
#[argp(subcommand, name = "extract")]
pub struct ExtractArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file
    xex_file: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Prints information about an Xex file.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file
    input: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Prints information about an Xex map file.
#[argp(subcommand, name = "map")]
pub struct MapArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file
    input: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Prints information about a Xenon PDB.
#[argp(subcommand, name = "pdb")]
pub struct PdbArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file
    input: Utf8NativePathBuf,
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Splits an xex into relocatable objects.
#[argp(subcommand, name = "split")]
pub struct SplitArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input configuration file
    config: Utf8NativePathBuf,
    #[argp(positional, from_str_fn(native_path))]
    /// output directory
    out_dir: Utf8NativePathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Disasm(c_args) => disasm(c_args),
        SubCommand::Extract(c_args) => extract(c_args),
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Map(c_args) => map(c_args),
        SubCommand::Pdb(c_args) => pdb(c_args),
        SubCommand::Split(c_args) => split(c_args),
    }
}

struct ExeAnalyzeResult {
    pub obj: ObjInfo,
    pub dep: Vec<Utf8NativePathBuf>,
    pub symbols_cache: Option<FileReadInfo>,
    pub splits_cache: Option<FileReadInfo>,
    /// Vtable candidates surfaced by FindXboxVtables (rb3-xenon enhancement).
    /// Drained by `split` to write `proposed_splits.txt` next to config.json.
    pub vtable_candidates: Vec<VtableCandidate>,
}

struct ExeModuleInfo<'a> {
    obj: ObjInfo,
    config: &'a ModuleConfig,
    symbols_cache: Option<FileReadInfo>,
    splits_cache: Option<FileReadInfo>,
    dep: Vec<Utf8NativePathBuf>,
}

// look at dol split for this
fn split(args: SplitArgs) -> Result<()> {
    info!("Loading {}", args.config);
    let config: ProjectConfig = {
        let mut config_file = open_file(&args.config, true)?;
        serde_yaml::from_reader(config_file.as_mut())?
    };
    // println!("{:?}", config);

    // config.base.object: the path to the xex as a Utf8UnixPathBuf
    // config.base.splits: the path to the splits.txt as a Utf8UnixPathBuf
    // config.base.symbols: the path to the symbols.txt as a Utf8UnixPathBuf
    // config.base.map: the path to the map as a Utf8UnixPathBuf, if it exists

    // get config.json path and create DepFile from it
    let out_config_path = args.out_dir.join("config.json");
    let mut dep = DepFile::new(out_config_path.clone());

    // load_analyze_dol is called here, takes in ProjectConfig and ObjectBase and returns a Result<AnalyzeResult>
    // load_dol_module - returns a Result<(ObjInfo, Utf8NativePathBuf)> - process_xex, then the path of the object
    info!("Loading and analyzing xex");
    let xex_result: Option<Result<ExeAnalyzeResult>> = Some(load_analyze_xex(&config));
    let (mut exe, vtable_candidates) = {
        let result = xex_result.unwrap()?;
        dep.extend(result.dep);
        let module = ExeModuleInfo {
            obj: result.obj,
            config: &config.base,
            symbols_cache: result.symbols_cache,
            splits_cache: result.splits_cache,
            dep: Default::default(),
        };
        (module, result.vtable_candidates)
    };
    let function_count = exe.obj.symbols.by_kind(ObjSymbolKind::Function).count();
    info!("Initial analysis completed (found {} functions)", function_count);

    // extract and write exe
    let (exe_name, exe_bytes) = extract_exe(&config.base.object.with_encoding())?;

    // Create out dirs
    DirBuilder::new().recursive(true).create(&args.out_dir)?;

    // rb3-xenon: emit proposed_splits.txt next to config.json. Paste-bait for
    // splits.txt — not consumed by jeff itself. See util::proposed_splits.
    {
        let proposed_path = args.out_dir.join("proposed_splits.txt");
        info!(
            "Writing {} ({} vtable candidate(s))",
            proposed_path,
            vtable_candidates.len()
        );
        write_proposed_splits(&proposed_path, &exe.obj, &vtable_candidates)?;
    }

    // write the exe in the same dir the xex is
    let exe_path: Utf8NativePathBuf =
        config.base.object.with_encoding().parent().unwrap().join(&exe_name);
    info!("Extracting exe to {exe_path}");
    std::fs::write(exe_path, exe_bytes)?;

    info!("Rebuilding relocations and splitting");
    // dol split_write_obj
    let output_module = split_write_obj_exe(&mut exe, &config, &args.out_dir)?;
    // here, out_config = OutputConfig { the result of split_write_obj }
    let out_config = OutputConfig {
        version: env!("CARGO_PKG_VERSION").to_string(),
        base: output_module,
        modules: vec![],
        links: vec![],
    };

    // Write output config here
    {
        let mut out_file = buf_writer(&out_config_path)?;
        serde_json::to_writer_pretty(&mut out_file, &out_config)?;
        out_file.flush()?;
    }

    // Write dep file here
    dep.extend(exe.dep);
    {
        let dep_path = args.out_dir.join("dep");
        let mut dep_file = buf_writer(&dep_path)?;
        dep.write(&mut dep_file)?;
        dep_file.flush()?;
    }

    info!("Done!");
    Ok(())
}

/// Remove spurious overlapping function symbols left over from CFA speculation
/// or a stale `symbols.txt` cache.
///
/// ## The bug this fixes
///
/// dtk's symbol set occasionally contains a "phantom" function symbol whose
/// `[address, address + size)` range straddles the boundaries of one or more
/// *real* functions. For example, in RB3's `framing.c` cluster:
///
/// ```text
///   fn_82BF8D80  size 0xE4  -> ogg_page_checksum_set (real leaf, has callers)
///   fn_82BF8E48  size 0x94  -> PHANTOM: starts inside D80's tail, ends inside EA0
///   fn_82BF8E68  size 0x34  -> ogg_stream_clear      (real, pdata-anchored)
///   fn_82BF8EA0  size 0x54  -> ogg_stream_destroy    (real, pdata-anchored)
/// ```
///
/// `write_coff` carves one COFF section per function symbol from the section
/// bytes. When a phantom overlaps real functions, it captures their bytes into
/// *its* section and leaves the real functions' COMDAT sections zero-filled.
/// objdiff then resolves the real symbols to those empty sections and scores
/// them 0% / all-`<illegal>`. The human-readable asm shows the same corruption
/// as mis-nested `.fn`/`.endfn` directives.
///
/// ## The discriminator
///
/// A phantom is identified structurally + semantically. A symbol is pruned only
/// if ALL of:
///   1. it is a `Function` symbol in a code section, and
///   2. its range *overlaps* another function symbol's range, and
///   3. it is **not** anchored by a `.pdata` unwind entry, and
///   4. it has **zero incoming references** (no relocation anywhere in the
///      module targets it — i.e. nothing calls it or takes its address).
///
/// The load-bearing gate is condition (2): a *well-formed* function has a
/// correct size and therefore does not overlap its neighbors at all, so it is
/// never even a deletion candidate — regardless of whether it is referenced.
/// Conditions (3) and (4) only decide the fate of symbols that DO overlap:
/// among the overlapping set, pdata-anchored functions (3) and call/address
/// targets (4) are kept, leaving only ranges that nothing describes and nothing
/// references — genuine CFA / stale-cache garbage.
///
/// ## Residual false-positive risk (audited, not eliminated)
///
/// Conditions (3) and (4) are NOT independently sufficient to protect every
/// real function. A real function that is *both* (a) mis-sized so its range
/// bleeds into a neighbor and (b) unreferenced within this module and absent
/// from `.pdata` would be pruned. The plausible carriers of that combination
/// are tail-call `b` thunks, vtable-/indirect-call-only entries, and XEX
/// exports (referenced from outside the module). This is believed rare — a
/// correctly-sized symbol can't trip condition (2) — but it is not provably
/// impossible. Therefore every prune is emitted to the log at `info` with its
/// name, address, size, and the address it overlaps, so a regression in a
/// pinned unit can be traced back to a specific stripped symbol by grepping the
/// split log rather than guessing. Treat an unexpected match regression after a
/// jeff bump as "grep the log for `Pruning phantom`" first.
///
/// Pruned symbols are renamed to `__DELETED_<name>` with the same stripped
/// flags the CFA tail-block / stale-duplicate logic uses (see
/// `analysis::cfa::apply_cfa`), so downstream `split_obj` / `write_coff` ignore
/// them without re-indexing the symbol table.
/// Clamp oversized function symbols down to their authoritative length before
/// pruning runs.
///
/// ## The bug this fixes
///
/// CFA / a stale `symbols.txt` cache frequently records a function symbol whose
/// `size` is LARGER than the function's true length, so its
/// `[address, address + size)` range straddles one or more *real* neighbor
/// functions. `write_coff` carves one COFF section per function symbol from the
/// section bytes; an oversized symbol captures its neighbors' bytes into *its*
/// section, leaving the real neighbors' COMDAT sections starved. objdiff then
/// scores those neighbors 0% / all-`<illegal>`. This is the same corruption the
/// phantom prune addresses, except here the oversized symbol is itself a real,
/// pdata-anchored or referenced function — the prune correctly spares it, so it
/// stays oversized and keeps clobbering its neighbors.
///
/// The downstream pin-ranker (`tools/pin_candidates.py`) additionally refuses
/// any pin span that touches an overlap region, so every oversized symbol
/// poisons whole TUs for pinning, not just the immediate neighbor.
///
/// ## The two authoritative length oracles
///
/// 1. `.pdata` (`obj.known_functions`) gives the EXACT length of every
///    pdata-anchored function. A pdata-anchored symbol sized larger than its
///    `.pdata` length is unambiguously wrong; we clamp it to the `.pdata`
///    length. This is provably safe — the `.pdata` table is a clean partition
///    of `.text`: no entry's `[start, start+len)` ever overruns the next entry's
///    start (verified across all 56,836 RB3 `.text` entries).
///
/// 2. For a NON-pdata-anchored function symbol that straddles a pdata-anchored
///    neighbor's start, the next pdata start is a hard function boundary the
///    symbol cannot legitimately cross (it would mean two real functions share
///    one symbol). We clamp such a symbol to end exactly at the first
///    pdata-anchored start it would otherwise swallow. These symbols are CFA
///    artifacts (their first instruction is padding / a mid-function branch
///    target, not a prologue); clamping restores the real boundary without
///    deleting the referenced entry the prune must keep.
///
/// Neither clamp ever *grows* a symbol or touches a correctly-sized one, so it
/// can only shrink genuine overruns. Every clamp is logged at `info` for audit,
/// mirroring the prune's policy.
fn clamp_oversized_function_symbols(obj: &mut ObjInfo) {
    use std::collections::BTreeMap as StdBTreeMap;

    // (1) Per code section, the sorted list of pdata-anchored function starts
    //     (a hard boundary set) and the exact length of each.
    let mut pdata_starts: StdBTreeMap<SectionIndex, Vec<u64>> = StdBTreeMap::new();
    let mut pdata_len: StdBTreeMap<(SectionIndex, u64), u32> = StdBTreeMap::new();
    for (sa, &len) in &obj.known_functions {
        pdata_starts.entry(sa.section).or_default().push(sa.address as u64);
        if let Some(l) = len {
            pdata_len.insert((sa.section, sa.address as u64), l);
        }
    }
    for v in pdata_starts.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    clamp_oversized_function_symbols_inner(obj, &pdata_starts, &pdata_len)
}

/// Grow an UNDERSIZED pdata-anchored function symbol up to its authoritative
/// `.pdata` length. This is the mirror image of the clamp pass and fixes the
/// "funclet truncation" / premature-`.endfn` class of bug.
///
/// ## The bug this fixes (truncation mode 1: stale-size, NOT mis-decode)
///
/// A stale `symbols.txt` cache (or a too-short CFA boundary that an earlier
/// split persisted) records a function symbol whose `size` is SMALLER than the
/// function's true `.pdata` length. When the split re-runs, CFA recomputes the
/// correct (larger) size, but `Symbols::add` keeps the existing too-small size
/// whenever both sizes are `size_known` and `replace` is false
/// (`src/obj/symbols.rs` — `existing.size` wins). So the cached truncation is
/// self-perpetuating. `write_coff` then carves a COFF section of only the
/// truncated length: objdiff compares our full compiled body against the
/// short stub bytes and scores a FALSE 0%, and the orphan tail (plus the
/// binary tail) is lost.
///
/// Examples: GemTrack::See @0x82B63200 (pdata length 0x64, cached at 0x28),
/// the Award ctor (truncated at 0x28 before its unwind record), LicenseMgr.
///
/// ## Why `.pdata` length is the right, overlap-safe oracle
///
/// `.pdata` (`obj.known_functions`) gives the EXACT length of every
/// pdata-anchored function, and the `.pdata` table is a clean partition of
/// `.text`: no entry's `[start, start + len)` ever overruns the next entry's
/// start (verified across all 56,836 RB3 `.text` entries). Therefore growing a
/// pdata-anchored symbol to exactly its `.pdata` length can never make it
/// straddle the next pdata-anchored start. We additionally cap the grown size
/// at the next pdata start as a belt-and-suspenders no-op (it would only fire
/// on a malformed `.pdata`), so the pass is provably overlap-safe.
///
/// This pass only ever GROWS a symbol that is strictly shorter than its
/// authoritative `.pdata` length, and never touches a correctly-sized or
/// oversized one (the clamp pass handles oversized). It runs BEFORE the clamp
/// so the clamp's invariant (no overlaps remain) still holds afterward. Every
/// grow is logged at `info` for audit, mirroring the clamp/prune policy.
///
/// This fixes truncation mode 1 (stale/short size) only. Mode 2 — an
/// `except_data` mis-decode that drops the real `.pdata` entry entirely — is a
/// different defect not addressed here.
fn grow_undersized_function_symbols(obj: &mut ObjInfo) {
    use std::collections::BTreeMap as StdBTreeMap;

    // (1) Per code section, pdata starts (sorted) + the exact length of each.
    let mut pdata_starts: StdBTreeMap<SectionIndex, Vec<u64>> = StdBTreeMap::new();
    let mut pdata_len: StdBTreeMap<(SectionIndex, u64), u32> = StdBTreeMap::new();
    for (sa, &len) in &obj.known_functions {
        pdata_starts.entry(sa.section).or_default().push(sa.address as u64);
        if let Some(l) = len {
            pdata_len.insert((sa.section, sa.address as u64), l);
        }
    }
    for v in pdata_starts.values_mut() {
        v.sort_unstable();
        v.dedup();
    }

    // (2) Decide the grown size for every undersized pdata-anchored symbol.
    //     to_grow: (symbol_index, old_size, new_size).
    let mut to_grow: Vec<(SymbolIndex, u64, u64)> = Vec::new();
    for (idx, sym) in obj.symbols.iter() {
        if sym.kind != ObjSymbolKind::Function {
            continue;
        }
        let Some(sec_idx) = sym.section else { continue };
        if !matches!(obj.sections.get(sec_idx), Some(s) if s.kind == ObjSectionKind::Code) {
            continue;
        }
        let addr = sym.address;
        // Only pdata-anchored symbols have an authoritative length oracle.
        let Some(&len) = pdata_len.get(&(sec_idx, addr)) else { continue };
        let len = len as u64;
        if sym.size >= len {
            continue; // correctly sized or oversized (clamp's job)
        }
        // Belt-and-suspenders: never let the grown end cross the next
        // pdata-anchored start. On a clean partition this never binds.
        let mut new_size = len;
        if let Some(starts) = pdata_starts.get(&sec_idx) {
            let pos = starts.partition_point(|&s| s <= addr);
            if pos < starts.len() {
                let next_start = starts[pos];
                if addr + new_size > next_start {
                    new_size = next_start - addr;
                }
            }
        }
        if new_size > sym.size {
            to_grow.push((idx, sym.size, new_size));
        }
    }

    if to_grow.is_empty() {
        return;
    }

    for &(idx, old_size, new_size) in &to_grow {
        let existing = obj.symbols[idx].clone();
        log::info!(
            "Growing undersized function symbol {} @ {:#010x} {:#x} -> {:#x} (pdata-length)",
            existing.name,
            existing.address,
            old_size,
            new_size
        );
        let resized = ObjSymbol { size: new_size, size_known: true, ..existing };
        if let Err(e) = obj.symbols.replace(idx, resized) {
            log::warn!("Failed to grow undersized function symbol #{idx}: {e:#}");
        }
    }
    log::info!(
        "Grew {} undersized pdata-anchored function symbol(s) to their authoritative length",
        to_grow.len()
    );
}

fn clamp_oversized_function_symbols_inner(
    obj: &mut ObjInfo,
    pdata_starts: &std::collections::BTreeMap<SectionIndex, Vec<u64>>,
    pdata_len: &std::collections::BTreeMap<(SectionIndex, u64), u32>,
) {
    // (2) Decide the clamped size for every oversized function symbol.
    //     to_clamp: (symbol_index, old_size, new_size, reason).
    let mut to_clamp: Vec<(SymbolIndex, u64, u64, &'static str)> = Vec::new();
    for (idx, sym) in obj.symbols.iter() {
        if sym.kind != ObjSymbolKind::Function || sym.size == 0 {
            continue;
        }
        let Some(sec_idx) = sym.section else { continue };
        if !matches!(obj.sections.get(sec_idx), Some(s) if s.kind == ObjSectionKind::Code) {
            continue;
        }
        let addr = sym.address;
        let end = addr + sym.size;

        // (2a) pdata-anchored and oversized -> clamp to the exact pdata length.
        if let Some(&len) = pdata_len.get(&(sec_idx, addr)) {
            if sym.size > len as u64 {
                to_clamp.push((idx, sym.size, len as u64, "pdata-length"));
                continue;
            }
        }

        // (2b) not pdata-anchored but straddles a pdata-anchored start ->
        //      clamp to end exactly at the first such start.
        if let Some(starts) = pdata_starts.get(&sec_idx) {
            // first pdata start strictly greater than addr
            let pos = starts.partition_point(|&s| s <= addr);
            if pos < starts.len() {
                let next_start = starts[pos];
                if next_start < end {
                    to_clamp.push((idx, sym.size, next_start - addr, "next-pdata-boundary"));
                }
            }
        }
    }

    if to_clamp.is_empty() {
        return;
    }

    for &(idx, old_size, new_size, reason) in &to_clamp {
        let existing = obj.symbols[idx].clone();
        log::info!(
            "Clamping oversized function symbol {} @ {:#010x} {:#x} -> {:#x} ({})",
            existing.name,
            existing.address,
            old_size,
            new_size,
            reason
        );
        let resized = ObjSymbol { size: new_size, size_known: true, ..existing };
        if let Err(e) = obj.symbols.replace(idx, resized) {
            log::warn!("Failed to clamp oversized function symbol #{idx}: {e:#}");
        }
    }
    log::info!(
        "Clamped {} oversized function symbol(s) to their authoritative length",
        to_clamp.len()
    );
}

fn prune_overlapping_phantom_functions(obj: &mut ObjInfo) {
    use std::collections::BTreeSet;

    // (1) Collect every address that is the target of some relocation. These
    //     are the "referenced" function entry points (call targets, address
    //     taken, vtable slots, etc.). We resolve each reloc's target symbol to
    //     its (section, address) so a phantom that merely shares a name can't
    //     be mistaken for referenced.
    let mut referenced: BTreeSet<(SectionIndex, u64)> = BTreeSet::new();
    let symbol_count = obj.symbols.count();
    for (_sec_idx, section) in obj.sections.iter() {
        for (_addr, reloc) in section.relocations.iter() {
            if reloc.target_symbol >= symbol_count {
                continue;
            }
            let tsym = &obj.symbols[reloc.target_symbol];
            if let Some(tsec) = tsym.section {
                referenced.insert((tsec, tsym.address));
            }
        }
    }

    // (2) pdata-anchored entry points (authoritative function bounds).
    let mut pdata_anchored: BTreeSet<(SectionIndex, u64)> = BTreeSet::new();
    for sa in &obj.pdata_funcs {
        pdata_anchored.insert((sa.section, sa.address as u64));
    }

    // (3) Build the per-section sorted list of function symbols so we can find
    //     overlaps. (index, address, end).
    let mut by_section: BTreeMap<SectionIndex, Vec<(SymbolIndex, u64, u64)>> = BTreeMap::new();
    for (idx, sym) in obj.symbols.iter() {
        if sym.kind != ObjSymbolKind::Function || sym.size == 0 {
            continue;
        }
        let Some(sec_idx) = sym.section else { continue };
        // Only code sections have COMDAT-carved functions.
        if !matches!(obj.sections.get(sec_idx), Some(s) if s.kind == ObjSectionKind::Code) {
            continue;
        }
        by_section.entry(sec_idx).or_default().push((idx, sym.address, sym.address + sym.size));
    }

    // (4) Within each section, flag function symbols that overlap another
    //     function and are neither pdata-anchored nor referenced.
    //     `overlapping_function_intervals` does the linear overlap sweep (see
    //     its doc comment); here we apply the pdata/reference protections.
    let mut to_delete: Vec<(SymbolIndex, u64)> = Vec::new();
    for (sec_idx, mut funcs) in by_section {
        funcs.sort_by_key(|&(_, addr, _)| addr);
        for (i, overlap_addr) in overlapping_function_intervals(&funcs) {
            let (idx, addr, _end) = funcs[i];
            let key = (sec_idx, addr);
            if pdata_anchored.contains(&key) || referenced.contains(&key) {
                continue; // protected: real function
            }
            to_delete.push((idx, overlap_addr));
        }
    }

    if to_delete.is_empty() {
        return;
    }

    for &(idx, overlap_addr) in &to_delete {
        // Clone first to avoid holding an immutable borrow across the replace.
        let existing = obj.symbols[idx].clone();
        // Audit log: every prune is recorded at `info` with address/size/overlap
        // so the rare false-positive class (a real but module-unreferenced
        // function — tail-call `b` thunk, vtable-/indirect-only entry, XEX
        // export — that is also mis-sized into a neighbor) is greppable instead
        // of being silently deleted. If a pinned unit regresses after a jeff
        // bump, grep the split log for these lines first.
        log::info!(
            "Pruning phantom function symbol {} @ {:#010x} (size {:#x}); overlaps function @ {:#010x}",
            existing.name,
            existing.address,
            existing.size,
            overlap_addr
        );
        let stripped = ObjSymbol {
            name: format!("__DELETED_{}", existing.name),
            kind: ObjSymbolKind::Unknown,
            size: 0,
            flags: ObjSymbolFlagSet(
                ObjSymbolFlags::RelocationIgnore
                    | ObjSymbolFlags::NoWrite
                    | ObjSymbolFlags::NoExport
                    | ObjSymbolFlags::Stripped,
            ),
            ..existing
        };
        if let Err(e) = obj.symbols.replace(idx, stripped) {
            log::warn!("Failed to strip phantom function symbol #{idx}: {e:#}");
        }
    }
    log::info!(
        "Pruned {} spurious overlapping function symbol(s) (unreferenced, no pdata anchor)",
        to_delete.len()
    );
}

/// Find every function interval that overlaps at least one other, returning
/// `(index_into_funcs, representative_overlapped_start_addr)` for each.
///
/// `funcs` is `(symbol_index, start, end)` and MUST be sorted ascending by
/// `start`. The overlap predicate is half-open-interval intersection,
/// `start_i < end_j && start_j < end_i`. A naive all-pairs `any()` is O(n^2),
/// and the full-module split puts ~66k functions in a single `.text` section
/// (~4.4 billion comparisons). Because `funcs` is sorted by start, an interval
/// overlaps some other interval iff EITHER:
///   - some strictly-earlier interval's end reaches past its start — tracked by
///     `prefix_max_end`, the running max end over funcs[0..i]. This is the case
///     that catches a large phantom swallowing the functions after it; their
///     immediate predecessor may be tiny, so a neighbor-only check is NOT
///     enough — the running max is required. OR
///   - the immediately-following interval starts before this one ends — the
///     next interval has the smallest start of all later ones, so if it does
///     not intersect, none do.
///
/// This is exactly equivalent to the all-pairs test, but linear after the sort
/// (asserted against a brute-force reference in the unit tests below). The
/// returned address is a representative overlapped neighbor, used only for the
/// audit log.
fn overlapping_function_intervals(funcs: &[(SymbolIndex, u64, u64)]) -> Vec<(usize, u64)> {
    let mut out: Vec<(usize, u64)> = Vec::new();
    let mut prefix_max_end: u64 = 0;
    let mut prefix_max_addr: u64 = 0; // start of the function owning prefix_max_end
    let mut have_prefix = false;
    for i in 0..funcs.len() {
        let (_, addr, end) = funcs[i];
        // Evaluate overlap against the prefix BEFORE folding funcs[i] into it.
        let overlaps_earlier = have_prefix && prefix_max_end > addr;
        let earlier_addr = prefix_max_addr; // meaningful only if overlaps_earlier
        let next_overlap_addr =
            funcs.get(i + 1).filter(|&&(_, n_addr, _)| n_addr < end).map(|&(_, n_addr, _)| n_addr);
        // Extend the running prefix max to include funcs[i] for later iters.
        if !have_prefix || end > prefix_max_end {
            prefix_max_end = end;
            prefix_max_addr = addr;
            have_prefix = true;
        }
        if overlaps_earlier {
            out.push((i, earlier_addr));
        } else if let Some(n_addr) = next_overlap_addr {
            out.push((i, n_addr));
        }
    }
    out
}

fn split_write_obj_exe(
    module: &mut ExeModuleInfo,
    config: &ProjectConfig,
    out_dir: &Utf8NativePath,
) -> Result<OutputModule> {
    debug!("Performing relocation analysis");
    let mut tracker = Tracker::new(&module.obj);
    tracker.process(&module.obj)?;

    debug!("Applying relocations");
    tracker.apply(&mut module.obj, false)?;

    // Prune spurious overlapping function symbols (CFA / stale-symbols.txt
    // phantoms). Must run AFTER tracker.apply (so every real reference has been
    // resolved to a target symbol) and BEFORE write_symbols_file / split_obj /
    // write_coff (so the phantom is gone from the committed symbols.txt cache
    // and never captures a real function's bytes into its own COMDAT section).
    //
    // First clamp oversized-but-real function symbols (pdata-anchored or
    // referenced) down to their authoritative length. These survive the prune
    // by design (they are real), so without the clamp they keep straddling and
    // starving their neighbors' COMDAT sections. Clamping also collapses the
    // residual symbols.txt overlap regions that block the pin-ranker.
    //
    // BEFORE the clamp, grow UNDERSIZED pdata-anchored symbols up to their
    // authoritative .pdata length. This fixes the "funclet truncation" /
    // premature-.endfn bug (e.g. GemTrack::See, Award ctor): a stale symbols.txt
    // size that is shorter than the function's true pdata length is otherwise
    // self-perpetuating (Symbols::add keeps the existing short size). Growing to
    // the pdata length is overlap-safe (pdata is a clean partition) and a no-op
    // on correctly-sized functions, so it can only ever lengthen a truncated
    // stub back to its real bounds. Run before the clamp so the clamp's
    // no-overlap invariant still holds.
    grow_undersized_function_symbols(&mut module.obj);
    clamp_oversized_function_symbols(&mut module.obj);
    prune_overlapping_phantom_functions(&mut module.obj);

    if !config.symbols_known && config.detect_objects {
        debug!("Detecting object boundaries");
        detect_objects(&mut module.obj)?;
    }

    if config.detect_strings {
        debug!("Detecting strings");
        detect_strings(&mut module.obj)?;
    }

    debug!("Adjusting splits");
    let module_id = module.obj.module_id;
    update_splits(&mut module.obj, None, false)?;

    debug!("Writing configuration");
    if let Some(symbols_path) = &module.config.symbols {
        write_symbols_file(&symbols_path.with_encoding(), &module.obj, module.symbols_cache)?;
    }
    if let Some(splits_path) = &module.config.splits {
        write_splits_file(&splits_path.with_encoding(), &module.obj, false, module.splits_cache)?;
    }

    // Determine which `except_data_<addr>` symbols are genuine PDATA_EH structs
    // (vs. spurious symbols sitting on live code left by a prior split). Must be
    // computed on the FULL module so the shared cross-unit C++ frame handler VA
    // resolves; the per-unit split objs can't see it. See `genuine_except_data_set`.
    let genuine_except_data = genuine_except_data_set(&module.obj);
    log::info!(
        "Classified {} genuine PDATA_EH structs (handler VA resolves to code)",
        genuine_except_data.len()
    );

    debug!("Splitting {} objects", module.obj.link_order.len());
    let module_name = module.config.name().to_string();
    let split_objs = split_obj(&module.obj, None, config.globalize_symbols)?;

    debug!("Writing object files");
    DirBuilder::new()
        .recursive(true)
        .create(out_dir)
        .with_context(|| format!("Failed to create out dir '{out_dir}'"))?;
    let obj_dir = out_dir.join("obj");
    let entry = if module.obj.kind == ObjKind::Executable {
        module.obj.entry.and_then(|e| {
            let (section_index, _) = module.obj.sections.at_address(e as u32).ok()?;
            let symbols =
                module.obj.symbols.at_section_address(section_index, e as u32).collect_vec();
            best_match_for_reloc(symbols, ObjRelocKind::PpcRel24).map(|(_, s)| s.name.clone())
        })
    } else {
        module.obj.symbols.by_name("_prolog")?.map(|(_, s)| s.name.clone())
    };
    let mut out_config = OutputModule {
        name: module_name,
        module_id,
        ldscript: out_dir.join("ldscript.lcf").with_unix_encoding(),
        units: Vec::with_capacity(split_objs.len()),
        entry,
        extract: Vec::with_capacity(module.config.extract.len()),
    };
    for (unit, split_obj) in module.obj.link_order.iter().zip(&split_objs) {
        // pub fn write_elf(obj: &ObjInfo, export_all: bool) -> Result<Vec<u8>>
        let out_obj = write_coff(split_obj, &genuine_except_data)?;
        let obj_path = coff_path_for_unit(&unit.name);
        let out_path = obj_dir.join(&obj_path);
        out_config.units.push(OutputUnit {
            object: out_path.with_unix_encoding(),
            name: unit.name.clone(),
            autogenerated: unit.autogenerated,
            code_size: split_obj.code_size(),
            data_size: split_obj.data_size(),
        });
        if let Some(parent) = out_path.parent() {
            DirBuilder::new().recursive(true).create(parent)?;
        }
        write_coff_if_changed(&out_path, &out_obj)?;
    }

    // for coff_obj in &split_objs {
    //     let root_name = coff_obj.name.split('.').next().unwrap();
    //     // println!("Writing {}.obj", root_name);
    //
    //     // for each obj:
    //     let mut cur_coff = Object::new(BinaryFormat::Coff, Architecture::PowerPc, Endianness::Big);
    //     let mut sect_map: BTreeMap<SectionIndex, SectionId> = Default::default();
    //     let mut sym_map: BTreeMap<SymbolIndex, SymbolId> = Default::default();
    //
    //     // insert the sections
    //     for (idx, sect) in coff_obj.sections.iter() {
    //         // println!("Section: {}", sect.name);
    //         let sect_id = cur_coff.add_section(Vec::new(), sect.name.clone().into_bytes(), match sect.kind {
    //             ObjSectionKind::Code => SectionKind::Text,
    //             ObjSectionKind::Data => SectionKind::Data,
    //             ObjSectionKind::ReadOnlyData => SectionKind::ReadOnlyData,
    //             ObjSectionKind::Bss => SectionKind::UninitializedData,
    //         });
    //         if sect.kind != ObjSectionKind::Bss {
    //             cur_coff.append_section_data(sect_id, &sect.data, sect.align);
    //         }
    //         sect_map.insert(idx, sect_id);
    //     }
    //
    //     // insert the symbols
    //     for (idx, sym) in coff_obj.symbols.iter(){
    //         let sym_id = cur_coff.add_symbol(Symbol {
    //             name: sym.name.clone().into_bytes(),
    //             value: match sym.section {
    //                 Some(idx) => match coff_obj.sections.get(idx) {
    //                     Some(sect) => sym.address - sect.address,
    //                     None => bail!("Could not find section for symbol {}!", sym.name),
    //                 },
    //                 None => 0,
    //             },
    //             size: 0,
    //             kind: match sym.kind {
    //                 ObjSymbolKind::Function => SymbolKind::Text,
    //                 ObjSymbolKind::Object => SymbolKind::Data,
    //                 ObjSymbolKind::Section => SymbolKind::Section,
    //                 ObjSymbolKind::Unknown => SymbolKind::Label,
    //             },
    //             scope: match sym.flags.scope() {
    //                 ObjSymbolScope::Local => SymbolScope::Compilation,
    //                 _ => SymbolScope::Linkage,
    //                 // ObjSymbolScope::Global => SymbolScope::Linkage,
    //                 // ObjSymbolScope::Weak => SymbolScope::Linkage, // verify this
    //                 // ObjSymbolScope::Unknown => SymbolScope::Unknown,
    //             },
    //             weak: false, // sym.flags.scope() == ObjSymbolScope::Weak,
    //             section: match sym.section {
    //                 Some(idx) => SymbolSection::Section(sect_map.get(&idx).unwrap().clone()),
    //                 None => SymbolSection::Undefined,
    //             },
    //             flags: SymbolFlags::None,
    //         });
    //         sym_map.insert(idx, sym_id);
    //     }
    //
    //     // insert the relocs
    //     for (sect_idx, sect) in coff_obj.sections.iter() {
    //         for (addr, reloc) in sect.relocations.iter() {
    //             let sym_id = match sym_map.get(&reloc.target_symbol) {
    //                 Some(id) => id,
    //                 None => bail!("Could not find symbol ID for index {}", reloc.target_symbol),
    //             };
    //             cur_coff.add_relocation(sect_map.get(&sect_idx).unwrap().clone(), Relocation {
    //                 offset: addr as u64,
    //                 symbol: sym_id.clone(),
    //                 addend: 0,
    //                 flags: RelocationFlags::Coff { typ: reloc.to_coff() }
    //             })?;
    //         }
    //     }
    //
    //     // finally, write the COFF
    //     let coff_data = cur_coff.write()?;
    //
    //     // out_config.units.push(OutputUnit {
    //     //     object: out_path.with_unix_encoding(),
    //     //     name: unit.name.clone(),
    //     //     autogenerated: unit.autogenerated,
    //     //     code_size: split_obj.code_size(),
    //     //     data_size: split_obj.data_size(),
    //     // });
    //     // if let Some(parent) = out_path.parent() {
    //     //     DirBuilder::new().recursive(true).create(parent)?;
    //     // }
    //
    //     // create any necessary folders
    //     let mut full_path = obj_dir.clone();
    //     full_path.push(format!("{}.obj", root_name));
    //     if let Some(parent) = full_path.parent() {
    //         std::fs::create_dir_all(parent)?;
    //     }
    //
    //     // write the file
    //     let file = File::create(&full_path)?;
    //     let mut writer = BufWriter::new(file);
    //     writer.write_all(&coff_data)?;
    //     writer.flush()?;
    //     // call write_if_changed here?
    // }

    if config.write_asm {
        debug!("Writing disassembly");
        let asm_dir = out_dir.join("asm");
        // Aggregate per-file failures so we can keep going (and surface every
        // broken file in one report) but still fail loud at the end.
        let mut asm_failures: Vec<(Utf8NativePathBuf, anyhow::Error)> = Vec::new();
        for asm_obj in &split_objs {
            let root_name = asm_obj.name.split('.').next().unwrap();

            // create any necessary folders
            let mut full_path = asm_dir.clone();
            full_path.push(format!("{}.s", root_name));
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // write the file
            let file = File::create(&full_path)?;
            let mut writer = BufWriter::new(file);
            match write_asm(&mut writer, &asm_obj)
                .with_context(|| format!("Failed to write {full_path}"))
            {
                std::result::Result::Ok(()) => {
                    // Only commit the buffer when the writer succeeded —
                    // flushing a partial buffer leaves a truncated file on
                    // disk that downstream consumers can't tell from a real
                    // one (the original silent-truncation bug).
                    writer.flush()?;
                }
                Err(e) => {
                    log::error!("[ASM WRITE ERROR] {full_path}: {e:#}");
                    drop(writer); // discard the partially-buffered output
                    if let Err(remove_err) = std::fs::remove_file(&full_path) {
                        log::warn!(
                            "Failed to remove partial asm file {full_path}: {remove_err}"
                        );
                    }
                    asm_failures.push((full_path, e));
                }
            }
        }
        if !asm_failures.is_empty() {
            let count = asm_failures.len();
            for (path, err) in &asm_failures {
                log::warn!("asm write failed: {path}: {err:#}");
            }
            // These auto-generated asm files are reference-only; the unit
            // configuration in out_config (config.json) is what downstream
            // build steps actually consume. Warn loudly but keep going so
            // ninja can proceed to compiling the project's own sources.
            log::warn!(
                "{count} auto-extracted asm file(s) failed to write; config.json still emitted"
            );
        }
    }
    Ok(out_config)
}

fn write_coff_if_changed(path: &Utf8NativePath, contents: &[u8]) -> Result<()> {
    if fs::metadata(path).is_ok_and(|m| m.is_file()) {
        let old_file = fs::read(path)?;
        let old_data = &*old_file;
        // If the file is the same size, check if the contents are the same
        // Avoid writing if unchanged, since it will update the file's mtime
        if old_data.len() == contents.len() && xxh3_64(old_data) == xxh3_64(contents) {
            return Ok(());
        }
    }
    fs::write(path, contents).with_context(|| format!("Failed to write file '{path}'"))?;
    Ok(())
}

// load_analyze_dol but for xexes
fn load_analyze_xex(config: &ProjectConfig) -> Result<ExeAnalyzeResult> {
    let object_path: Utf8NativePathBuf = config.base.object.with_encoding();
    let mut obj = process_xex(&object_path)?;
    let mut dep: Vec<Utf8NativePathBuf> = vec![object_path];

    if let Some(map_path) = &config.base.map {
        let map_path: Utf8NativePathBuf = map_path.with_encoding();
        apply_map_file_exe(&map_path, &mut obj)?;
        dep.push(map_path);
    }

    if let Some(pdb_path) = &config.base.pdb {
        let pdb_path: Utf8NativePathBuf = pdb_path.with_encoding();
        let pdb_syms = try_parse_pdb(&pdb_path, &obj.sections)?;
        for sym in pdb_syms {
            if !is_reg_intrinsic(&sym.name) && sym.name != "__NLG_Return" {
                match obj.sections.at_address(sym.address as u32).ok() {
                    Some((sec_idx, sec)) => {
                        let sym_to_add: ObjSymbol;
                        // if func came from pdata, DO NOT override the size
                        let the_sec_addr = SectionAddress::new(sec_idx, sym.address as u32);
                        if obj.pdata_funcs.contains(&the_sec_addr) {
                            sym_to_add = ObjSymbol {
                                name: sym.name,
                                address: sym.address,
                                section: Some(sec_idx),
                                size: obj.known_functions.get(&the_sec_addr).unwrap().unwrap()
                                    as u64,
                                size_known: true,
                                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                                kind: if sec.kind == ObjSectionKind::Code {
                                    ObjSymbolKind::Function
                                } else {
                                    ObjSymbolKind::Object
                                },
                                ..Default::default()
                            };
                        } else {
                            sym_to_add = ObjSymbol {
                                name: sym.name,
                                address: sym.address,
                                section: Some(sec_idx),
                                size: sym.size,
                                size_known: sym.size_known,
                                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                                kind: if sec.kind == ObjSectionKind::Code {
                                    ObjSymbolKind::Function
                                } else {
                                    ObjSymbolKind::Object
                                },
                                ..Default::default()
                            };
                        }
                        obj.add_symbol(sym_to_add, true)?;
                    }
                    // if we couldn't find the section (like maybe it was stripped), just continue on
                    _ => continue,
                };
            }
        }
        dep.push(pdb_path);
    }

    let splits_cache = if let Some(splits_path) = &config.base.splits {
        let splits_path = splits_path.with_encoding();
        let cache = apply_splits_file(&splits_path, &mut obj)?;
        dep.push(splits_path);
        cache
    } else {
        None
    };

    let symbols_cache = if let Some(symbols_path) = &config.base.symbols {
        let symbols_path = symbols_path.with_encoding();
        let cache = apply_symbols_file(&symbols_path, &mut obj)?;
        dep.push(symbols_path);
        cache
    } else {
        None
    };

    // Apply block relocations from config
    apply_block_relocations(&mut obj, &config.base.block_relocations)?;

    let mut vtable_candidates: Vec<VtableCandidate> = Vec::new();
    if !config.symbols_known && !config.quick_analysis {
        let mut config = CfaConfig::default();
        debug!("Detecting function boundaries");
        FindSaveRestSledsXbox::execute(&mut config, &obj)?;
        // rb3-xenon: detect MSVC C++ vtables in .rdata. Pushes synthetic
        // `vftable_<addr>` known_symbols and surfaces candidates the `split`
        // caller writes to proposed_splits.txt.
        vtable_candidates = FindXboxVtables::execute_collect(&mut config, &obj)?;
        let result = run_cfa(&obj, &config)?; // perform CFA
        apply_cfa(&mut obj, &result, &config)?; // give each found function a symbol
    }

    // Apply additional relocations from config
    apply_add_relocations(&mut obj, &config.base.add_relocations)?;

    Ok(ExeAnalyzeResult { obj, dep, symbols_cache, splits_cache, vtable_candidates })
}

// references:
// https://github.com/zeroKilo/XEXLoaderWV/blob/master/XEXLoaderWV/src/main/java/xexloaderwv/XEXHeader.java#L120
// https://github.com/emoose/idaxex/blob/5b7de7b964e67fc049db0c61e4cba5d13ee69cec/formats/xex.hpp

fn extract(args: ExtractArgs) -> Result<()> {
    // validate that our input is an .xex
    let xex_ext = args.xex_file.extension();
    ensure!(xex_ext.is_some() && xex_ext.unwrap() == "xex", "Need to provide a valid input xex!");
    // then, grab the exe
    let (exe_name, exe_bytes) = extract_exe(&args.xex_file)?;
    let xex_dir = args.xex_file.parent().unwrap();
    // ...and write it to the same directory the xex is in
    let out_path = xex_dir.join(exe_name);
    std::fs::write(out_path, exe_bytes)?;
    Ok(())
}

// look at dol info function too!
// dol load_analyze_dol as well
fn disasm(args: DisasmArgs) -> Result<()> {
    log::info!("Loading {}", args.xex_file);

    // extract_exe(&args.xex_file);

    // step 1. process xex, and return an ObjInfo
    let mut obj = process_xex(&args.xex_file)?;

    let mut config = CfaConfig::default();

    // step 2. find common functions (save/restore reg funcs, XAPI calls)
    // rename the save/restore gpr/fpr funcs that were previously found in pdata
    FindSaveRestSledsXbox::execute(&mut config, &obj)?;
    // rb3-xenon: detect MSVC C++ vtables in .rdata before CFA so the synthetic
    // `vftable_<addr>` known_symbols seed downstream analysis. Result is also
    // written to proposed_splits.txt alongside `args.out`.
    let vtables = FindXboxVtables::execute_collect(&mut config, &obj)?;

    let result = run_cfa(&obj, &config)?;
    log::info!(
        "Discovered {} functions",
        result.functions.iter().filter(|(_, i)| i.end.is_some()).count()
    );
    // give each found function a symbol
    apply_cfa(&mut obj, &result, &config)?;

    println!("Checking for relocatable targets...");
    // look at dol's split_write_obj
    let mut tracker = Tracker::new(&obj);
    tracker.process(&obj)?;

    println!("Applying relocatable targets...");
    tracker.apply(&mut obj, true)?;

    println!("Detecting objects");
    detect_objects(&mut obj)?;

    println!("Detecting strings");
    detect_strings(&mut obj)?;

    // rb3-xenon: drop proposed_splits.txt next to args.out so disasm runs also
    // surface vtable-derived TU boundary candidates.
    if let Some(out_dir) = args.out.parent() {
        let proposed_path = out_dir.join("proposed_splits.txt");
        log::info!(
            "Writing {} ({} vtable candidate(s))",
            proposed_path,
            vtables.len()
        );
        write_proposed_splits(&proposed_path, &obj, &vtables)?;
    }

    // println!("Writing symbols.txt");
    // let mut w = buf_writer(&args.out)?;
    // write_asm(&mut w, &obj)?;
    // w.flush()?;

    // write_symbols_file(&args.out, &obj, None)?;

    // Gamepad Release
    apply_splits_file(&args.out, &mut obj)?;
    update_splits(&mut obj, None, false)?;
    let split_objs = split_obj(&mut obj, None, false)?;

    for coff_obj in &split_objs {
        // skip autogenned splits for now
        // if coff_obj.name.contains("auto_"){ continue; }

        println!("Split object: {}", coff_obj.name);
        let root_name = coff_obj.name.split('.').next().unwrap();
        println!("Root name: {}", root_name);

        // for each obj:
        let mut cur_coff = Object::new(BinaryFormat::Coff, Architecture::PowerPc, Endianness::Big);
        let mut sect_map: BTreeMap<SectionIndex, SectionId> = Default::default();
        let mut sym_map: BTreeMap<SymbolIndex, SymbolId> = Default::default();

        // insert the sections
        for (idx, sect) in coff_obj.sections.iter() {
            println!("Section: {}", sect.name);
            let sect_id =
                cur_coff.add_section(Vec::new(), sect.name.clone().into_bytes(), match sect.kind {
                    ObjSectionKind::Code => SectionKind::Text,
                    ObjSectionKind::Data => SectionKind::Data,
                    ObjSectionKind::ReadOnlyData => SectionKind::ReadOnlyData,
                    ObjSectionKind::Bss => SectionKind::UninitializedData,
                });
            cur_coff.append_section_data(sect_id, &sect.data, sect.align);
            sect_map.insert(idx, sect_id);
        }

        // for (idx, sym) in coff_obj.symbols.iter() {
        //     if sym.kind == ObjSymbolKind::Unknown {
        //         println!("Unknown symbol {}!", sym.name);
        //     }
        // }

        // insert the symbols
        for (idx, sym) in coff_obj.symbols.iter() {
            // if sym.kind == ObjSymbolKind::Unknown {
            //     let the_master_sym = obj.symbols.by_name(&sym.name)?;
            //     if the_master_sym.is_some(){
            //         println!("{} kind: {:?}", sym.name, the_master_sym.unwrap().1.kind);
            //     }
            // }

            let sym_id = cur_coff.add_symbol(Symbol {
                name: sym.name.clone().into_bytes(),
                value: match sym.section {
                    Some(idx) => match coff_obj.sections.get(idx) {
                        Some(sect) => sym.address - sect.address,
                        None => bail!("Could not find section for symbol {}!", sym.name),
                    },
                    None => 0,
                },
                size: 0,
                kind: match sym.kind {
                    ObjSymbolKind::Function => SymbolKind::Text,
                    ObjSymbolKind::Object => SymbolKind::Data,
                    ObjSymbolKind::Section => SymbolKind::Section,
                    ObjSymbolKind::Unknown => SymbolKind::Label,
                },
                scope: match sym.flags.scope() {
                    ObjSymbolScope::Local => SymbolScope::Compilation,
                    _ => SymbolScope::Linkage,
                    // ObjSymbolScope::Global => SymbolScope::Linkage,
                    // ObjSymbolScope::Weak => SymbolScope::Linkage, // verify this
                    // ObjSymbolScope::Unknown => SymbolScope::Unknown,
                },
                weak: false, // sym.flags.scope() == ObjSymbolScope::Weak,
                section: match sym.section {
                    Some(idx) => SymbolSection::Section(sect_map.get(&idx).unwrap().clone()),
                    None => SymbolSection::Undefined,
                },
                flags: SymbolFlags::None,
            });
            sym_map.insert(idx, sym_id);
        }

        // insert the relocs
        for (sect_idx, sect) in coff_obj.sections.iter() {
            for (addr, reloc) in sect.relocations.iter() {
                let sym_id = match sym_map.get(&reloc.target_symbol) {
                    Some(id) => id,
                    None => bail!("Could not find symbol ID for index {}", reloc.target_symbol),
                };
                cur_coff.add_relocation(sect_map.get(&sect_idx).unwrap().clone(), Relocation {
                    offset: addr as u64,
                    symbol: sym_id.clone(),
                    addend: 0,
                    flags: RelocationFlags::Coff { typ: reloc.to_coff() },
                })?;
            }
        }

        // finally, write the COFF
        let coff_data = cur_coff.write()?;
        std::fs::write(format!("{}.obj", root_name), coff_data)?;
    }
    Ok(())
}

fn map(args: MapArgs) -> Result<()> {
    println!("map: {}", args.input);
    process_map_exe(&args.input)?;
    Ok(())
}

fn pdb(args: PdbArgs) -> Result<()> {
    println!("pdb: {}", args.input);
    let data = try_parse_pdb(&args.input, &ObjSections::new(ObjKind::Executable, vec![]))?;
    println!("{:#?}", data);
    Ok(())
}

// fn file_stem_from_unit(str: &str) -> String {
//     let str = str.strip_suffix(ASM_SUFFIX).unwrap_or(str);
//     let str = str.strip_prefix("C:").unwrap_or(str);
//     let str = str.strip_prefix("D:").unwrap_or(str);
//     let str = str
//         .strip_suffix(".c")
//         .or_else(|| str.strip_suffix(".cp"))
//         .or_else(|| str.strip_suffix(".cpp"))
//         .or_else(|| str.strip_suffix(".s"))
//         .or_else(|| str.strip_suffix(".o"))
//         .unwrap_or(str);
//     let str = str.replace('\\', "/");
//     str.strip_prefix('/').unwrap_or(&str).to_string()
// }

// const ASM_SUFFIX: &str = " (asm)";

// // fn fixup(args: FixupArgs) -> Result<()> {
// //     let obj = process_elf(&args.in_file)?;
// //     let out = write_elf(&obj)?;
// //     fs::write(&args.out_file, &out).context("Failed to create output file")?;
// //     Ok(())
// // }

// fn fixup(args: FixupArgs) -> Result<()> {
//     let in_buf = fs::read(&args.in_file)
//         .with_context(|| format!("Failed to open input file: '{}'", args.in_file))?;
//     let in_file = object::read::File::parse(&*in_buf).context("Failed to parse input ELF")?;
//     let mut out_file =
//         object::write::Object::new(in_file.format(), in_file.architecture(), in_file.endianness());
//     out_file.flags =
//         FileFlags::Elf { os_abi: elf::ELFOSABI_SYSV, abi_version: 0, e_flags: elf::EF_PPC_EMB };
//     out_file.mangling = Mangling::None;

//     // Write file symbol first
//     let mut file_symbol_found = false;
//     for symbol in in_file.symbols() {
//         if symbol.kind() != SymbolKind::File {
//             continue;
//         }
//         let mut out_symbol = to_write_symbol(&symbol, &[])?;
//         out_symbol.name.append(&mut ASM_SUFFIX.as_bytes().to_vec());
//         out_file.add_symbol(out_symbol);
//         file_symbol_found = true;
//         break;
//     }
//     // Create a file symbol if not found
//     if !file_symbol_found {
//         let file_name = args
//             .in_file
//             .file_name()
//             .ok_or_else(|| anyhow!("'{}' is not a file path", args.in_file))?;
//         let mut name_bytes = file_name.as_bytes().to_vec();
//         name_bytes.append(&mut ASM_SUFFIX.as_bytes().to_vec());
//         out_file.add_symbol(object::write::Symbol {
//             name: name_bytes,
//             value: 0,
//             size: 0,
//             kind: SymbolKind::File,
//             scope: SymbolScope::Compilation,
//             weak: false,
//             section: object::write::SymbolSection::Absolute,
//             flags: SymbolFlags::None,
//         });
//     }

//     // Write section symbols & sections
//     let mut section_ids: Vec<Option<SectionId>> = vec![None /* ELF null section */];
//     for section in in_file.sections() {
//         // Skip empty sections or metadata sections
//         if section.size() == 0 || section.kind() == SectionKind::Metadata {
//             section_ids.push(None);
//             continue;
//         }
//         let section_id =
//             out_file.add_section(vec![], section.name_bytes()?.to_vec(), section.kind());
//         section_ids.push(Some(section_id));
//         let out_section = out_file.section_mut(section_id);
//         if section.kind() == SectionKind::UninitializedData {
//             out_section.append_bss(section.size(), section.align());
//         } else {
//             out_section.set_data(section.uncompressed_data()?.into_owned(), section.align());
//         }
//         if has_section_flags(section.flags(), elf::SHF_ALLOC)? {
//             // Generate section symbol
//             out_file.section_symbol(section_id);
//         }
//     }

//     // Write symbols
//     let mut symbol_ids: Vec<Option<SymbolId>> = vec![None /* ELF null symbol */];
//     let mut addr_to_sym: BTreeMap<SectionId, BTreeMap<u32, SymbolId>> = BTreeMap::new();
//     for symbol in in_file.symbols() {
//         // Skip section and file symbols, we wrote them above
//         if matches!(symbol.kind(), SymbolKind::Section | SymbolKind::File) {
//             symbol_ids.push(None);
//             continue;
//         }
//         let out_symbol = to_write_symbol(&symbol, &section_ids)?;
//         let section_id = out_symbol.section.id();
//         let symbol_id = out_file.add_symbol(out_symbol);
//         symbol_ids.push(Some(symbol_id));
//         if symbol.size() != 0 {
//             if let Some(section_id) = section_id {
//                 match addr_to_sym.entry(section_id) {
//                     btree_map::Entry::Vacant(e) => e.insert(BTreeMap::new()),
//                     btree_map::Entry::Occupied(e) => e.into_mut(),
//                 }
//                 .insert(symbol.address() as u32, symbol_id);
//             }
//         }
//     }

//     // Write relocations
//     for section in in_file.sections() {
//         let section_id = match section_ids[section.index().0] {
//             Some(id) => id,
//             None => continue,
//         };
//         for (addr, reloc) in section.relocations() {
//             let mut target_symbol_id = match reloc.target() {
//                 RelocationTarget::Symbol(idx) => match symbol_ids[idx.0] {
//                     Some(id) => Ok(id),
//                     None => {
//                         let in_symbol = in_file.symbol_by_index(idx)?;
//                         match in_symbol.kind() {
//                             SymbolKind::Section => in_symbol
//                                 .section_index()
//                                 .ok_or_else(|| anyhow!("Section symbol without section"))
//                                 .and_then(|section_idx| {
//                                     section_ids[section_idx.0].ok_or_else(|| {
//                                         anyhow!("Relocation against stripped section")
//                                     })
//                                 })
//                                 .map(|section_idx| out_file.section_symbol(section_idx)),
//                             _ => Err(anyhow!("Missing symbol for relocation")),
//                         }
//                     }
//                 },
//                 RelocationTarget::Section(section_idx) => section_ids[section_idx.0]
//                     .ok_or_else(|| anyhow!("Relocation against stripped section"))
//                     .map(|section_id| out_file.section_symbol(section_id)),
//                 target => Err(anyhow!("Invalid relocation target '{target:?}'")),
//             }?;

//             // Attempt to replace section symbols with direct symbol references
//             let mut addend = reloc.addend();
//             let target_sym = out_file.symbol(target_symbol_id);
//             if target_sym.kind == SymbolKind::Section {
//                 if let Some(&new_symbol_id) = target_sym
//                     .section
//                     .id()
//                     .and_then(|id| addr_to_sym.get(&id))
//                     .and_then(|map| map.get(&(addend as u32)))
//                 {
//                     target_symbol_id = new_symbol_id;
//                     addend = 0;
//                 }
//             }

//             out_file.add_relocation(section_id, object::write::Relocation {
//                 offset: addr,
//                 symbol: target_symbol_id,
//                 addend,
//                 flags: reloc.flags(),
//             })?;
//         }
//     }

//     let mut out = buf_writer(&args.out_file)?;
//     out_file.write_stream(&mut out).map_err(|e| anyhow!("{e:?}"))?;
//     out.flush()?;
//     Ok(())
// }

// fn to_write_symbol_section(
//     section: SymbolSection,
//     section_ids: &[Option<SectionId>],
// ) -> Result<object::write::SymbolSection> {
//     match section {
//         SymbolSection::None => Ok(object::write::SymbolSection::None),
//         SymbolSection::Absolute => Ok(object::write::SymbolSection::Absolute),
//         SymbolSection::Common => Ok(object::write::SymbolSection::Common),
//         SymbolSection::Section(idx) => section_ids
//             .get(idx.0)
//             .and_then(|&opt| opt)
//             .map(object::write::SymbolSection::Section)
//             .ok_or_else(|| anyhow!("Missing symbol section")),
//         _ => Ok(object::write::SymbolSection::Undefined),
//     }
// }

// fn to_write_symbol_flags(
//     flags: SymbolFlags<SectionIndex, SymbolIndex>,
// ) -> Result<SymbolFlags<SectionId, SymbolId>> {
//     match flags {
//         SymbolFlags::Elf { st_info, st_other } => Ok(SymbolFlags::Elf { st_info, st_other }),
//         SymbolFlags::None => Ok(SymbolFlags::None),
//         _ => Err(anyhow!("Unexpected symbol flags")),
//     }
// }

// fn to_write_symbol(
//     symbol: &object::read::Symbol,
//     section_ids: &[Option<SectionId>],
// ) -> Result<object::write::Symbol> {
//     Ok(object::write::Symbol {
//         name: symbol.name_bytes()?.to_vec(),
//         value: symbol.address(),
//         size: symbol.size(),
//         kind: symbol.kind(),
//         scope: symbol.scope(),
//         weak: symbol.is_weak(),
//         section: to_write_symbol_section(symbol.section(), section_ids)?,
//         flags: to_write_symbol_flags(symbol.flags())?,
//     })
// }

// fn has_section_flags(flags: SectionFlags, flag: u32) -> Result<bool> {
//     match flags {
//         SectionFlags::Elf { sh_flags } => Ok(sh_flags & flag as u64 == flag as u64),
//         _ => Err(anyhow!("Unexpected section flags")),
//     }
// }

// fn signatures(args: SignaturesArgs) -> Result<()> {
//     // Process response files (starting with '@')
//     let files = process_rsp(&args.files)?;

//     let mut signatures: HashMap<String, FunctionSignature> = HashMap::new();
//     for path in files {
//         log::info!("Processing {}", path);
//         let signature = match generate_signature(&path, &args.symbol) {
//             Ok(Some(signature)) => signature,
//             Ok(None) => continue,
//             Err(e) => {
//                 eprintln!("Failed: {e:?}");
//                 continue;
//             }
//         };
//         log::info!("Comparing hash {}", signature.hash);
//         if let Some(existing) = signatures.get_mut(&signature.hash) {
//             compare_signature(existing, &signature)?;
//         } else {
//             signatures.insert(signature.hash.clone(), signature);
//         }
//     }
//     let mut signatures = signatures.into_values().collect::<Vec<FunctionSignature>>();
//     log::info!("{} unique signatures", signatures.len());
//     signatures.sort_by_key(|s| s.signature.len());
//     let mut out = buf_writer(&args.out_file)?;
//     serde_yaml::to_writer(&mut out, &signatures)?;
//     out.flush()?;
//     Ok(())
// }

// const MODULE_FLAGS: [&str; 8] = [ "Title Module", "Exports To Title", "System Debugger", "DLL Module", "Module Patch", "Patch Full", "Patch Delta", "User Mode" ];

fn info(args: InfoArgs) -> Result<()> {
    let xex = XexInfo::from_file(&args.input)?;
    println!("Jeff: Retrieving Xex info...");
    println!("shoutouts go to xorloser for the original XexTool!\n");

    println!("Xex Info:");
    println!("  {}", if xex.is_dev_kit { "Devkit" } else { "Retail" });
    let bff = xex.opt_header_data.base_file_format.as_ref().unwrap();
    println!(
        "  {}",
        if bff.compression == XexCompression::Compressed { "Compressed" } else { "Uncompressed" }
    );
    println!("  {}", if bff.encryption == XexEncryption::No { "Unencrypted" } else { "Encrypted" });
    println!("");

    println!("Basefile Info:");
    println!("  Original PE Name: {}", xex.opt_header_data.original_name);
    println!("  Load address: 0x{:08X}", xex.opt_header_data.image_base);
    println!("  Entry point: 0x{:08X}", xex.opt_header_data.entry_point);
    print!("  File time: 0x{:08X} - ", xex.opt_header_data.file_timestamp);
    // west coast best coast
    let dur = std::time::Duration::from_secs(xex.opt_header_data.file_timestamp as u64);
    let datetime = chrono::DateTime::<chrono::Utc>::from(UNIX_EPOCH + dur);
    let pst = FixedOffset::west_opt(8 * 3600).unwrap();
    let dt_pst = datetime.with_timezone(&pst);
    println!("{}", dt_pst.format("%a %b %d %H:%M:%S %Y"));
    println!("");

    println!("Static Libraries:");
    let mut idx = 1;
    for lib in xex.opt_header_data.static_libs {
        println!("  {}. {}: v{}.{}.{}.{}", idx, lib.name, lib.major, lib.minor, lib.build, lib.qfe);
        idx += 1;
    }
    println!("");

    // TODO: import libraries
    list_exe_sections(&PeFile32::parse(&*xex.exe_bytes).expect("Failed to parse object file"));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::overlapping_function_intervals;

    /// O(n^2) reference oracle: an interval overlaps if it half-open-intersects
    /// any *other* interval. Returns the sorted set of overlapping indices.
    fn brute_overlap_indices(funcs: &[(u32, u64, u64)]) -> Vec<usize> {
        let mut v = Vec::new();
        for i in 0..funcs.len() {
            let (_, a, e) = funcs[i];
            let hit = funcs.iter().enumerate().any(|(j, &(_, oa, oe))| j != i && a < oe && oa < e);
            if hit {
                v.push(i);
            }
        }
        v
    }

    /// Run the linear sweep on an already-sorted slice, return just the indices.
    fn linear_overlap_indices(funcs: &[(u32, u64, u64)]) -> Vec<usize> {
        let mut idxs: Vec<usize> =
            overlapping_function_intervals(funcs).into_iter().map(|(i, _)| i).collect();
        idxs.sort_unstable();
        idxs
    }

    #[test]
    fn canonical_phantom_cluster() {
        // framing.c cluster from the docstring: D80 real (0xE4), E48 PHANTOM
        // (0x94, swallows the E68/EA0 tails), E68 real (0x34), EA0 real (0x54).
        // Every member overlaps the phantom, so the sweep flags all four; the
        // pdata/reference protections (applied by the caller, not here) then
        // keep the three real ones and delete only E48.
        let mut funcs = vec![
            (0u32, 0x82BF8D80u64, 0x82BF8D80 + 0xE4),
            (1u32, 0x82BF8E48, 0x82BF8E48 + 0x94),
            (2u32, 0x82BF8E68, 0x82BF8E68 + 0x34),
            (3u32, 0x82BF8EA0, 0x82BF8EA0 + 0x54),
        ];
        funcs.sort_by_key(|&(_, a, _)| a);
        assert_eq!(linear_overlap_indices(&funcs), brute_overlap_indices(&funcs));
        assert_eq!(linear_overlap_indices(&funcs), vec![0, 1, 2, 3]);
    }

    #[test]
    fn disjoint_functions_flag_nothing() {
        let mut funcs =
            vec![(0u32, 0x1000u64, 0x1010), (1u32, 0x1010, 0x1020), (2u32, 0x1020, 0x1030)];
        funcs.sort_by_key(|&(_, a, _)| a);
        assert!(linear_overlap_indices(&funcs).is_empty());
        assert!(overlapping_function_intervals(&funcs).is_empty());
    }

    #[test]
    fn phantom_behind_a_tiny_disjoint_neighbor_is_still_caught() {
        // The phantom A=[0x100,0x300) is the FIRST interval; C=[0x120,0x128)
        // sits inside A but its immediate predecessor B=[0x110,0x118) is tiny
        // and disjoint from C. A backward neighbor-only check would miss that C
        // overlaps A; the running-max-end catches it. Guards the design choice.
        let mut funcs = vec![
            (0u32, 0x100u64, 0x300), // big phantom
            (1u32, 0x110, 0x118),    // tiny, inside A
            (2u32, 0x120, 0x128),    // tiny, inside A, disjoint from B
        ];
        funcs.sort_by_key(|&(_, a, _)| a);
        assert_eq!(linear_overlap_indices(&funcs), vec![0, 1, 2]);
        assert_eq!(linear_overlap_indices(&funcs), brute_overlap_indices(&funcs));
    }

    #[test]
    fn duplicate_start_addresses_overlap() {
        // Two symbols sharing a start (stale-cache duplicate) overlap each other.
        let mut funcs = vec![(0u32, 0x200u64, 0x210), (1u32, 0x200, 0x208)];
        funcs.sort_by_key(|&(_, a, _)| a);
        assert_eq!(linear_overlap_indices(&funcs), vec![0, 1]);
        assert_eq!(linear_overlap_indices(&funcs), brute_overlap_indices(&funcs));
    }

    #[test]
    fn linear_sweep_matches_brute_force_over_many_cases() {
        // Deterministic LCG (no rng dep). Tight address range forces frequent
        // overlaps, ties, nesting, and chains — the cases the linear sweep must
        // get exactly right vs the O(n^2) oracle.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            state >> 33
        };
        for _ in 0..5000 {
            let n = (next() % 12) as usize;
            let mut funcs: Vec<(u32, u64, u64)> = Vec::with_capacity(n);
            for k in 0..n {
                let start = next() % 16; // tight range → frequent overlaps & ties
                let size = 1 + next() % 6; // nonzero (matches the size==0 prefilter)
                funcs.push((k as u32, start, start + size));
            }
            funcs.sort_by_key(|&(_, a, _)| a);

            let swept = overlapping_function_intervals(&funcs);
            let mut linear: Vec<usize> = swept.iter().map(|&(i, _)| i).collect();
            linear.sort_unstable();
            assert_eq!(linear, brute_overlap_indices(&funcs), "indices mismatch: {funcs:?}");

            // The representative overlap address must be a real overlapping neighbor.
            for &(i, oa) in &swept {
                let (_, a, e) = funcs[i];
                let ok = funcs
                    .iter()
                    .enumerate()
                    .any(|(j, &(_, oa2, oe2))| j != i && oa2 == oa && a < oe2 && oa2 < e);
                assert!(ok, "reported overlap addr {oa:#x} for index {i} is bogus: {funcs:?}");
            }
        }
    }
}
