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
        read_u32,
        tracker::Tracker,
    },
    cmd::dol::{
        apply_add_relocations, apply_block_relocations, ModuleConfig, OutputConfig, OutputModule,
        OutputUnit, ProjectConfig,
    },
    obj::{
        best_match_for_reloc, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSectionKind,
        ObjSections, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind, ObjSymbolScope,
        SectionIndex, SymbolIndex,
    },
    util::{
        asm::write_asm,
        config::{
            apply_splits_file, apply_symbols_file, create_auto_symbol_name, write_splits_file,
            write_symbols_file,
        },
        dep::DepFile,
        file::{buf_writer, FileReadInfo},
        map_exe::{apply_map_file_exe, is_reg_intrinsic, process_map_exe},
        path::native_path,
        proposed_splits::write_proposed_splits,
        split::{split_obj, update_splits},
        xex::{
            coff_path_for_unit, extract_exe, genuine_except_data_set, list_exe_sections,
            clamp_functions_over_except_data, strip_spurious_except_data,
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

/// True if `word` (a big-endian PowerPC instruction) unconditionally ends
/// fall-through control flow — nothing after it is reachable without an
/// explicit branch/call into it. Used to prove that the instruction *following*
/// such a word begins a fresh flow unit, which — combined with that address
/// being a relocation target — proves a leaf function entry.
fn is_hard_flow_terminator(word: u32) -> bool {
    // blr / blrl / bctr / bctrl (unconditional bclr/bcctr, BO=20, LK 0 or 1).
    if matches!(word, 0x4E80_0020 | 0x4E80_0021 | 0x4E80_0420 | 0x4E80_0421) {
        return true;
    }
    // Unconditional branch `b`/`ba` (primary opcode 18) with LK=0 — a tail call
    // or goto, NOT a `bl` call (LK=1). A `bl` falls through to its return site.
    if (word >> 26) == 18 && (word & 1) == 0 {
        return true;
    }
    // Zeroed inter-function padding (dtk emits `.4byte 0 /* invalid */` between
    // functions); the address after padding starts the next function.
    word == 0
}

/// Synthesize `.fn` function symbols for PDATA-less leaf functions (tiny getters
/// `lbz`/`blr`, bool-materialize `cntlzw`/`extrwi` idioms, this-adjusting
/// thunks) that are PROVEN function entries but that CFA either
///
///   (a) absorbed into an oversized non-pdata neighbor — the leaf is referenced
///       from a vtable / data pointer / call as `parent + addend`, because the
///       parent symbol swallowed it (e.g. TrackPanel's `PushCrowdReaction`
///       @0x82B5EA00 declared 0x90 while its real body ends at 0x82B5EA50,
///       swallowing the three virtual getters at +0x50/+0x68/+0x80 that the
///       vtable references as `fn_82B5EA00+0x50` &c.), or
///
///   (b) emitted as a bare data label (`lbl_<addr>`) sitting in the gap between
///       two functions — the reloc target resolved to a fresh label instead of a
///       function (e.g. TrackPanel's `AutoVocals` @0x82B60D80 = `lbz r3,0xA1(r3);
///       blr`, referenced by the vtable but rendered `.sym lbl_82B60D80`).
///
/// Both leave objdiff unable to pair the leaf and the target-symbol renamer
/// unable to name it, capping matches fleet-wide (see the closeout33/t3 report).
///
/// ## Why this is safe (proof-of-entry + terminator + pdata partition)
///
/// A candidate address `T` is synthesized ONLY when ALL of:
///   1. `T` is the effective target (`target_symbol.address + addend`) of a
///      relocation (from EITHER a DATA section — a vtable slot / function-pointer
///      table — OR a code-section `bl`/branch) that is not inside a jump table
///      (those point to internal case blocks, not separate functions) or an
///      exception record. A relocation to `T` proves `T` is a real, referenced
///      entry. Both data-sourced and code-`bl`-sourced targets may split an
///      absorbing non-pdata parent: the companion `merge_tail_blocks` fix
///      (src/analysis/cfa.rs) now respects the persisted function symbol this
///      pass writes, so a `bl` target CFA would otherwise merge as a shared-loop
///      tail block — and the Unknown-scope parent stub left behind — are NOT
///      re-merged on the next re-split. (The earlier iteration of this pass
///      restricted parent-splitting to DATA sources precisely because the
///      Global-only merge guard could not protect those clamped parents; that
///      restriction is lifted now that the guard covers any persisted symbol.)
///   2. `T` is not already a `.fn` start.
///   3. The word at `T-4` is a hard flow terminator (`blr`/`bctr`/`b`/padding),
///      so `T` cannot be reached by fall-through: it is a genuine new unit.
///   4. The word at `T` is a nonzero (decodable) instruction.
///   5. If `T` lies strictly inside an existing function `P`, then `P` is NOT
///      pdata-anchored. The Xbox 360 `.pdata` table is a clean, authoritative
///      partition of `.text` (verified across all 56,836 RB3 entries): a
///      pdata-anchored function never contains a separate function, so we never
///      split one — this is what keeps switch/jump-table-heavy (framed, hence
///      pdata-anchored) functions untouched.
///
/// NOTE (round 3, the INVERSE pass): this pass sometimes OVER-splits one
/// compiled function into 2+ consecutive anonymous PDATA-less leaf fragments in
/// a `.pdata` GAP (the AddRoll class). [`merge_fallthrough_leaf_fragments`] is
/// the exact inverse — it re-collapses those fragments AFTER this pass, in the
/// same symbol layer. That merge does NOT weaken guard 5: it refuses to merge
/// any pdata-anchored start (its P4), so the `.pdata` partition still partitions
/// `.text`. If you are tempted to "fix" a merged-larger symbol back into
/// fragments, don't — the merged extent is the real compiled function; the split
/// was this pass's artifact.
///
/// The pass only ADDS function symbols and SHRINKS an oversized non-pdata parent
/// down to its first real split point; it never grows a symbol, never touches a
/// pdata-anchored function, and never deletes a real function. Sizes exclude
/// trailing zero padding. Every synthesis/clamp is logged at `info` for audit,
/// mirroring the grow/clamp/prune passes. Relocations that referenced the leaf
/// as `parent+addend` are re-pointed to the new symbol so vtables render the
/// leaf's own name (helps the vtable data-symbol match too).
///
/// ## Single-call convergence (idempotent output)
///
/// Carving a leaf out of an absorbing parent can EXPOSE a further leaf that was
/// previously interior to that same parent (e.g. a `bl` helper nested two levels
/// deep only becomes a splittable candidate once its enclosing parent has itself
/// been split off as a non-pdata function). One pass therefore only peels one
/// nesting level; running the splitter twice would keep peeling, so the emitted
/// symbols.txt would not be byte-stable across re-splits. `_once` performs a
/// single peel and reports how many leaves it created; the public wrapper
/// [`synthesize_reloc_targeted_leaf_functions`] iterates it to a fixed point so a
/// single split invocation already emits the fully-converged symbol set. The
/// pass only ever ADDS function symbols and SHRINKS non-pdata parents (never
/// removes or grows one), and candidates are bounded by the finite reloc-target
/// set, so the iteration is monotonic and always terminates.
fn synthesize_reloc_targeted_leaf_functions_once(obj: &mut ObjInfo) -> usize {
    use std::collections::{BTreeMap, BTreeSet};

    let is_code = |sec: SectionIndex| -> bool {
        matches!(obj.sections.get(sec), Some(s) if s.kind == ObjSectionKind::Code)
    };

    // (1) pdata-anchored function starts — authoritative, never split/duplicate.
    let mut pdata_anchored: BTreeSet<(SectionIndex, u64)> = BTreeSet::new();
    for sa in &obj.pdata_funcs {
        pdata_anchored.insert((sa.section, sa.address as u64));
    }

    // (2) Data-in-code ranges: jump tables (entries point to internal case
    //     blocks) and exception data/records (point to EH funclets). These are
    //     excluded BOTH as a reloc source (their entries are internal edges, not
    //     calls) AND as a reloc target (the blob itself is data — it must never
    //     be promoted to a function; see the `jumptable_` regression below).
    let mut excluded_ranges: BTreeMap<SectionIndex, Vec<(u64, u64)>> = BTreeMap::new();
    // (2b) Existing Function symbols, per section, sorted by start: (start, end).
    //      Plus a set of exact function starts for O(log n) membership.
    let mut func_starts: BTreeSet<(SectionIndex, u64)> = BTreeSet::new();
    let mut funcs_by_sec: BTreeMap<SectionIndex, Vec<(SymbolIndex, u64, u64)>> = BTreeMap::new();
    for (idx, sym) in obj.symbols.iter() {
        let Some(sec) = sym.section else { continue };
        let name = &sym.name;
        if (name.starts_with("jumptable_")
            || name.starts_with("except_data_")
            || name.starts_with("except_record_"))
            && sym.size > 0
        {
            excluded_ranges.entry(sec).or_default().push((sym.address, sym.address + sym.size));
        }
        if sym.kind == ObjSymbolKind::Function && sym.size > 0 && is_code(sec) {
            func_starts.insert((sec, sym.address));
            funcs_by_sec.entry(sec).or_default().push((idx, sym.address, sym.address + sym.size));
        }
    }
    for v in funcs_by_sec.values_mut() {
        v.sort_by_key(|&(_, a, _)| a);
    }

    // Range of the existing function that strictly contains `addr`, if any.
    let containing_func = |sec: SectionIndex, addr: u64| -> Option<(u64, u64)> {
        let funcs = funcs_by_sec.get(&sec)?;
        let pos = funcs.partition_point(|&(_, s, _)| s <= addr);
        if pos == 0 {
            return None;
        }
        let (_, pstart, pend) = funcs[pos - 1];
        (pstart < addr && addr < pend).then_some((pstart, pend))
    };

    // (3) Collect candidate entry VAs = effective reloc targets that land in a
    //     code section, whose reloc source is not excluded.
    let symbol_count = obj.symbols.count();
    // candidate -> externally_referenced: true when at least one reloc reaches the
    // candidate from OUTSIDE the function body that already contains it. This
    // is the discriminator between a real leaf function that CFA accidentally
    // absorbed into a neighbour, and an address INTERNAL to its own function:
    //
    //   * `lis r12, X@ha / addi r12, r12, X@l / add / mtctr / bctr` — the
    //     computed-goto case-table base of a switch. Both the reloc sources and
    //     `X` live in the same function. Promoting `X` cuts the function in half
    //     at its own dispatch and (when `X` names the jump-table blob) types
    //     table DATA as code.
    //   * a backward `bdnz`/`bc` edge to a loop head reached by an earlier
    //     forward `b` (e.g. `memset`'s `b .L_8299EDDC` / `bdnzf eq, 0x8299EDD0`).
    //
    // Neither is a function entry, yet both sit immediately after a hard flow
    // terminator, so the terminator heuristic alone cannot reject them. A
    // reference from outside the containing body cannot be an internal edge, so
    // requiring one keeps the genuine absorbed-leaf case working.
    let mut candidates: BTreeMap<(SectionIndex, u64), bool> = BTreeMap::new();
    for (src_sec, section) in obj.sections.iter() {
        let src_is_data = !is_code(src_sec);
        let excl = excluded_ranges.get(&src_sec);
        for (src_addr, reloc) in section.relocations.iter() {
            if let Some(ranges) = excl {
                let sa = src_addr as u64;
                if ranges.iter().any(|&(s, e)| sa >= s && sa < e) {
                    continue;
                }
            }
            if reloc.target_symbol >= symbol_count {
                continue;
            }
            let tsym = &obj.symbols[reloc.target_symbol];
            let Some(tsec) = tsym.section else { continue };
            if !is_code(tsec) {
                continue;
            }
            let tva = tsym.address as i64 + reloc.addend;
            if tva < 0 {
                continue;
            }
            let tva = tva as u64;
            // Is this reference internal to the body that already contains the
            // target? (Only meaningful when the source is code in the same
            // section; a data-section pointer is external by construction.)
            let internal = !src_is_data
                && src_sec == tsec
                && containing_func(tsec, tva).is_some_and(|(pstart, pend)| {
                    let sa = src_addr as u64;
                    sa >= pstart && sa < pend
                });
            let entry = candidates.entry((tsec, tva)).or_default();
            *entry |= !internal;
        }
    }

    // (4) Filter candidates to genuine new leaf-function entries.
    let mut genuine: BTreeSet<(SectionIndex, u64)> = BTreeSet::new();
    for (&(sec, addr), &externally_referenced) in candidates.iter() {
        if func_starts.contains(&(sec, addr)) {
            continue; // already a function start
        }
        // Never promote data that happens to live in a code section. A
        // `jumptable_*` blob is reached by `lis/addi <table>@ha/@l` from the
        // dispatching function, so it looks exactly like a reloc-targeted entry
        // sitting after the `bctr` hard terminator — but its words are absolute
        // case addresses, not instructions.
        if excluded_ranges
            .get(&sec)
            .is_some_and(|ranges| ranges.iter().any(|&(s, e)| addr >= s && addr < e))
        {
            continue;
        }
        // Same guard by symbol kind, for data-in-code blobs the naming heuristic
        // above does not cover.
        if obj
            .symbols
            .at_section_address(sec, addr as u32)
            .any(|(_, s)| s.kind == ObjSymbolKind::Object)
        {
            continue;
        }
        let Some(section) = obj.sections.get(sec) else { continue };
        if addr < section.address + 4 {
            continue;
        }
        let (Some(cur), Some(prev)) = (read_u32(section, addr as u32), read_u32(section, (addr - 4) as u32))
        else {
            continue;
        };
        if cur == 0 || !is_hard_flow_terminator(prev) {
            continue;
        }
        // Is T strictly inside an existing function P?
        if let Some((pstart, _pend)) = containing_func(sec, addr) {
            // pdata-anchored parents are an authoritative partition — never
            // split one.
            if pdata_anchored.contains(&(sec, pstart)) {
                continue;
            }
            // Splitting a leaf OUT of a non-pdata parent is safe for BOTH
            // data-sourced (vtable) AND code-`bl` targets — but ONLY when some
            // reference reaches it from outside P. Every reference coming from
            // inside P means the address is P's own internal control flow (a
            // switch case-table base, or a loop head re-entered by a backward
            // branch), and carving it out bisects P at its own dispatch.
            //
            // Regression: `?LowerForearm@ST@@YAHKPAK@Z` @ 0x82B728F8 is a
            // 22-case switch. Its only reference to `jumptable_82B7291C` is the
            // `lis/addi` pair three instructions earlier, inside itself. Without
            // this gate the parent is clamped 0xB4 -> 0x24, the jump table is
            // retyped Object -> Function, and the next `dtk xex split` aborts on
            // the boundary the jump-table pass re-derives:
            //   "Overlapping functions 4:0x82B728F8-4:0x82B72974 -> 4:0x82B7291C"
            // i.e. the splitter's output was not a fixed point of its own input.
            if !externally_referenced {
                continue;
            }
        }
        genuine.insert((sec, addr));
    }

    if genuine.is_empty() {
        return 0;
    }

    // (5) Per-section sorted boundary list = func starts ∪ pdata starts ∪ genuine
    //     ∪ section end. Used to size each new function (end = next boundary),
    //     with trailing zero-padding trimmed off.
    let mut boundaries: BTreeMap<SectionIndex, BTreeSet<u64>> = BTreeMap::new();
    for &(sec, a) in func_starts.iter().chain(pdata_anchored.iter()).chain(genuine.iter()) {
        boundaries.entry(sec).or_default().insert(a);
    }
    for (sec, section) in obj.sections.iter() {
        if is_code(sec) {
            boundaries.entry(sec).or_default().insert(section.address + section.size);
        }
    }

    // Precompute the padding-trimmed size of every genuine leaf (end = next
    // boundary, trailing zero words trimmed) BEFORE any mutation, so the sizing
    // reads don't hold a borrow across the later symbol edits.
    let mut leaf_size: BTreeMap<(SectionIndex, u64), u64> = BTreeMap::new();
    for &(sec, addr) in &genuine {
        let Some(section) = obj.sections.get(sec) else { continue };
        let Some(&next) = boundaries.get(&sec).and_then(|b| b.range((addr + 1)..).next()) else {
            continue;
        };
        let mut end = next;
        while end > addr + 4 && matches!(read_u32(section, (end - 4) as u32), Some(0)) {
            end -= 4;
        }
        if end > addr {
            leaf_size.insert((sec, addr), end - addr);
        }
    }

    // (6) Parent clamps: an oversized non-pdata function whose interior holds a
    //     genuine split point is shrunk to end at its first split point (also
    //     trimming trailing padding).
    let mut clamp_parent: Vec<(SymbolIndex, u64, u64)> = Vec::new(); // (idx, old, new)
    for (sec, funcs) in &funcs_by_sec {
        for &(idx, pstart, pend) in funcs {
            if pdata_anchored.contains(&(*sec, pstart)) {
                continue;
            }
            let first_split =
                genuine.range((*sec, pstart + 1)..(*sec, pend)).next().map(|&(_, a)| a);
            if let Some(first) = first_split {
                let mut new_end = first;
                if let Some(section) = obj.sections.get(*sec) {
                    while new_end > pstart + 4
                        && matches!(read_u32(section, (new_end - 4) as u32), Some(0))
                    {
                        new_end -= 4;
                    }
                }
                clamp_parent.push((idx, pend - pstart, new_end - pstart));
            }
        }
    }

    // (7) Apply: clamp parents, then create/promote function symbols.
    for &(idx, old_size, new_size) in &clamp_parent {
        if new_size == 0 || new_size >= old_size {
            continue;
        }
        let existing = obj.symbols[idx].clone();
        log::info!(
            "Clamping absorbing function symbol {} @ {:#010x} {:#x} -> {:#x} (leaf-split)",
            existing.name, existing.address, old_size, new_size
        );
        let resized = ObjSymbol { size: new_size, size_known: true, ..existing };
        if let Err(e) = obj.symbols.replace(idx, resized) {
            log::warn!("Failed to clamp absorbing function symbol #{idx}: {e:#}");
        }
    }

    let module_id = obj.module_id;
    let mut created: BTreeMap<(SectionIndex, u64), SymbolIndex> = BTreeMap::new();
    let genuine_vec: Vec<(SectionIndex, u64)> = genuine.iter().copied().collect();
    for &(sec, addr) in &genuine_vec {
        let Some(&size) = leaf_size.get(&(sec, addr)) else { continue };
        if size == 0 {
            continue;
        }
        // Promote an existing exact-address non-function symbol (label), else add.
        let existing_nonfn: Option<SymbolIndex> = obj
            .symbols
            .at_section_address(sec, addr as u32)
            .find(|(_, s)| s.kind != ObjSymbolKind::Function)
            .map(|(i, _)| i);
        if let Some(idx) = existing_nonfn {
            let existing = obj.symbols[idx].clone();
            log::info!(
                "Promoting label {} @ {:#010x} to leaf function (size {:#x})",
                existing.name, addr, size
            );
            let name = if existing.name.starts_with("lbl_") {
                create_auto_symbol_name("fn", module_id, addr as u32)
            } else {
                existing.name.clone()
            };
            let promoted = ObjSymbol {
                name,
                kind: ObjSymbolKind::Function,
                size,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                ..existing
            };
            if let Err(e) = obj.symbols.replace(idx, promoted) {
                log::warn!("Failed to promote label to leaf function @ {addr:#010x}: {e:#}");
                continue;
            }
            created.insert((sec, addr), idx);
        } else {
            let name = create_auto_symbol_name("fn", module_id, addr as u32);
            log::info!("Synthesizing leaf function {} @ {:#010x} (size {:#x})", name, addr, size);
            match obj.add_symbol(
                ObjSymbol {
                    name,
                    address: addr,
                    section: Some(sec),
                    size,
                    size_known: true,
                    kind: ObjSymbolKind::Function,
                    flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                    ..Default::default()
                },
                false,
            ) {
                std::result::Result::Ok(idx) => {
                    created.insert((sec, addr), idx);
                }
                Err(e) => log::warn!("Failed to synthesize leaf function @ {addr:#010x}: {e:#}"),
            }
        }
    }

    // (8) Re-point relocations that referenced a synthesized leaf as
    //     `parent + addend` to the leaf's own symbol (addend 0), so vtables /
    //     call sites render the leaf's real name.
    let mut repoints: Vec<(SectionIndex, u32, SymbolIndex)> = Vec::new();
    for (src_sec, section) in obj.sections.iter() {
        for (src_addr, reloc) in section.relocations.iter() {
            if reloc.target_symbol >= symbol_count {
                continue;
            }
            let tsym = &obj.symbols[reloc.target_symbol];
            let Some(tsec) = tsym.section else { continue };
            let tva = tsym.address as i64 + reloc.addend;
            if tva < 0 {
                continue;
            }
            if let Some(&new_idx) = created.get(&(tsec, tva as u64)) {
                if reloc.target_symbol != new_idx {
                    repoints.push((src_sec, src_addr, new_idx));
                }
            }
        }
    }
    for (src_sec, src_addr, new_idx) in &repoints {
        let section = &mut obj.sections[*src_sec];
        if let Some(existing) = section.relocations.at(*src_addr).cloned() {
            let reloc = ObjReloc { target_symbol: *new_idx, addend: 0, ..existing };
            section.relocations.replace(*src_addr, reloc);
        }
    }

    log::info!(
        "Synthesized/promoted {} PDATA-less leaf function symbol(s); clamped {} absorbing parent(s); re-pointed {} relocation(s)",
        created.len(), clamp_parent.len(), repoints.len()
    );
    created.len()
}

/// Iterate [`synthesize_reloc_targeted_leaf_functions_once`] to a fixed point.
///
/// A single peel can expose a deeper nested leaf (see that function's docs), so
/// we loop until a pass creates nothing new. This makes one split invocation
/// emit the fully-converged symbol set, so `symbols.txt`/`splits.txt` are
/// byte-stable across re-splits (idempotent) rather than drifting one nesting
/// level per rebuild. The iteration is monotonic (only adds symbols / shrinks
/// parents, bounded by the finite reloc-target set) and thus always terminates;
/// the cap is a belt-and-suspenders guard against an unforeseen oscillation.
fn synthesize_reloc_targeted_leaf_functions(obj: &mut ObjInfo) {
    const MAX_ITERS: usize = 32;
    for iter in 0..MAX_ITERS {
        let created = synthesize_reloc_targeted_leaf_functions_once(obj);
        if created == 0 {
            if iter > 0 {
                log::info!(
                    "Leaf-synthesis converged after {} additional peel iteration(s)",
                    iter
                );
            }
            return;
        }
    }
    log::warn!(
        "Leaf-synthesis hit iteration cap ({}) without converging; \
         symbols.txt may still drift on the next re-split",
        MAX_ITERS
    );
}

/// One fall-through leaf fragment, as consumed by [`plan_fallthrough_merge_runs`].
///
/// `last_insn` is the last big-endian instruction word of `[addr, addr+size)`;
/// `xref` is the number of module-wide relocations whose effective target VA is
/// exactly `addr` (post-`tracker.apply`); `anon` is true iff the symbol name is
/// `fn_`/`lbl_` (never merge a named/persisted symbol away); `pdata` is true iff
/// the address is a genuine `.pdata`-anchored function start (an authoritative
/// boundary that must never be merged across); `split_key` identifies the split
/// UNIT containing the fragment — `Some(unit_start_addr)` for a pinned/committed
/// split, `None` for an inter-unit gap — so the merge never crosses a compiled
/// translation-unit boundary (P5).
#[derive(Clone, Copy, Debug)]
struct LeafFrag {
    addr: u64,
    size: u64,
    last_insn: u32,
    xref: u32,
    anon: bool,
    pdata: bool,
    split_key: Option<u32>,
    /// True iff this address is externally identified as a real function start
    /// that must be preserved (e.g. present in a decomp project's symbol-
    /// identification map applied post-split). Such a fragment is NEVER absorbed
    /// — its independent match would be lost. See `JEFF_MERGE_PROTECT`.
    protected: bool,
}

/// Pure planner for the fall-through leaf-fragment merge. Given a section's
/// function symbols sorted ascending by address, return the maximal runs
/// `(start_idx, end_idx_inclusive)` (each of length ≥ 2) that should collapse
/// into a single function starting at `start_idx`.
///
/// This is the exact INVERSE of [`synthesize_reloc_targeted_leaf_functions`]:
/// that pass CREATES a leaf-function start where a relocation proves a real
/// entry; this pass REMOVES a leaf-function start where the split is a pure dtk
/// CFA artifact — an anonymous, unreferenced fragment reached only by
/// fall-through from its predecessor (the AddRoll-class over-split). The
/// predicate mirrors census §h: for a growing chain `Sᵢ … Sⱼ`, each step absorbs
/// the next fragment `Sₖ₊₁` iff ALL of:
///   - **P1 adjacency:** the merged tail ends exactly at `Sₖ₊₁.addr` (no gap).
///   - **P2 fall-through:** the last instruction of the current tail fragment
///     `Sₖ` is NOT a hard flow terminator (`is_hard_flow_terminator`), so control
///     flows straight into `Sₖ₊₁`.
///   - **P3 no independent entry:** `Sₖ₊₁` has zero incoming relocations AND an
///     anonymous name — its only reachable entry is the fall-through, so it is
///     definitionally part of `Sᵢ`'s function.
///   - **P4 not pdata-anchored:** neither `Sᵢ` nor `Sₖ₊₁` is a `.pdata`-anchored
///     start (a genuine pdata boundary is authoritative — never merge across it;
///     this subsumes `func_type==3` EH-anchored starts).
///   - **P5 same split unit:** `Sₖ₊₁` lies in the SAME split unit as the chain
///     head `Sᵢ` (`split_key` equal). A pinned split range is the exact byte span
///     of one compiled translation unit; a function can never cross it. This
///     guard is BEYOND census §h — the census predicate (P1–P4 only) over-counted
///     because it ignored split boundaries, so a gap fragment adjacent to the
///     first (anonymous, unreferenced) function of the NEXT pinned unit would
///     otherwise fuse across the TU boundary (e.g. a gap fn before MoveMgr.cpp's
///     first function), producing dtk's "split ends within symbol" error. AddRoll
///     is unaffected: both fragments live inside Stats.cpp's pinned `.text` range.
///   - **P6 not externally protected:** `Sₖ₊₁` is not an externally-identified
///     real function start (`protected`). Also beyond census §h: a decomp project
///     may carry an identification map (rb3-xenon's `target_symbol_map.json`)
///     that renames an anonymous fragment to a real function POST-split; such a
///     fragment can coincidentally match our (shorter/ICF-folded) compiled body
///     as a standalone symbol, and absorbing it would delete that match. This is
///     the dtk-visible form of the census's "exclude Sₖ₊₁ if it matches 100%
///     standalone" tightening. Empirically (rb3-xenon A/B) two absorptions —
///     MidiReader `_M_erase` and BandCharDesc `operator delete` — were
///     over-split fragments whose 80B/4B body matched our shorter codegen; P6
///     preserves them. The chain HEAD may be protected (it grows, keeping its
///     identity); only ABSORPTION of a protected address is blocked.
///
/// Because the walk is greedy-forward and each absorbed fragment is anonymous +
/// unreferenced, the result is a partition of the input into merge-runs and
/// singletons — chains (census: 272 multi-pair runs, longest 9 fragments) fall
/// out naturally.
fn plan_fallthrough_merge_runs(frags: &[LeafFrag]) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i + 1 < frags.len() {
        let s1 = frags[i];
        // P4 for the chain start: a pdata-anchored function is authoritative.
        if s1.pdata {
            i += 1;
            continue;
        }
        let mut j = i;
        let mut cur_end = s1.addr + s1.size;
        while j + 1 < frags.len() {
            let next = frags[j + 1];
            // P1 adjacency (no gap / padding word).
            if cur_end != next.addr {
                break;
            }
            // P2 fall-through: the current tail fragment must flow off its end.
            if is_hard_flow_terminator(frags[j].last_insn) {
                break;
            }
            // P3 no independent entry for the absorbed fragment.
            if next.xref != 0 || !next.anon {
                break;
            }
            // P4 the absorbed fragment must not be a genuine pdata boundary.
            if next.pdata {
                break;
            }
            // P5 the absorbed fragment must be in the SAME split unit as the
            // chain head — never merge across a compiled translation-unit
            // boundary (pinned split range).
            if next.split_key != s1.split_key {
                break;
            }
            // P6 never absorb an externally-identified real function start.
            if next.protected {
                break;
            }
            j += 1;
            cur_end = next.addr + next.size;
        }
        if j > i {
            runs.push((i, j));
            i = j + 1;
        } else {
            i += 1;
        }
    }
    runs
}

/// Merge adjacent fall-through PDATA-less leaf fragments back into one function.
///
/// ## The defect (census 2026-07-16, `docs/plans/jeff-pdata-boundary-round3.md`)
///
/// jeff's own CFA / [`synthesize_reloc_targeted_leaf_functions`] (commit
/// `a670a12`) sometimes carves ONE compiled function into 2+ consecutive
/// anonymous leaf-function symbols inside a `.pdata` gap, persisted in
/// `symbols.txt`. objdiff then pairs our whole compiled body against the first
/// (truncated) fragment → a permanent mismatch no source work can close.
/// Confirmed fixture: `Stats::AddRoll` (`band3/game/Stats.cpp`) —
/// `fn_826976E0`(16B) + `fn_826976F0`(20B, `lastS1=addi r11,r11,1` fall-through,
/// zero xrefs) → one 36B function `0x826976E0..0x82697704`.
///
/// This pass is the exact INVERSE of `a670a12`, in the SAME symbol layer (the
/// final function-symbol set), NOT over the `.pdata` table — the raw `.pdata`
/// predicate finds ZERO such pairs (the fragments live in pdata GAPS). See
/// [`plan_fallthrough_merge_runs`] for the per-step predicate (census §h P1–P4).
///
/// ## Invariant (does NOT weaken `a670a12`'s guard 5)
///
/// `a670a12`'s guard 5 asserts the `.pdata` table is a clean partition of `.text`
/// and a pdata-anchored function never contains a separate function. This pass
/// preserves that in full: P4 refuses to merge any pdata-anchored start, so the
/// pdata partition still partitions `.text` unchanged. We only ever collapse
/// symbol-layer fragments that CFA/leaf-synthesis introduced inside a pdata GAP —
/// never a pdata boundary. A future session must NOT "fix" this merge as a
/// boundary bug: the merged extent is the real compiled function; the fragment
/// split was the artifact.
///
/// ## Idempotency / re-split byte-stability
///
/// The pass runs every split. Once `symbols.txt` records the merged 36B symbol,
/// the absorbed fragment `Sₖ₊₁` cannot be re-created:
/// [`synthesize_reloc_targeted_leaf_functions`] only synthesizes reloc-TARGETED
/// leaves, but P3 guaranteed `Sₖ₊₁` has zero relocations — so the leaf pass
/// skips it. Should a stale cache or a fresh CFA re-carve it anyway, this pass
/// re-merges it (deterministic), and any residual overlap is swept by the
/// following [`prune_overlapping_phantom_functions`]. Either way the emitted
/// `symbols.txt` converges to the merged extent. Runs AFTER leaf synthesis (its
/// fragments are the input) and BEFORE the prune (a merge never creates an
/// overlap, but the prune is the belt-and-suspenders for a re-carve).
///
/// Load the optional `JEFF_MERGE_PROTECT` set: a JSON object whose keys are hex
/// addresses (`"0x82XXXXXX"`) of externally-identified real function starts that
/// must never be absorbed (P6). Values (names) are ignored. Returns an empty set
/// when the env var is unset or the file cannot be read/parsed (the pass then
/// runs purely structurally) — a warn is logged on a present-but-unreadable path
/// so a misconfigured project surfaces instead of silently over-firing.
fn load_merge_protect_addrs() -> std::collections::BTreeSet<u64> {
    let mut set = std::collections::BTreeSet::new();
    let Some(path) = std::env::var_os("JEFF_MERGE_PROTECT") else { return set };
    let text = match std::fs::read_to_string(&path) {
        std::result::Result::Ok(t) => t,
        Err(e) => {
            log::warn!("JEFF_MERGE_PROTECT set but {:?} unreadable: {e:#}", path);
            return set;
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        std::result::Result::Ok(v) => v,
        Err(e) => {
            log::warn!("JEFF_MERGE_PROTECT {:?} is not valid JSON: {e:#}", path);
            return set;
        }
    };
    if let Some(map) = value.as_object() {
        for key in map.keys() {
            let hex = key.trim().trim_start_matches("0x").trim_start_matches("0X");
            if let std::result::Result::Ok(addr) = u64::from_str_radix(hex, 16) {
                set.insert(addr);
            }
        }
    }
    set
}

/// This pass is ALWAYS ON (unconditional) — it runs on every split. (During
/// round-3 A/B bring-up it was gated by `JEFF_CLASS2_MERGE`; the gate was removed
/// on landing, verified byte-identical to the gated-on run.)
///
/// `JEFF_MERGE_PROTECT` (optional): a path to a JSON object whose keys are hex
/// addresses (`"0x82XXXXXX"`) of externally-identified real function starts —
/// e.g. rb3-xenon's `scripts/target_symbol_map.json`, applied post-split by the
/// target-symbol renamer. Those addresses are never absorbed (P6). Unset ⇒ the
/// pass runs purely structurally (census P1–P5); on rb3-xenon that over-fires by
/// exactly the two coincidental over-split matches (`_M_erase`, `operator delete`
/// void*,void*), so the identification map should be provided for a 0-loss run.
fn merge_fallthrough_leaf_fragments(obj: &mut ObjInfo) {
    use std::collections::{BTreeMap, BTreeSet};

    let is_code = |sec: SectionIndex| -> bool {
        matches!(obj.sections.get(sec), Some(s) if s.kind == ObjSectionKind::Code)
    };

    // (0) Externally-identified real function starts to never absorb (P6). Parsed
    //     from JEFF_MERGE_PROTECT (a JSON map addr->name, e.g. target_symbol_map).
    //     A single flat set of VAs (module-wide; .text VAs are globally unique).
    let protected_addrs: BTreeSet<u64> = load_merge_protect_addrs();
    if !protected_addrs.is_empty() {
        log::info!(
            "merge_fallthrough_leaf_fragments: {} externally-protected address(es) loaded (P6)",
            protected_addrs.len()
        );
    }

    // (1) pdata-anchored starts — genuine boundaries, never merged (P4).
    let mut pdata_anchored: BTreeSet<(SectionIndex, u64)> = BTreeSet::new();
    for sa in &obj.pdata_funcs {
        pdata_anchored.insert((sa.section, sa.address as u64));
    }

    // (2) TRUE post-tracker.apply reloc-target xref counts, keyed by the
    //     effective target VA (target_symbol.address + addend) landing in a code
    //     section — ALL sources (bl / vtable / data pointer / jumptable). This is
    //     the SAME set the leaf pass consumes; a fall-through fragment with an
    //     independent entry has a nonzero count here and is left alone (P3).
    let symbol_count = obj.symbols.count();
    let mut xrefs: BTreeMap<(SectionIndex, u64), u32> = BTreeMap::new();
    for (_src_sec, section) in obj.sections.iter() {
        for (_src_addr, reloc) in section.relocations.iter() {
            if reloc.target_symbol >= symbol_count {
                continue;
            }
            let tsym = &obj.symbols[reloc.target_symbol];
            let Some(tsec) = tsym.section else { continue };
            if !is_code(tsec) {
                continue;
            }
            let tva = tsym.address as i64 + reloc.addend;
            if tva < 0 {
                continue;
            }
            *xrefs.entry((tsec, tva as u64)).or_insert(0) += 1;
        }
    }

    // (3) Per code section, function symbols sorted by address, with their
    //     symbol index so the merge can resize S1 and strip the absorbed tail.
    let mut by_section: BTreeMap<SectionIndex, Vec<(SymbolIndex, u64, u64, bool)>> = BTreeMap::new();
    for (idx, sym) in obj.symbols.iter() {
        let Some(sec) = sym.section else { continue };
        if sym.kind != ObjSymbolKind::Function || sym.size == 0 || !is_code(sec) {
            continue;
        }
        let anon = sym.name.starts_with("fn_") || sym.name.starts_with("lbl_");
        by_section.entry(sec).or_default().push((idx, sym.address, sym.size, anon));
    }
    for v in by_section.values_mut() {
        v.sort_by_key(|&(_, a, _, _)| a);
        v.dedup_by_key(|&mut (_, a, _, _)| a);
    }

    // (4) Plan merges per section, then apply: grow S1 to the run's end, strip
    //     the absorbed fragments (mirroring prune's symbol-removal convention).
    let mut merged_runs = 0usize;
    let mut absorbed = 0usize;
    for (sec, funcs) in &by_section {
        let Some(section) = obj.sections.get(*sec) else { continue };
        // Build the pure-planner input for this section.
        let mut frags: Vec<LeafFrag> = Vec::with_capacity(funcs.len());
        for &(_idx, addr, size, anon) in funcs {
            let last_insn = read_u32(section, (addr + size - 4) as u32).unwrap_or(0);
            let xref = xrefs.get(&(*sec, addr)).copied().unwrap_or(0);
            let pdata = pdata_anchored.contains(&(*sec, addr));
            // The split UNIT containing this fragment (pinned range start), or
            // None if it sits in an inter-unit gap. Fragments merge only within
            // one unit (P5) — a pinned split range is one TU's exact byte span.
            let split_key = section.splits.for_address(addr as u32).map(|(start, _)| start);
            let protected = protected_addrs.contains(&addr);
            frags.push(LeafFrag {
                addr,
                size,
                last_insn,
                xref,
                anon,
                pdata,
                split_key,
                protected,
            });
        }
        let runs = plan_fallthrough_merge_runs(&frags);
        for (start, end) in runs {
            let (s1_idx, s1_addr, _s1_size, _) = funcs[start];
            let new_end = frags[end].addr + frags[end].size;
            let new_size = new_end - s1_addr;
            // Grow S1 to cover the whole run.
            let existing = obj.symbols[s1_idx].clone();
            let absorbed_addrs: Vec<u64> =
                (start + 1..=end).map(|k| frags[k].addr).collect();
            log::info!(
                "Merging fallthrough leaf fragments into {} @ {:#010x}: absorbing {:#x?} \
                 -> merged size {:#x} (end {:#010x}); reason=anon+zero-xref+fallthrough, non-pdata",
                existing.name,
                s1_addr,
                absorbed_addrs,
                new_size,
                new_end
            );
            let resized = ObjSymbol { size: new_size, size_known: true, ..existing };
            if let Err(e) = obj.symbols.replace(s1_idx, resized) {
                log::warn!("Failed to grow merged leaf fragment head #{s1_idx}: {e:#}");
                continue;
            }
            merged_runs += 1;
            // Strip the absorbed fragment symbols (same convention as the prune:
            // Unknown kind, size 0, non-writable/exportable/stripped, __MERGED_
            // name prefix so the merge is greppable in symbols.txt).
            for &(idx, _, _, _) in &funcs[start + 1..=end] {
                let frag = obj.symbols[idx].clone();
                let stripped = ObjSymbol {
                    name: format!("__MERGED_{}", frag.name),
                    kind: ObjSymbolKind::Unknown,
                    size: 0,
                    flags: ObjSymbolFlagSet(
                        ObjSymbolFlags::RelocationIgnore
                            | ObjSymbolFlags::NoWrite
                            | ObjSymbolFlags::NoExport
                            | ObjSymbolFlags::Stripped,
                    ),
                    ..frag
                };
                if let Err(e) = obj.symbols.replace(idx, stripped) {
                    log::warn!("Failed to strip absorbed leaf fragment #{idx}: {e:#}");
                    continue;
                }
                absorbed += 1;
            }
        }
    }

    if merged_runs > 0 {
        log::info!(
            "Merged {} fallthrough leaf-fragment run(s), absorbing {} fragment symbol(s) \
             (inverse of leaf-synthesis; pdata partition preserved)",
            merged_runs,
            absorbed
        );
    }
}

/// CLASS 1 CENSUS (env-gated, read-only). When `JEFF_CLASS1_CENSUS=1`, dump every
/// persisted `Function` symbol in a code section whose `[addr, addr+size)` span
/// contains NO hard flow terminator (`is_hard_flow_terminator`: blr/bctr/uncond-b/
/// zero-padding). Runs AFTER the full repair pipeline (grow/clamp/leaf-synth/
/// class2-merge/prune) so it reflects the final symbols.txt. Uses jeff's OWN
/// post-`tracker.apply` reloc set + `obj.pdata_funcs` + split ranges — never
/// Python/Ghidra. For each survivor: addr/size/name/last-insn, the next symbol's
/// info, split unit, protected status, and a primary guard-class (a-e) explaining
/// why the class-2 merge did not absorb its tail. Output to file at
/// `JEFF_CLASS1_CENSUS_OUT` (else stderr).
fn census_terminatorless_functions(obj: &ObjInfo) {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;

    if std::env::var_os("JEFF_CLASS1_CENSUS").is_none() {
        return;
    }

    let is_code = |sec: SectionIndex| -> bool {
        matches!(obj.sections.get(sec), Some(s) if s.kind == ObjSectionKind::Code)
    };

    let protected_addrs: BTreeSet<u64> = load_merge_protect_addrs();

    // pdata-anchored starts.
    let mut pdata_anchored: BTreeSet<(SectionIndex, u64)> = BTreeSet::new();
    for sa in &obj.pdata_funcs {
        pdata_anchored.insert((sa.section, sa.address as u64));
    }

    // TRUE post-tracker.apply reloc-target xref counts (same as the merge pass).
    let symbol_count = obj.symbols.count();
    let mut xrefs: BTreeMap<(SectionIndex, u64), u32> = BTreeMap::new();
    for (_src_sec, section) in obj.sections.iter() {
        for (_src_addr, reloc) in section.relocations.iter() {
            if reloc.target_symbol >= symbol_count {
                continue;
            }
            let tsym = &obj.symbols[reloc.target_symbol];
            let Some(tsec) = tsym.section else { continue };
            if !is_code(tsec) {
                continue;
            }
            let tva = tsym.address as i64 + reloc.addend;
            if tva < 0 {
                continue;
            }
            *xrefs.entry((tsec, tva as u64)).or_insert(0) += 1;
        }
    }

    // Symbol-at-address maps: function symbols and any-kind symbols.
    let mut func_at: BTreeMap<(SectionIndex, u64), (String, u64, bool)> = BTreeMap::new();
    let mut any_at: BTreeMap<(SectionIndex, u64), &'static str> = BTreeMap::new();
    for (_idx, sym) in obj.symbols.iter() {
        let Some(sec) = sym.section else { continue };
        if !is_code(sec) {
            continue;
        }
        let tag = match sym.kind {
            ObjSymbolKind::Function => "FUNC",
            ObjSymbolKind::Object => "OBJ",
            _ => "OTHER",
        };
        let e = any_at.entry((sec, sym.address)).or_insert(tag);
        if tag == "FUNC" {
            *e = "FUNC";
        }
        if sym.kind == ObjSymbolKind::Function && sym.size > 0 {
            let anon = sym.name.starts_with("fn_") || sym.name.starts_with("lbl_");
            func_at.insert((sec, sym.address), (sym.name.clone(), sym.size, anon));
        }
    }

    let mut out: Box<dyn std::io::Write> = match std::env::var_os("JEFF_CLASS1_CENSUS_OUT") {
        Some(p) => match std::fs::File::create(&p) {
            std::result::Result::Ok(f) => Box::new(std::io::BufWriter::new(f)),
            std::result::Result::Err(e) => {
                log::warn!("JEFF_CLASS1_CENSUS_OUT {:?} unwritable: {e:#}; using stderr", p);
                Box::new(std::io::stderr())
            }
        },
        None => Box::new(std::io::stderr()),
    };

    let (mut total, mut g_a, mut g_b, mut g_c, mut g_d, mut g_e, mut g_anom) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut pinned, mut gap) = (0u64, 0u64);
    let (mut selfpdata_ct, mut nextprot_ct) = (0u64, 0u64);
    let (mut last_bl, mut last_bcond, mut last_bctrl, mut last_other) = (0u64, 0u64, 0u64, 0u64);

    for (_idx, sym) in obj.symbols.iter() {
        let Some(sec) = sym.section else { continue };
        if sym.kind != ObjSymbolKind::Function || sym.size == 0 || !is_code(sec) {
            continue;
        }
        let Some(section) = obj.sections.get(sec) else { continue };
        let addr = sym.address;
        let size = sym.size;
        let mut has_term = false;
        let mut w = addr;
        while w + 4 <= addr + size {
            if let Some(word) = read_u32(section, w as u32) {
                if is_hard_flow_terminator(word) {
                    has_term = true;
                    break;
                }
            }
            w += 4;
        }
        if has_term {
            continue;
        }
        total += 1;

        let last_insn = read_u32(section, (addr + size - 4) as u32).unwrap_or(0);
        let first_insn = read_u32(section, addr as u32).unwrap_or(0);
        let op = last_insn >> 26;
        let lasttag = if op == 18 && (last_insn & 1) == 1 {
            last_bl += 1;
            "BL"
        } else if op == 16 {
            last_bcond += 1;
            "BCOND"
        } else if matches!(last_insn, 0x4E80_0021 | 0x4E80_0421) {
            last_bctrl += 1;
            "BCTRL"
        } else if op == 31 && ((last_insn >> 1) & 0x3ff) == 528 && (last_insn & 1) == 1 {
            last_bctrl += 1;
            "BCCTRL"
        } else {
            last_other += 1;
            "OTHER"
        };

        let selfpdata = pdata_anchored.contains(&(sec, addr));
        if selfpdata {
            selfpdata_ct += 1;
        }
        let self_split = section.splits.for_address(addr as u32).map(|(s, sp)| (s, sp.unit.clone()));
        let self_split_key = self_split.as_ref().map(|(s, _)| *s);
        let self_split_name =
            self_split.as_ref().map(|(_, u)| u.clone()).unwrap_or_else(|| "GAP".to_string());
        if self_split_key.is_some() {
            pinned += 1;
        } else {
            gap += 1;
        }

        let next_addr = addr + size;
        let next_func = func_at.get(&(sec, next_addr));
        let next_any = any_at.get(&(sec, next_addr)).copied();
        let next_xref = xrefs.get(&(sec, next_addr)).copied().unwrap_or(0);
        let next_pdata = pdata_anchored.contains(&(sec, next_addr));
        let next_prot = protected_addrs.contains(&next_addr);
        if next_prot {
            nextprot_ct += 1;
        }
        let next_split_key = section.splits.for_address(next_addr as u32).map(|(s, _)| s);
        let (next_name, next_size, next_anon, next_kind): (String, u64, bool, &str) =
            match next_func {
                Some((n, sz, anon)) => (n.clone(), *sz, *anon, "FUNC"),
                None => ("-".to_string(), 0, false, next_any.unwrap_or("NONE")),
            };

        let guard: &str = if selfpdata {
            "c"
        } else if next_kind == "FUNC" {
            if next_xref != 0 {
                "a"
            } else if !next_anon {
                "b"
            } else if next_pdata {
                "c"
            } else if next_split_key != self_split_key {
                "d"
            } else if next_prot {
                "b"
            } else {
                "anomaly"
            }
        } else {
            "e"
        };
        match guard {
            "a" => g_a += 1,
            "b" => g_b += 1,
            "c" => g_c += 1,
            "d" => g_d += 1,
            "e" => g_e += 1,
            _ => g_anom += 1,
        }

        let _ = writeln!(
            out,
            "CLASS1 addr={:#010x} size={:#x} name={} lastw={:#010x} lasttag={} firstw={:#010x} \
             selfpdata={} selfsplit={} nextaddr={:#010x} nextkind={} nextname={} nextsize={:#x} \
             nextxref={} nextpdata={} nextprot={} nextsplitdiff={} guard={}",
            addr,
            size,
            sym.name,
            last_insn,
            lasttag,
            first_insn,
            selfpdata as u8,
            self_split_name,
            next_addr,
            next_kind,
            next_name,
            next_size,
            next_xref,
            next_pdata as u8,
            next_prot as u8,
            (next_split_key != self_split_key) as u8,
            guard,
        );
    }

    let _ = writeln!(
        out,
        "CLASS1_SUMMARY total={total} guard_a={g_a} guard_b={g_b} guard_c={g_c} guard_d={g_d} \
         guard_e={g_e} anomaly={g_anom} pinned={pinned} gap={gap} selfpdata={selfpdata_ct} \
         nextprotected={nextprot_ct} last_bl={last_bl} last_bcond={last_bcond} \
         last_bctrl={last_bctrl} last_other={last_other}"
    );
    let _ = out.flush();
    log::info!(
        "JEFF_CLASS1_CENSUS: {total} terminatorless function symbol(s) \
         (a={g_a} b={g_b} c={g_c} d={g_d} e={g_e} anom={g_anom}; pinned={pinned} gap={gap})"
    );
}

/// Compute the absolute branch target of a PPC `b`/`bc` instruction (opcode 18 or
/// 16) at `pc`. Returns None for `bl`/`bcl` (LK=1, calls that fall through) and
/// for register-form branches (bclr/bcctr). AA=1 → absolute target.
fn ppc_branch_target(word: u32, pc: u64) -> Option<u64> {
    let op = word >> 26;
    if op == 18 {
        // b/ba/bl/bla: skip LK=1 (call).
        if word & 1 == 1 {
            return None;
        }
        let aa = (word >> 1) & 1;
        // LI = sign-extended 26-bit (bits 6..29, already *4).
        let mut li = (word & 0x03FF_FFFC) as i64;
        if li & 0x0200_0000 != 0 {
            li -= 0x0400_0000;
        }
        Some(if aa == 1 { li as u64 } else { (pc as i64 + li) as u64 })
    } else if op == 16 {
        // bc/bca/bcl/bcla: skip LK=1.
        if word & 1 == 1 {
            return None;
        }
        let aa = (word >> 1) & 1;
        // BD = sign-extended 16-bit (bits 16..29, already *4).
        let bd = ((word & 0x0000_FFFC) as u16) as i16 as i64;
        Some(if aa == 1 { bd as u64 } else { (pc as i64 + bd) as u64 })
    } else {
        None
    }
}

/// CLASS 4 CENSUS (env-gated, read-only). When `JEFF_CLASS4_CENSUS=1`, dump the
/// "post-blr/branch over-carve" family: a NAMED (map-identified, i.e. in
/// JEFF_MERGE_PROTECT — rb3-xenon renames anon `fn_` to real names POST-split, so
/// inside dtk the only "named" signal is protect-map membership) function head S1
/// immediately followed by one or more CONTIGUOUS anonymous, zero-xref,
/// non-pdata, same-split-unit `fn_` tails that are reached NOT by fall-through
/// (Class-2's case) but by a NON-`bl` branch INSIDE the accumulated head span
/// targeting at-or-past the first tail. The head typically ENDS in a hard flow
/// terminator (early-return `blr` or unconditional `b`), which is exactly why
/// objdiff pairs only the tiny head → a 0.3–1% reading. This is the COMPLEMENT of
/// [`merge_fallthrough_leaf_fragments`]. Read-only: emits the structural
/// candidates with a `branchproof` flag (the discriminant that separates a real
/// over-carve from a genuinely-separate anon function a naive merge would wrongly
/// eat). Output to `JEFF_CLASS4_CENSUS_OUT` (else stderr).
fn census_class4_overcarve(obj: &ObjInfo) {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;

    if std::env::var_os("JEFF_CLASS4_CENSUS").is_none() {
        return;
    }

    let is_code = |sec: SectionIndex| -> bool {
        matches!(obj.sections.get(sec), Some(s) if s.kind == ObjSectionKind::Code)
    };

    let protected_addrs: BTreeSet<u64> = load_merge_protect_addrs();

    let mut pdata_anchored: BTreeSet<(SectionIndex, u64)> = BTreeSet::new();
    for sa in &obj.pdata_funcs {
        pdata_anchored.insert((sa.section, sa.address as u64));
    }

    // Reloc-target -> list of SOURCE VAs (code-section refs). Unlike the class-2
    // zero-xref test, class-4 tails are reached by a BRANCH from the head, which
    // dtk models as a relocation INTO the tail — so the tail is NOT zero-xref. We
    // must distinguish an INTERNAL reference (source inside the reconstructed
    // function span) from an EXTERNAL one (bl / vtable slot / data ptr / jumptable
    // from outside). A tail with any external source is an independent function.
    // src_va = None for a data-section source (always external for a code tail).
    let symbol_count = obj.symbols.count();
    let mut xref_src: BTreeMap<(SectionIndex, u64), Vec<Option<u64>>> = BTreeMap::new();
    for (src_sec, section) in obj.sections.iter() {
        let src_is_code = is_code(src_sec);
        // NOTE: `ObjRelocations` is keyed by the ABSOLUTE source VA (the tracker
        // inserts instruction VAs), so `src_addr` IS the source VA directly — do
        // NOT add section.address (that would double-count and mark every
        // referenced tail external).
        for (src_addr, reloc) in section.relocations.iter() {
            if reloc.target_symbol >= symbol_count {
                continue;
            }
            let tsym = &obj.symbols[reloc.target_symbol];
            let Some(tsec) = tsym.section else { continue };
            if !is_code(tsec) {
                continue;
            }
            let tva = tsym.address as i64 + reloc.addend;
            if tva < 0 {
                continue;
            }
            let src_va = if src_is_code { Some(src_addr as u64) } else { None };
            xref_src.entry((tsec, tva as u64)).or_default().push(src_va);
        }
    }
    // Does target `a` have any reference sourced OUTSIDE [lo, hi)? (data sources
    // and any code source outside the window count as external.)
    let has_external_ref = |sec: SectionIndex, a: u64, lo: u64, hi: u64| -> bool {
        match xref_src.get(&(sec, a)) {
            None => false,
            Some(srcs) => srcs.iter().any(|s| match s {
                None => true,
                Some(v) => *v < lo || *v >= hi,
            }),
        }
    };

    // Per code section: sorted (addr, size, anon, protected, name).
    #[allow(clippy::type_complexity)] // read-only census scratch; kept as a tuple
    let mut by_section: BTreeMap<SectionIndex, Vec<(u64, u64, bool, bool, String)>> =
        BTreeMap::new();
    for (_idx, sym) in obj.symbols.iter() {
        let Some(sec) = sym.section else { continue };
        if sym.kind != ObjSymbolKind::Function || sym.size == 0 || !is_code(sec) {
            continue;
        }
        let anon = sym.name.starts_with("fn_") || sym.name.starts_with("lbl_");
        let prot = protected_addrs.contains(&sym.address);
        by_section.entry(sec).or_default().push((
            sym.address,
            sym.size,
            anon,
            prot,
            sym.name.clone(),
        ));
    }
    for v in by_section.values_mut() {
        v.sort_by_key(|&(a, _, _, _, _)| a);
        v.dedup_by_key(|&mut (a, _, _, _, _)| a);
    }

    // Object symbols in code sections (except_data / padding / jump tables) keyed
    // by start -> end. Used only under JEFF_CLASS4_RELAX to allow the head→tail
    // adjacency to skip exactly one intervening data-in-text object (the MakeHSL
    // case: an except_data record sits between the head and its first anon tail).
    let relax = std::env::var_os("JEFF_CLASS4_RELAX").is_some();
    let mut obj_span: BTreeMap<(SectionIndex, u64), u64> = BTreeMap::new();
    if relax {
        for (_idx, sym) in obj.symbols.iter() {
            let Some(sec) = sym.section else { continue };
            if sym.kind == ObjSymbolKind::Object && sym.size > 0 && is_code(sec) {
                obj_span.insert((sec, sym.address), sym.address + sym.size);
            }
        }
    }

    let mut out: Box<dyn std::io::Write> = match std::env::var_os("JEFF_CLASS4_CENSUS_OUT") {
        Some(p) => match std::fs::File::create(&p) {
            std::result::Result::Ok(f) => Box::new(std::io::BufWriter::new(f)),
            std::result::Result::Err(e) => {
                log::warn!("JEFF_CLASS4_CENSUS_OUT {:?} unwritable: {e:#}; using stderr", p);
                Box::new(std::io::stderr())
            }
        },
        None => Box::new(std::io::stderr()),
    };

    let (mut total, mut proof_yes, mut proof_no) = (0u64, 0u64, 0u64);
    let (mut pinned, mut gap) = (0u64, 0u64);
    let (mut head_blr, mut head_b, mut head_bctr, mut head_cond, mut head_other) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut chain1, mut chain2, mut chain3plus) = (0u64, 0u64, 0u64);
    let mut proof_yes_pinned = 0u64;
    let (mut relaxed_groups, mut relaxed_proof) = (0u64, 0u64);

    for (sec, funcs) in &by_section {
        let Some(section) = obj.sections.get(*sec) else { continue };
        let split_key = |a: u64| section.splits.for_address(a as u32).map(|(s, _)| s);
        let split_name = |a: u64| {
            section.splits.for_address(a as u32).map(|(_, sp)| sp.unit.clone())
        };
        let n = funcs.len();
        let mut i = 0usize;
        while i < n {
            let (h_addr, h_size, h_anon, h_prot, h_name) = funcs[i].clone();
            let head_named = !h_anon || h_prot;
            let dbg = std::env::var_os("JEFF_CLASS4_DEBUG").is_some()
                && (h_addr == 0x824F5480 || h_addr == 0x824F5368);
            if dbg {
                eprintln!(
                    "[C4DBG] head 0x{:x} size 0x{:x} anon={} prot={} named={}; next func: {:x?}; \
                     objspan@end={:x?}",
                    h_addr,
                    h_size,
                    h_anon,
                    h_prot,
                    head_named,
                    funcs.get(i + 1).map(|f| (f.0, f.1, f.2, f.3)),
                    obj_span.get(&(*sec, h_addr + h_size)),
                );
            }
            if !head_named {
                i += 1;
                continue;
            }
            // Phase 1: greedy maximal structural run (adjacency + anon +
            // non-pdata + same-split + not-protected), IGNORING xref for now.
            let h_split = split_key(h_addr);
            let mut j = i;
            let mut cur_end = h_addr + h_size;
            let mut run: Vec<(u64, u64)> = Vec::new(); // (addr, size)
            let mut relaxed_used = false;
            while j + 1 < n {
                let (a, sz, anon, prot, _) = funcs[j + 1].clone();
                if a != cur_end {
                    // P1 adjacency. Under JEFF_CLASS4_RELAX, tolerate exactly one
                    // intervening data-in-text object (except_data/padding) that
                    // fills [cur_end, a) — the MakeHSL over-carve shape.
                    if relax && obj_span.get(&(*sec, cur_end)).copied() == Some(a) {
                        relaxed_used = true;
                    } else {
                        break;
                    }
                }
                if !anon {
                    break; // tail must be anonymous
                }
                if pdata_anchored.contains(&(*sec, a)) {
                    break; // P4 not pdata-anchored (authoritative boundary)
                }
                if split_key(a) != h_split {
                    break; // P5 same split unit
                }
                if prot {
                    break; // don't absorb a map-identified real function tail
                }
                run.push((a, sz));
                cur_end = a + sz;
                j += 1;
            }
            if dbg {
                eprintln!("[C4DBG] run for 0x{:x}: {:x?}", h_addr, run);
            }
            if run.is_empty() {
                i += 1;
                continue;
            }
            let run_end = cur_end;
            // Phase 2: cut the run at the first tail that has an EXTERNAL reference
            // (sourced outside [h_addr, run_end)) — that tail is an independent
            // function, not part of this head. A branch from the head into a tail
            // is an INTERNAL ref (source inside the window) and is allowed.
            let mut tail_addrs: Vec<u64> = Vec::new();
            let mut chain_end = h_addr + h_size;
            for &(a, sz) in &run {
                if has_external_ref(*sec, a, h_addr, run_end) {
                    break;
                }
                tail_addrs.push(a);
                chain_end = a + sz;
            }
            if tail_addrs.is_empty() {
                i += 1;
                continue;
            }
            let first_tail = tail_addrs[0];
            // Branch-target proof: any non-bl branch in the accumulated span whose
            // target lands in [first_tail, chain_end).
            let mut branchproof = false;
            let mut w = h_addr;
            while w + 4 <= chain_end {
                if let Some(word) = read_u32(section, w as u32) {
                    if let Some(t) = ppc_branch_target(word, w) {
                        if t >= first_tail && t < chain_end {
                            branchproof = true;
                            break;
                        }
                    }
                }
                w += 4;
            }
            // Head terminating instruction class.
            let last = read_u32(section, (h_addr + h_size - 4) as u32).unwrap_or(0);
            let op = last >> 26;
            let htag = if matches!(last, 0x4E80_0020 | 0x4E80_0021) {
                head_blr += 1;
                "BLR"
            } else if op == 18 && (last & 1) == 0 {
                head_b += 1;
                "B"
            } else if matches!(last, 0x4E80_0420 | 0x4E80_0421) {
                head_bctr += 1;
                "BCTR"
            } else if op == 16 {
                head_cond += 1;
                "BCOND"
            } else {
                head_other += 1;
                "OTHER"
            };

            total += 1;
            if branchproof {
                proof_yes += 1;
            } else {
                proof_no += 1;
            }
            let is_pinned = h_split.is_some();
            if is_pinned {
                pinned += 1;
            } else {
                gap += 1;
            }
            if branchproof && is_pinned {
                proof_yes_pinned += 1;
            }
            match tail_addrs.len() {
                1 => chain1 += 1,
                2 => chain2 += 1,
                _ => chain3plus += 1,
            }
            if relaxed_used {
                relaxed_groups += 1;
                if branchproof {
                    relaxed_proof += 1;
                }
            }

            let _ = writeln!(
                out,
                "CLASS4 head={:#010x} headsize={:#x} headname={} headprot={} headterm={} \
                 ntails={} tails={:x?} chainend={:#010x} branchproof={} pinned={} relaxed={} split={}",
                h_addr,
                h_size,
                h_name,
                h_prot as u8,
                htag,
                tail_addrs.len(),
                tail_addrs,
                chain_end,
                branchproof as u8,
                is_pinned as u8,
                relaxed_used as u8,
                split_name(h_addr).unwrap_or_else(|| "GAP".to_string()),
            );

            // Advance past the head + the INCLUDED tails only (the run may have
            // been cut short by an external ref; the cut tail restarts the scan).
            let _ = j;
            i += 1 + tail_addrs.len();
        }
    }

    let _ = writeln!(
        out,
        "CLASS4_SUMMARY total={total} branchproof_yes={proof_yes} branchproof_no={proof_no} \
         pinned={pinned} gap={gap} proof_yes_pinned={proof_yes_pinned} \
         head_blr={head_blr} head_b={head_b} head_bctr={head_bctr} head_cond={head_cond} \
         head_other={head_other} chain1={chain1} chain2={chain2} chain3plus={chain3plus} \
         relaxed_groups={relaxed_groups} relaxed_proof={relaxed_proof}"
    );
    let _ = out.flush();
    log::info!(
        "JEFF_CLASS4_CENSUS: {total} named-head over-carve group(s) \
         (branchproof yes={proof_yes} no={proof_no}; pinned={pinned}; proof_yes_pinned={proof_yes_pinned})"
    );
}

/// Merge the CLASS-4 defect: post-`blr`/branch OVER-CARVE. jeff/dtk splits ONE
/// real function into a NAMED (map-identified) head `S1` plus one or more
/// CONTIGUOUS anonymous `fn_<addr>` tail fragments, triggered by an early-return
/// `blr` and/or a forward conditional branch INSIDE the head. objdiff then pairs
/// our full compiled body only against the tiny head (→ a 0.3–1.0% reading). The
/// SOURCE and the VA→name map are already correct; the defect is purely the
/// target carve. This pass grows `S1` to cover `[S1.addr, chain_end)` and strips
/// the absorbed anon tails, so the target `.obj` contains the whole function.
///
/// ## Exact complement of [`merge_fallthrough_leaf_fragments`] (Class-2)
///
/// Class-2 required the head to NOT end in a hard-flow terminator (fall-through,
/// its P2). Class-4 heads DO end in a terminator (`blr`/`b`/`bctr`) yet the body
/// continues past it into a zero-EXTERNAL-ref anon tail reached by a *branch*
/// inside the head. Class-2's P2 excludes them by design; this pass is the
/// disjoint other half. It reuses Class-2's entire safety architecture (P4 pdata,
/// P5 same-split-unit, P6 `JEFF_MERGE_PROTECT`, audit log, run AFTER leaf-synthesis
/// and the Class-2 merge, BEFORE the prune).
///
/// ## Predicate (design.md §"Class 4", the census-validated ground truth)
///   - **P1 adjacency (exact):** `cur_end == next.addr` — no intervening object.
///     (The relaxed one-intervening-`except_data` variant is intentionally NOT
///     implemented here; ship exact first.)
///   - **P2′ POSITIVE BRANCH-TARGET PROOF (load-bearing, MANDATORY):** there is a
///     non-`bl` branch inside `[S1.addr, chain_end)` whose computed target VA lands
///     in `[first_tail, chain_end)`. This is what licenses merging *across* a `blr`
///     (a `blr` legitimately ends most real functions, so adjacency alone is
///     unsafe). Without it the pass over-fires by ≥10 (e.g. the
///     `fn_822769A8`→`fn_82276A20` except_data phantom, which this proof FAILs).
///   - **P3′ zero EXTERNAL refs:** the tail's only incoming references are sourced
///     INSIDE the reconstructed span. NOT "zero incoming relocs" — the head's
///     branch INTO the tail IS a reloc; we test only refs whose *source* VA lies
///     outside the window. `ObjRelocations` is keyed by ABSOLUTE source VA (the
///     tracker inserts instruction VAs), so `src_addr` is used directly — adding
///     `section.address` would mark every referenced tail external and the pass
///     would find nothing. Tail must also be anon (`fn_`/`lbl_`).
///   - **P4 not-pdata-anchored (HARD):** neither the head nor any tail is a
///     `.pdata`-anchored start. This correctly blocks MakeHSL (its tail is behind
///     the pdata-anchored shared return block `fn_824F54D0`). Never relaxed.
///   - **P5 same-split-unit:** all tails share the head's split unit (else dtk's
///     "split ends within symbol" build failure).
///   - **P6 `JEFF_MERGE_PROTECT`:** a protected address is never absorbed as a
///     tail (tails are anon by construction, so this is belt-and-suspenders). The
///     head is the chain HEAD and grows keeping its identity.
///
/// ## Idempotency / re-split byte-stability
///
/// Monotone (only grows named heads / strips anon tails), deterministic, and runs
/// every split AFTER leaf-synthesis. In a PINNED unit the leaf pass never re-carves
/// a code-only (branch-target) leaf out of a parent, so the merged head stays
/// merged. Should a stale cache or a gap re-carve re-create a tail, this pass
/// re-merges it on the same pass, and the prune is the belt-and-suspenders — the
/// emitted `symbols.txt` converges to the merged extent across re-splits.
fn merge_branch_reached_overcarve_tails(obj: &mut ObjInfo) {
    use std::collections::{BTreeMap, BTreeSet};

    let is_code = |sec: SectionIndex| -> bool {
        matches!(obj.sections.get(sec), Some(s) if s.kind == ObjSectionKind::Code)
    };

    // (0) Externally-identified real function starts to never absorb (P6).
    let protected_addrs: BTreeSet<u64> = load_merge_protect_addrs();

    // (1) pdata-anchored starts — genuine boundaries, never merged (P4).
    let mut pdata_anchored: BTreeSet<(SectionIndex, u64)> = BTreeSet::new();
    for sa in &obj.pdata_funcs {
        pdata_anchored.insert((sa.section, sa.address as u64));
    }

    // (2) Reloc-target -> list of SOURCE VAs (code sources) / None (data source).
    //     Class-4 tails ARE reached by a branch from the head (a reloc INTO the
    //     tail), so they are never literally zero-xref; we distinguish an INTERNAL
    //     ref (source inside the reconstructed span) from an EXTERNAL one. MUST-FIX:
    //     `ObjRelocations` is keyed by the ABSOLUTE source VA — use `src_addr`
    //     directly (do NOT add section.address).
    let symbol_count = obj.symbols.count();
    let mut xref_src: BTreeMap<(SectionIndex, u64), Vec<Option<u64>>> = BTreeMap::new();
    for (src_sec, section) in obj.sections.iter() {
        let src_is_code = is_code(src_sec);
        for (src_addr, reloc) in section.relocations.iter() {
            if reloc.target_symbol >= symbol_count {
                continue;
            }
            let tsym = &obj.symbols[reloc.target_symbol];
            let Some(tsec) = tsym.section else { continue };
            if !is_code(tsec) {
                continue;
            }
            let tva = tsym.address as i64 + reloc.addend;
            if tva < 0 {
                continue;
            }
            let src_va = if src_is_code { Some(src_addr as u64) } else { None };
            xref_src.entry((tsec, tva as u64)).or_default().push(src_va);
        }
    }
    // Does target `a` have any reference sourced OUTSIDE [lo, hi)? (P3′)
    let has_external_ref = |sec: SectionIndex, a: u64, lo: u64, hi: u64| -> bool {
        match xref_src.get(&(sec, a)) {
            None => false,
            Some(srcs) => srcs.iter().any(|s| match s {
                None => true,
                Some(v) => *v < lo || *v >= hi,
            }),
        }
    };

    // (3) Per code section: function symbols sorted by address, with symbol index.
    //     `protected` is recomputed inline from `protected_addrs` where needed
    //     (keeps this tuple a 4-field one, matching the Class-2 pass).
    let mut by_section: BTreeMap<SectionIndex, Vec<(SymbolIndex, u64, u64, bool)>> = BTreeMap::new();
    for (idx, sym) in obj.symbols.iter() {
        let Some(sec) = sym.section else { continue };
        if sym.kind != ObjSymbolKind::Function || sym.size == 0 || !is_code(sec) {
            continue;
        }
        let anon = sym.name.starts_with("fn_") || sym.name.starts_with("lbl_");
        by_section.entry(sec).or_default().push((idx, sym.address, sym.size, anon));
    }
    for v in by_section.values_mut() {
        v.sort_by_key(|&(_, a, _, _)| a);
        v.dedup_by_key(|&mut (_, a, _, _)| a);
    }

    // (4) Plan merges (immutable borrow only), then apply. A plan is
    //     (head_idx, new_size, head_addr, chain_end, [tail_idx..]).
    struct Plan {
        head_idx: SymbolIndex,
        new_size: u64,
        head_addr: u64,
        chain_end: u64,
        tail_idxs: Vec<SymbolIndex>,
    }
    let mut plans: Vec<Plan> = Vec::new();

    for (sec, funcs) in &by_section {
        let Some(section) = obj.sections.get(*sec) else { continue };
        let split_key = |a: u64| section.splits.for_address(a as u32).map(|(s, _)| s);
        let n = funcs.len();
        let mut i = 0usize;
        while i < n {
            let (_h_idx, h_addr, h_size, h_anon) = funcs[i];
            let h_prot = protected_addrs.contains(&h_addr);
            // Head must be map-identified/named (protected or a real dtk name).
            let head_named = !h_anon || h_prot;
            if !head_named {
                i += 1;
                continue;
            }
            let h_split = split_key(h_addr);
            // Phase 1: greedy maximal structural run (P1 exact adjacency + anon +
            // P4 non-pdata + P5 same-split + P6 not-protected), ignoring xref.
            let mut j = i;
            let mut cur_end = h_addr + h_size;
            let mut run: Vec<(SymbolIndex, u64, u64)> = Vec::new(); // (idx, addr, size)
            while j + 1 < n {
                let (a_idx, a, sz, anon) = funcs[j + 1];
                if a != cur_end {
                    break; // P1 exact adjacency (relaxed variant not implemented)
                }
                if !anon {
                    break; // tail must be anonymous
                }
                if pdata_anchored.contains(&(*sec, a)) {
                    break; // P4 not pdata-anchored (authoritative boundary)
                }
                if split_key(a) != h_split {
                    break; // P5 same split unit
                }
                if protected_addrs.contains(&a) {
                    break; // P6 never absorb a map-identified real function tail
                }
                run.push((a_idx, a, sz));
                cur_end = a + sz;
                j += 1;
            }
            if run.is_empty() {
                i += 1;
                continue;
            }
            let run_end = cur_end;
            // Phase 2: cut the run at the first tail with an EXTERNAL reference
            // (sourced outside [h_addr, run_end)) — that tail is an independent
            // function. A branch from the head into a tail is an INTERNAL ref.
            let mut tail_idxs: Vec<SymbolIndex> = Vec::new();
            let mut tail_addrs: Vec<u64> = Vec::new();
            let mut chain_end = h_addr + h_size;
            for &(t_idx, a, sz) in &run {
                if has_external_ref(*sec, a, h_addr, run_end) {
                    break;
                }
                tail_idxs.push(t_idx);
                tail_addrs.push(a);
                chain_end = a + sz;
            }
            if tail_addrs.is_empty() {
                i += 1;
                continue;
            }
            let first_tail = tail_addrs[0];
            // P2′ branch-target proof (MANDATORY): a non-bl branch in the
            // accumulated span whose target lands in [first_tail, chain_end).
            let mut branchproof = false;
            let mut w = h_addr;
            while w + 4 <= chain_end {
                if let Some(word) = read_u32(section, w as u32) {
                    if let Some(t) = ppc_branch_target(word, w) {
                        if t >= first_tail && t < chain_end {
                            branchproof = true;
                            break;
                        }
                    }
                }
                w += 4;
            }
            let consumed = tail_addrs.len();
            if branchproof {
                plans.push(Plan {
                    head_idx: funcs[i].0,
                    new_size: chain_end - h_addr,
                    head_addr: h_addr,
                    chain_end,
                    tail_idxs,
                });
            }
            // Advance past the head + the included tails (mirrors the census: a
            // branchproof-failing group's anon tails are never valid heads, so
            // consuming them is safe and keeps the scan linear).
            i += 1 + consumed;
        }
    }

    // (5) Apply: grow each head to its chain end, strip the absorbed anon tails
    //     (same symbol-removal convention as the Class-2 merge / the prune).
    let mut merged_runs = 0usize;
    let mut absorbed = 0usize;
    for plan in &plans {
        let existing = obj.symbols[plan.head_idx].clone();
        let head_name = existing.name.clone();
        let absorbed_addrs: Vec<u64> = plan
            .tail_idxs
            .iter()
            .map(|&t| obj.symbols[t].address)
            .collect();
        log::info!(
            "Merging branch-reached over-carve tails into {} @ {:#010x}: absorbing {:#x?} \
             -> merged size {:#x} (end {:#010x}); reason=anon+internal-only+branch-proven, \
             non-pdata (Class-4)",
            head_name,
            plan.head_addr,
            absorbed_addrs,
            plan.new_size,
            plan.chain_end
        );
        let resized = ObjSymbol { size: plan.new_size, size_known: true, ..existing };
        if let Err(e) = obj.symbols.replace(plan.head_idx, resized) {
            log::warn!("Failed to grow branch-reached over-carve head #{}: {e:#}", plan.head_idx);
            continue;
        }
        merged_runs += 1;
        for &t_idx in &plan.tail_idxs {
            let frag = obj.symbols[t_idx].clone();
            let stripped = ObjSymbol {
                name: format!("__MERGED_{}", frag.name),
                kind: ObjSymbolKind::Unknown,
                size: 0,
                flags: ObjSymbolFlagSet(
                    ObjSymbolFlags::RelocationIgnore
                        | ObjSymbolFlags::NoWrite
                        | ObjSymbolFlags::NoExport
                        | ObjSymbolFlags::Stripped,
                ),
                ..frag
            };
            if let Err(e) = obj.symbols.replace(t_idx, stripped) {
                log::warn!("Failed to strip absorbed over-carve tail #{t_idx}: {e:#}");
                continue;
            }
            absorbed += 1;
        }
    }

    if merged_runs > 0 {
        log::info!(
            "Merged {} branch-reached over-carve group(s), absorbing {} anon tail symbol(s) \
             (Class-4 complement of the fall-through merge; pdata partition preserved)",
            merged_runs,
            absorbed
        );
    }
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
    // Synthesize/promote PDATA-less leaf functions that CFA absorbed into an
    // oversized neighbor or emitted as a bare data label. Runs AFTER the clamp
    // (so pdata-authoritative bounds are settled) and BEFORE the prune (its
    // additions are cleanly partitioned, so the prune sees no new overlaps).
    synthesize_reloc_targeted_leaf_functions(&mut module.obj);
    // Merge the INVERSE defect: adjacent anonymous fall-through PDATA-less leaf
    // fragments that CFA/leaf-synthesis over-split out of one compiled function
    // (the AddRoll class). Runs AFTER synthesis (its fragments are the input) and
    // BEFORE the prune (a merge never creates an overlap; the prune is the
    // belt-and-suspenders for a stale-cache re-carve). Always-on; an optional
    // JEFF_MERGE_PROTECT identification map suppresses absorbing map-identified
    // real functions (P6).
    merge_fallthrough_leaf_fragments(&mut module.obj);
    // Merge the CLASS-4 defect (the disjoint complement of the above): a NAMED
    // (map-identified) head that ends in a hard terminator (`blr`/`b`) yet
    // continues past it into contiguous anonymous, internal-only, branch-proven
    // tails. Grows the head to cover the whole function so the target `.obj`
    // pairs the full compiled body. Runs AFTER the Class-2 merge and BEFORE the
    // prune (same slot/idempotency model); the mandatory branch-target proof (P2′)
    // licenses merging across the head's `blr`. Always-on; JEFF_MERGE_PROTECT (P6)
    // shields map-identified real functions from being absorbed as tails.
    merge_branch_reached_overcarve_tails(&mut module.obj);
    prune_overlapping_phantom_functions(&mut module.obj);
    // A function body can never contain the NEXT function's 8-byte EH prefix.
    // Runs here, after the repair passes, because CFA can legitimately discover a
    // real function in the bytes `strip_spurious_except_data` un-blocked and then
    // size it by running to the next known function start. See
    // `clamp_functions_over_except_data`.
    clamp_functions_over_except_data(&mut module.obj);
    // CLASS 1 CENSUS (env-gated, read-only): dump terminatorless survivors after
    // the full repair pipeline. No-op unless JEFF_CLASS1_CENSUS is set.
    census_terminatorless_functions(&module.obj);
    // CLASS 4 CENSUS (env-gated, read-only): named-head post-blr/branch over-carve
    // groups. No-op unless JEFF_CLASS4_CENSUS is set.
    census_class4_overcarve(&module.obj);

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

    // Strip `except_data_*` symbols that sit on live code, using the SAME
    // word1-resolves-to-a-code-section evidence `write_coff` has used since
    // `b1bc97c`. This has to happen HERE — after the symbols file is applied
    // (that is where the offenders come from) and before ANY extent analysis or
    // symbol/split writing — because `write_coff`'s decision came far too late
    // to stop the symbol terminating a function's extent or reaching `write_asm`
    // as an `.obj` block of `.4byte`. See `strip_spurious_except_data`.
    let (stripped, regrown) = strip_spurious_except_data(&mut obj);
    if stripped > 0 {
        log::info!(
            "Stripped {stripped} spurious except_data symbol(s) on live code \
             ({regrown} truncated function extent(s) re-grown)"
        );
    }

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
    use super::{
        overlapping_function_intervals, plan_fallthrough_merge_runs,
        synthesize_reloc_targeted_leaf_functions, LeafFrag,
    };
    use crate::obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjSection, ObjSectionKind,
        ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    };


    // Instruction words for the merge predicate tests.
    const BLR: u32 = 0x4E80_0020; // hard flow terminator
    const ADDI: u32 = 0x396B_0001; // addi r11,r11,1 — fall-through (AddRoll's lastS1)

    /// Builder for a fall-through fragment with the common "mergeable tail" shape
    /// (anonymous, zero xref, non-pdata, fall-through last insn, all in one unit).
    fn frag(addr: u64, size: u64, last: u32) -> LeafFrag {
        LeafFrag {
            addr,
            size,
            last_insn: last,
            xref: 0,
            anon: true,
            pdata: false,
            split_key: Some(1),
            protected: false,
        }
    }

    // ---- reloc-targeted leaf synthesis: internal-reference gates -------------
    //
    // Fixture reproducing `?LowerForearm@ST@@YAHKPAK@Z` @ 0x82B728F8 from DC3
    // (build/373307D9/asm/xdk/ST/modelfittingstage.s), a switch whose jump table
    // lives inside its own body:
    //
    //   0x1000  bgt    cr6, .Ldefault      ; range check
    //   0x1004  lis    r12, jumptable@ha   <- reloc, source INSIDE the function
    //   0x1008  addi   r12, r12, jumptable@l <- reloc, source INSIDE the function
    //   0x100C  bctr                       ; hard flow terminator
    //   0x1010  jumptable_00001010 (Object, 8 bytes of absolute case addresses)
    //   0x1018  blr                        ; case body, still the parent's code
    const BCTR: u32 = 0x4E80_0420;

    fn leaf_test_obj() -> ObjInfo {
        let words: [u32; 8] = [
            0x4199_0014, // 0x1000 bgt cr6, 0x1014
            0x3D80_0000, // 0x1004 lis r12, jumptable@ha
            0x398C_1010, // 0x1008 addi r12, r12, jumptable@l
            BCTR,        // 0x100C
            0x0000_1018, // 0x1010 jump table entry 0 (data)
            0x0000_1018, // 0x1014 jump table entry 1 (data)
            BLR,         // 0x1018 case body
            BLR,         // 0x101C case body
        ];
        let data: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        let section = ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: 0x1000,
            size: data.len() as u64,
            data,
            align: 4,
            ..Default::default()
        };
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "leaf-synth-test".into(),
            vec![],
            vec![section],
        )
    }

    fn add_sym(obj: &mut ObjInfo, name: &str, addr: u64, size: u64, kind: ObjSymbolKind) -> u32 {
        obj.add_symbol(
            ObjSymbol {
                name: name.into(),
                address: addr,
                section: Some(0),
                size,
                size_known: true,
                flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
                kind,
                ..Default::default()
            },
            false,
        )
        .expect("add_symbol")
    }

    fn add_reloc(obj: &mut ObjInfo, src: u32, target: u32) {
        obj.sections[0].relocations.insert(src, ObjReloc {
            kind: ObjRelocKind::PpcAddr16Ha,
            target_symbol: target,
            addend: 0,
            module: None,
        })
        .expect("insert reloc");
    }

    /// The jump table must stay an Object and the parent must keep its full
    /// extent. Before the fix the pass clamped the parent to prologue+dispatch
    /// and retyped the table as a Function, so the NEXT `dtk xex split` aborted
    /// with "Overlapping functions 4:0x82B728F8-4:0x82B72974 -> 4:0x82B7291C".
    #[test]
    fn jump_table_is_not_promoted_to_a_leaf_function() {
        let mut obj = leaf_test_obj();
        let parent = add_sym(&mut obj, "parent", 0x1000, 0x20, ObjSymbolKind::Function);
        let jt = add_sym(&mut obj, "jumptable_00001010", 0x1010, 0x8, ObjSymbolKind::Object);
        // The only references to the table are the lis/addi pair inside `parent`.
        add_reloc(&mut obj, 0x1004, jt);
        add_reloc(&mut obj, 0x1008, jt);

        synthesize_reloc_targeted_leaf_functions(&mut obj);

        assert_eq!(obj.symbols[jt].kind, ObjSymbolKind::Object, "jump table must stay data");
        assert_eq!(obj.symbols[jt].size, 0x8, "jump table size must not grow into the case bodies");
        assert_eq!(obj.symbols[parent].size, 0x20, "parent must not be clamped at its own dispatch");
    }

    /// Same shape, but the case-table base is an unnamed address inside the
    /// parent rather than a `jumptable_*` symbol (DC3's `Curl_raw_toupper`
    /// @ 0x82585A30 uses `lbzx` offsets added to an in-body base). Only the
    /// internal-reference gate can reject this one.
    #[test]
    fn internally_referenced_address_is_not_promoted_to_a_leaf_function() {
        let mut obj = leaf_test_obj();
        let parent = add_sym(&mut obj, "parent", 0x1000, 0x20, ObjSymbolKind::Function);
        // Reference the case-block base at 0x1010 via parent+0x10, from inside parent.
        obj.sections[0].relocations.insert(0x1004, ObjReloc {
            kind: ObjRelocKind::PpcAddr16Ha,
            target_symbol: parent,
            addend: 0x10,
            module: None,
        })
        .expect("insert reloc");

        synthesize_reloc_targeted_leaf_functions(&mut obj);

        assert_eq!(obj.symbols[parent].size, 0x20, "parent must not be clamped");
        assert!(
            obj.symbols.at_section_address(0, 0x1010).all(|(_, s)| s.kind != ObjSymbolKind::Function),
            "an address referenced only from inside its own function is not a function entry"
        );
    }

    /// The gate must not disable the pass's real job: a leaf that CFA absorbed
    /// into a neighbour, but which something OUTSIDE that neighbour references,
    /// is still carved out.
    #[test]
    fn externally_referenced_leaf_is_still_synthesized() {
        let mut obj = leaf_test_obj();
        // Append a separate function at 0x1020 that references parent+0x10.
        obj.sections[0].data.extend_from_slice(&BLR.to_be_bytes());
        obj.sections[0].data.extend_from_slice(&BLR.to_be_bytes());
        obj.sections[0].size = obj.sections[0].data.len() as u64;
        let parent = add_sym(&mut obj, "parent", 0x1000, 0x20, ObjSymbolKind::Function);
        add_sym(&mut obj, "caller", 0x1020, 0x8, ObjSymbolKind::Function);
        obj.sections[0].relocations.insert(0x1020, ObjReloc {
            kind: ObjRelocKind::PpcAddr16Ha,
            target_symbol: parent,
            addend: 0x10,
            module: None,
        })
        .expect("insert reloc");

        synthesize_reloc_targeted_leaf_functions(&mut obj);

        assert!(
            obj.symbols.at_section_address(0, 0x1010).any(|(_, s)| s.kind == ObjSymbolKind::Function),
            "an externally referenced absorbed leaf must still be split out"
        );
        assert_eq!(obj.symbols[parent].size, 0x10, "parent clamps to its first real split point");
    }

    #[test]
    fn addroll_two_fragment_merge() {
        // The confirmed TU5 fixture: fn_826976E0(16B, addi fall-through) +
        // fn_826976F0(20B, zero xref, anon, non-pdata) -> one 36B function.
        let frags = vec![
            frag(0x8269_76E0, 16, ADDI),
            frag(0x8269_76F0, 20, BLR), // real tail ends on blr
        ];
        assert_eq!(plan_fallthrough_merge_runs(&frags), vec![(0, 1)]);
    }

    #[test]
    fn hard_terminator_blocks_merge() {
        // S1 ends on blr -> control does not fall through, so no merge even
        // though S2 is anonymous/zero-xref/adjacent.
        let frags =
            vec![frag(0x1000, 8, BLR), frag(0x1008, 8, BLR)];
        assert!(plan_fallthrough_merge_runs(&frags).is_empty());
    }

    #[test]
    fn gap_blocks_merge() {
        // Non-adjacent (padding word between) -> P1 fails.
        let frags =
            vec![frag(0x1000, 8, ADDI), frag(0x100C, 8, BLR)];
        assert!(plan_fallthrough_merge_runs(&frags).is_empty());
    }

    #[test]
    fn referenced_second_fragment_blocks_merge() {
        // S2 has an independent entry (nonzero xref) -> it is a real function.
        let mut s2 = frag(0x1008, 8, BLR);
        s2.xref = 1;
        let frags = vec![frag(0x1000, 8, ADDI), s2];
        assert!(plan_fallthrough_merge_runs(&frags).is_empty());
    }

    #[test]
    fn named_second_fragment_blocks_merge() {
        // Never merge away a named/persisted symbol.
        let mut s2 = frag(0x1008, 8, BLR);
        s2.anon = false;
        let frags = vec![frag(0x1000, 8, ADDI), s2];
        assert!(plan_fallthrough_merge_runs(&frags).is_empty());
    }

    #[test]
    fn pdata_anchored_endpoints_block_merge() {
        // A pdata-anchored S1 or S2 is an authoritative boundary (P4).
        let mut s1p = frag(0x1000, 8, ADDI);
        s1p.pdata = true;
        assert!(plan_fallthrough_merge_runs(&[s1p, frag(0x1008, 8, BLR)]).is_empty());
        let mut s2p = frag(0x1008, 8, BLR);
        s2p.pdata = true;
        assert!(plan_fallthrough_merge_runs(&[frag(0x1000, 8, ADDI), s2p]).is_empty());
    }

    #[test]
    fn chain_of_fragments_merges_into_one_run() {
        // Census found chains up to 9 fragments. A 4-fragment chain (each tail
        // falling through into the next, last ending on blr) collapses to one
        // run [0,3]. The named function AFTER the chain is untouched.
        let frags = vec![
            frag(0x2000, 16, ADDI),
            frag(0x2010, 8, ADDI),
            frag(0x2018, 8, ADDI),
            frag(0x2020, 12, BLR),
            LeafFrag {
                addr: 0x2030,
                size: 8,
                last_insn: BLR,
                xref: 3,
                anon: false,
                pdata: true,
                split_key: Some(1),
                protected: false,
            },
        ];
        assert_eq!(plan_fallthrough_merge_runs(&frags), vec![(0, 3)]);
    }

    #[test]
    fn chain_stops_at_first_non_fallthrough_tail() {
        // Fragments 0->1 fall through, but fragment 1 ends on blr, so 2 starts a
        // fresh unit. Only [0,1] merges; 2->3 is an independent adjacent pair
        // that also merges as its own run.
        let frags = vec![
            frag(0x3000, 8, ADDI),
            frag(0x3008, 8, BLR), // terminates -> chain breaks after absorbing here
            frag(0x3010, 8, ADDI),
            frag(0x3018, 8, BLR),
        ];
        assert_eq!(plan_fallthrough_merge_runs(&frags), vec![(0, 1), (2, 3)]);
    }

    #[test]
    fn disjoint_singletons_produce_no_runs() {
        let frags = vec![frag(0x4000, 8, BLR), frag(0x4008, 8, BLR), frag(0x4010, 8, BLR)];
        assert!(plan_fallthrough_merge_runs(&frags).is_empty());
    }

    #[test]
    fn cross_split_unit_boundary_blocks_merge() {
        // The 0x822CFD58/0x822CFD60 over-fire: a gap fragment (split_key None)
        // adjacent to the first anonymous function of the NEXT pinned unit
        // (split_key Some) must NOT fuse across the TU boundary (P5), even though
        // it is adjacent + fall-through + anonymous + zero-xref + non-pdata.
        let mut s1_gap = frag(0x822C_FD58, 8, ADDI);
        s1_gap.split_key = None; // inter-unit gap
        let mut s2_unit = frag(0x822C_FD60, 0x70, BLR);
        s2_unit.split_key = Some(0x822C_FD60); // start of MoveMgr.cpp's pinned unit
        assert!(plan_fallthrough_merge_runs(&[s1_gap, s2_unit]).is_empty());
    }

    #[test]
    fn protected_fragment_is_not_absorbed() {
        // The _M_erase / operator-delete over-fire: an externally-identified real
        // function (protected) reached by fall-through must NOT be absorbed (P6),
        // even though it is adjacent + anonymous + zero-xref + non-pdata +
        // same-unit. The chain HEAD may be protected (it grows, keeping identity).
        let mut s2 = frag(0x1008, 0x50, BLR);
        s2.protected = true;
        assert!(plan_fallthrough_merge_runs(&[frag(0x1000, 8, ADDI), s2]).is_empty());
        // A chain stops at the protected fragment but still merges what precedes.
        let mut prot = frag(0x1018, 4, BLR);
        prot.protected = true;
        let chain = vec![
            frag(0x1000, 8, ADDI),
            frag(0x1008, 8, ADDI),
            frag(0x1010, 8, ADDI),
            prot, // 0x1018 protected -> not absorbed; chain is [0,2]
        ];
        assert_eq!(plan_fallthrough_merge_runs(&chain), vec![(0, 2)]);
    }

    #[test]
    fn same_gap_fragments_still_merge() {
        // Two adjacent fragments both in the same inter-unit gap (split_key None)
        // are one CFA-split function and DO merge — P5 only blocks CROSSING a
        // boundary, not merging within a gap.
        let mut a = frag(0x5000, 8, ADDI);
        a.split_key = None;
        let mut b = frag(0x5008, 8, BLR);
        b.split_key = None;
        assert_eq!(plan_fallthrough_merge_runs(&[a, b]), vec![(0, 1)]);
    }

    /// The Class-4 branch-target proof (P2′) relies on decoding `b`/`bc` targets.
    /// A `bl`/`bcl` (call) must return None (it falls through, does not license a
    /// merge); a backward/forward `b` and a conditional `bc` must decode exactly.
    #[test]
    fn ppc_branch_target_decodes_and_skips_calls() {
        use super::ppc_branch_target;
        // `b +0x20` at 0x1000 (opcode 18, LI=0x20, AA=0, LK=0) -> 0x1020.
        assert_eq!(ppc_branch_target(0x4800_0020, 0x1000), Some(0x1020));
        // `bl +0x20` (LK=1) is a call — must be skipped (None).
        assert_eq!(ppc_branch_target(0x4800_0021, 0x1000), None);
        // Backward `b -0x10` at 0x1000 (LI = -0x10 = 0x03FF_FFF0) -> 0xFF0.
        assert_eq!(ppc_branch_target(0x4BFF_FFF0, 0x1000), Some(0x0FF0));
        // `bge +0x2C` (opcode 16, BD=0x2C, LK=0) at 0x1000 -> 0x102C. This is the
        // MakeColor-class early forward branch that proves the over-carve.
        assert_eq!(ppc_branch_target(0x4080_002C, 0x1000), Some(0x102C));
        // `bcl` (conditional call, LK=1) -> None.
        assert_eq!(ppc_branch_target(0x4080_002D, 0x1000), None);
        // A non-branch instruction (`addi`) -> None.
        assert_eq!(ppc_branch_target(0x396B_0001, 0x1000), None);
        // `bctr`/`blr` are register-form (opcode 19) -> None (not a computed
        // target the proof can use); the head terminator is classified elsewhere.
        assert_eq!(ppc_branch_target(0x4E80_0020, 0x1000), None);
    }

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
