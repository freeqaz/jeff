use std::{collections::HashMap, fs::File, vec::Vec};

use anyhow::{ensure, Result};
use itertools::Itertools;
use pdb::{self, FallibleIterator, SectionOffset};
use typed_path::Utf8NativePathBuf;

use crate::obj::{
    ObjDataKind, ObjSection, ObjSections, ObjSymbol, ObjSymbolFlagSet, ObjSymbolKind,
    ObjSymbolScope,
};

pub fn try_parse_pdb(
    path: &Utf8NativePathBuf,
    section_addrs: &ObjSections,
) -> Result<Vec<ObjSymbol>> {
    let mut addr_vec: Vec<ObjSymbol> = vec![];
    let mut dbfile = pdb::PDB::open(File::open(path)?)?;

    // setup configgery
    let mut pdb2dtk_section_table: [u8; 32] =
        std::array::from_fn::<u8, 32, _>(|x: usize| -> u8 { x as u8 });
    let symtable = dbfile.global_symbols()?;
    let pdbmap = dbfile.address_map()?;
    let mut iter = symtable.iter();

    // build PDB -> DTK section lookup table
    ensure!(section_addrs.len() <= 32, "Oh god, why does your XEX have more than 32 sections?");
    {
        let mut dtk_iter = section_addrs.iter();
        let sec_headers = dbfile.sections()?.unwrap();
        while let Some(dtk_section) = dtk_iter.next() {
            sec_headers.iter().enumerate().for_each(|x| {
                log::trace!("PDBPDBPDB || {:x}: {}", x.1.virtual_address, x.1.name());
                if x.1.name() == dtk_section.1.name {
                    pdb2dtk_section_table[x.0 + 1] = dtk_section.0 as u8;
                    log::debug!(
                        "Remapping PDB section {} (no. {}) to DTK section {} (no. {})",
                        x.1.name(),
                        x.0 + 1,
                        dtk_section.1.name,
                        dtk_section.0
                    );
                }
            });
        }
    }

    // Resolve a PDB internal offset to a module VA, or None if the offset does
    // not map (e.g. a COMDAT the linker discarded, offset 0xFFFFFFFF).
    let resolve_va = |symoffset: &SectionOffset| -> Option<u64> {
        if symoffset.section == 0 || symoffset.section as usize >= pdb2dtk_section_table.len() {
            return None;
        }
        let section = section_addrs.get(pdb2dtk_section_table[symoffset.section as usize] as u32)?;
        Some(symoffset.offset as u64 + section.address)
    };

    // churn through actual symbols
    while let Some(symbol) = iter.next()? {
        match symbol.parse() {
            // Public is all the shit available to everyone
            Ok(pdb::SymbolData::Public(data)) => {
                let symoffset: SectionOffset =
                    data.offset.to_section_offset(&pdbmap).unwrap_or_default();
                addr_vec.push(ObjSymbol {
                    name: data.name.to_string().into(),
                    demangled_name: None,
                    address: symoffset.offset as u64
                        + section_addrs
                            .get(pdb2dtk_section_table[symoffset.section as usize] as u32)
                            .unwrap_or(&ObjSection::default())
                            .address,
                    section: Some(symoffset.section as u32),
                    size: 0,
                    size_known: false,
                    flags: ObjSymbolFlagSet::default(),
                    kind: if data.function {
                        ObjSymbolKind::Function
                    } else {
                        ObjSymbolKind::Object
                    },
                    align: None,
                    data_kind: ObjDataKind::Unknown,
                    name_hash: None,
                    demangled_name_hash: None,
                });
            }
            _ => {}
        }
    }

    // VA -> indices of every symbol loaded so far at that address. Publics can
    // legitimately share a VA (identical COMDAT folding), so this maps to a list
    // and a procedure record sizes ALL of them.
    let mut by_addr: HashMap<u64, Vec<usize>> = HashMap::with_capacity(addr_vec.len());
    for (i, sym) in addr_vec.iter().enumerate() {
        by_addr.entry(sym.address).or_default().push(i);
    }

    // Apply one S_GPROC32/S_LPROC32 record: size every existing symbol at its VA,
    // or create a fresh Function symbol when nothing else names that address
    // (static functions have no public at all).
    let mut n_procs = 0usize;
    let mut n_sized = 0usize;
    let mut n_created = 0usize;
    let mut apply_procedure = |data: &pdb::ProcedureSymbol,
                               addr_vec: &mut Vec<ObjSymbol>,
                               by_addr: &mut HashMap<u64, Vec<usize>>| {
        n_procs += 1;
        let Some(symoffset) = data.offset.to_section_offset(&pdbmap) else {
            return;
        };
        let Some(va) = resolve_va(&symoffset) else {
            return;
        };
        if data.len == 0 {
            return;
        }
        let scope = if data.global { ObjSymbolScope::Global } else { ObjSymbolScope::Local };
        if let Some(indices) = by_addr.get(&va) {
            for &i in indices {
                let func = &mut addr_vec[i];
                func.kind = ObjSymbolKind::Function;
                func.flags.set_scope(scope.clone());
                // First procedure record wins; folded duplicates carry the same len.
                if !func.size_known {
                    func.size = data.len as u64;
                    func.size_known = true;
                    n_sized += 1;
                }
            }
        } else {
            let mut flags = ObjSymbolFlagSet::default();
            flags.set_scope(scope.clone());
            addr_vec.push(ObjSymbol {
                name: data.name.to_string().into(),
                demangled_name: None,
                address: va,
                section: Some(symoffset.section as u32),
                size: data.len as u64,
                size_known: true,
                flags,
                kind: ObjSymbolKind::Function,
                align: None,
                data_kind: ObjDataKind::Unknown,
                name_hash: None,
                demangled_name_hash: None,
            });
            by_addr.entry(va).or_default().push(addr_vec.len() - 1);
            n_created += 1;
        }
    };

    // Procedure records are where function LENGTHS live, and they are almost
    // always in the per-module (DBI) streams, not the globals stream — MSVC's
    // globals stream carries S_PROCREF references, which the pdb crate does not
    // surface as Procedure. On HCEX.pdb the globals stream contains ZERO
    // Procedure records while the module streams contain 90,172; skipping the
    // module streams left every pdata-less leaf function sizeless, the tracker
    // skipped it (`size_known` filter), and its unit split with no .text
    // relocations at all.
    {
        let di = dbfile.debug_information()?;
        let mut modules = di.modules()?;
        while let Some(module) = modules.next()? {
            let Some(mi) = dbfile.module_info(&module)? else {
                continue;
            };
            let mut msyms = mi.symbols()?;
            while let Some(sym) = msyms.next()? {
                if let Ok(pdb::SymbolData::Procedure(data)) = sym.parse() {
                    apply_procedure(&data, &mut addr_vec, &mut by_addr);
                }
            }
        }
    }

    // Some PDBs (none seen yet, but upstream dtk assumed it) put Procedure
    // records straight in the globals stream; harvest those too.
    iter = symtable.iter();
    while let Some(symbol) = iter.next()? {
        if let Ok(pdb::SymbolData::Procedure(data)) = symbol.parse() {
            apply_procedure(&data, &mut addr_vec, &mut by_addr);
        }
    }
    log::info!(
        "PDB procedures: {} records, sized {} public symbol(s), created {} static function(s)",
        n_procs,
        n_sized,
        n_created
    );

    // sort vec
    addr_vec.sort_by(|l, r| {
        if l.section == r.section {
            Ord::cmp(&l.address, &r.address)
        } else {
            Ord::cmp(&l.section, &r.section)
        }
    });

    {
        // weed out xidata symbols (jeff finds them later)
        let xidata_symbols: Vec<ObjSymbol> = addr_vec
            .iter()
            .filter_map(|x| if x.name.contains("__imp_") { Some(x.clone()) } else { None })
            .collect_vec();
        let mut vec_it = xidata_symbols.iter().rev();
        while let Some(sym) = vec_it.next() {
            match addr_vec.iter().enumerate().find_map(|x| {
                if x.1.name.contains(sym.name.as_str()) {
                    Some(x.0)
                } else {
                    None
                }
            }) {
                Some(idx) => {
                    log::debug!("Dropping idx {}", idx);
                    addr_vec.remove(idx);
                }
                _ => {}
            };
        }
    }

    // fixup last symbols per section
    // let mut vec_it = addr_vec.iter_mut().peekable();
    // while let Some(sym) = vec_it.next() {
    //     match vec_it.peek() {
    //         Some(next_sym) => {
    //             if sym.section != next_sym.section {
    //                 sym.size = 4;
    //                 sym.size_known = true;
    //             }
    //         }
    //         _ => {}
    //     }
    // }
    Ok(addr_vec)
}
