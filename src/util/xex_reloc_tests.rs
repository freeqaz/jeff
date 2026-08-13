//! Regression tests for the PPC-COFF relocation writer (`util::xex::write_coff`).
//!
//! Session of record: `docs/sessions/2026-08-12-splitter-reloc-addend/`.
//!
//! These tests are deliberately written BEFORE the fix, so the fix has a
//! red-to-green witness. Two of the three are expected to FAIL at
//! `main` = `8a42efb`; the third pins today's (correct) REFHI/REFLO+PAIR record
//! shape so that future anchor work cannot silently change the layout.
//!
//! Every fixture here is a synthetic `ObjInfo` built in-test. Nothing in this
//! file reads a dc3/rb3-xenon checkout, an XEX, or any toolchain output — the
//! tests are portable.
//!
//! | test | shape | at `8a42efb` | today |
//! |---|---|---|---|
//! | `shape2_intra_function_conditional_branch_emits_no_relocation` | Shape 2 | RED | GREEN (T4 landed) |
//! | `ds_form_immediate_zeroing_must_preserve_xo_bits` | Q8 / FINDING 8 | RED | GREEN (T5 restored) |
//! | `refhi_reflo_pair_record_shape_is_pinned` | characterization | GREEN | GREEN |
//!
//! The DS-form test was `#[ignore]`d for one commit at integration (`dbc887a`)
//! and is live again as of the DS-form decode fix
//! (`docs/sessions/2026-08-13-dsform-decode/`): the writer half alone made the
//! LINKED image worse, because the analysis side minted the anchor two bytes
//! past the real datum and the two errors cancelled. Both halves are now
//! correct, so the test is green for the right reason.
//!
//! Run them with — note this crate has **no `[lib]` target**, only `[[bin]] dtk`,
//! so `cargo test --lib` errors with "no library targets found":
//!
//! ```text
//! CARGO_TARGET_DIR=<worktree>/target-scratch cargo test --bin dtk xex_reloc
//! ```
//!
//! The private `CARGO_TARGET_DIR` is mandatory: `dc3-decomp/configure.py:164`
//! points `config.dtk_path` at `../jeff/target/release/dtk`, so a build into the
//! default target dir deploys a new splitter to dc3 and rb3-xenon.

use std::collections::BTreeSet;

use object::{Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget};

use crate::{
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjRelocations, ObjSection,
        ObjSectionKind, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    },
    util::xex::write_coff,
};

// MS PE/COFF PowerPC relocation types (winnt.h / PE-COFF spec §5.2.5).
const IMAGE_REL_PPC_REL14: u16 = 0x0007;
const IMAGE_REL_PPC_REFHI: u16 = 0x0010;
const IMAGE_REL_PPC_REFLO: u16 = 0x0011;
const IMAGE_REL_PPC_PAIR: u16 = 0x0012;

/// One relocation record as it appears in the emitted COFF, read back out.
#[derive(Debug, Clone)]
struct CoffRelocRecord {
    /// Offset within the section.
    offset: u64,
    /// `Type` field of the relocation record.
    typ: u16,
    /// `SymbolTableIndex` field of the relocation record. For `IMAGE_REL_PPC_PAIR`
    /// this field is a *displacement*, not a symbol reference — see
    /// `xex.rs` `write_coff` and the PE/COFF spec.
    symbol_index: usize,
    /// Name of the symbol at `symbol_index`, when it resolves to one.
    symbol_name: String,
}

/// Read the named section's data and relocation records back out of an emitted COFF.
///
/// Records are returned in file order, which is the order `write_coff` added
/// them — test 3 depends on that order (REFHI/REFLO immediately followed by its
/// PAIR).
fn read_section(coff_data: &[u8], section_name: &str) -> (Vec<u8>, Vec<CoffRelocRecord>) {
    let file = object::File::parse(coff_data).expect("emitted COFF failed to parse");
    let section = file
        .sections()
        .find(|s| s.name().map(|n| n == section_name).unwrap_or(false))
        .unwrap_or_else(|| panic!("no {section_name} section in emitted COFF"));
    let data = section.data().expect("section data").to_vec();
    let mut records = Vec::new();
    for (offset, reloc) in section.relocations() {
        let typ = match reloc.flags() {
            RelocationFlags::Coff { typ } => typ,
            other => panic!("expected COFF relocation flags, got {other:?}"),
        };
        let (symbol_index, symbol_name) = match reloc.target() {
            RelocationTarget::Symbol(idx) => {
                let name = file
                    .symbol_by_index(idx)
                    .ok()
                    .and_then(|s| s.name().ok().map(|n| n.to_string()))
                    .unwrap_or_default();
                (idx.0, name)
            }
            other => panic!("expected a symbol relocation target, got {other:?}"),
        };
        records.push(CoffRelocRecord { offset, typ, symbol_index, symbol_name });
    }
    (data, records)
}

fn word_at(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn global_fn(name: &str, address: u64, size: u64) -> ObjSymbol {
    ObjSymbol {
        name: name.into(),
        address,
        section: Some(0),
        size,
        size_known: true,
        flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
        kind: ObjSymbolKind::Function,
        ..Default::default()
    }
}

fn text_section(data: Vec<u8>, relocations: ObjRelocations) -> ObjSection {
    ObjSection {
        name: ".text".into(),
        kind: ObjSectionKind::Code,
        address: 0,
        size: data.len() as u64,
        data,
        align: 4,
        elf_index: 0,
        relocations,
        virtual_address: None,
        file_offset: 0,
        section_known: true,
        splits: Default::default(),
    }
}

fn rdata_section(data: Vec<u8>) -> ObjSection {
    ObjSection {
        name: ".rdata".into(),
        kind: ObjSectionKind::ReadOnlyData,
        address: 0x1000,
        size: data.len() as u64,
        data,
        align: 4,
        elf_index: 1,
        relocations: ObjRelocations::default(),
        virtual_address: None,
        file_offset: 0,
        section_known: true,
        splits: Default::default(),
    }
}

fn empty_except_data() -> BTreeSet<String> { BTreeSet::new() }

// ---------------------------------------------------------------------------
// (1) SHAPE 2 — an intra-function conditional branch must not carry a relocation
// ---------------------------------------------------------------------------

/// Shape 2 from the session doc: the splitter emits an `IMAGE_REL_PPC_REL14`
/// on a conditional branch whose destination is *inside* the branch's own
/// function. MSVC never does this — measured across 2,193 compiler-produced
/// objects in dc3 and rb3-xenon, the compiler emits **zero** REL14 (NOTES.md
/// FINDING 3). Because PPC-COFF carries no usable addend for the anchor, the
/// record resolves to `function+0` and objdiff renders a fake control-flow
/// difference.
///
/// The fixture reproduces G36 `Curl_resolv_unlock`: a `beq cr6, +0x10` at
/// `fn+0x24` (`0x419A0010`, the exact word measured in both objects) whose
/// destination `fn+0x34` lies inside the function, plus the REL14 relocation
/// anchored on the enclosing function symbol with the correct in-memory addend.
///
/// EXPECTED TO FAIL at `main` = `8a42efb`: `write_coff` copies the relocation
/// through verbatim.
///
/// NOTE ON THE FIX SEAM: this test asserts on `write_coff` output from a
/// fixture that already contains the bad relocation, so it is only satisfied by
/// a writer-side filter. If the root-cause fix lands in `analysis/tracker.rs`
/// (so the relocation is never created), that is a good fix but this test stays
/// red — `write_coff` still needs the defensive drop for the assertion to hold.
/// That is deliberate: the writer is the last place the invariant "no
/// intra-function REL14 reaches a COFF" can be enforced unconditionally.
#[test]
fn shape2_intra_function_conditional_branch_emits_no_relocation() {
    const FN_START: u64 = 0;
    const FN_SIZE: u64 = 0x40;
    const BRANCH_OFF: u32 = 0x24;
    const BRANCH_DEST: u64 = 0x34;

    let mut data = vec![0u8; FN_SIZE as usize];
    for i in (0..FN_SIZE as usize).step_by(4) {
        data[i..i + 4].copy_from_slice(&0x6000_0000u32.to_be_bytes()); // nop
    }
    // fn+0x24: beq cr6, 0x10  -> fn+0x34 (byte-identical to G36's charged word)
    data[BRANCH_OFF as usize..BRANCH_OFF as usize + 4]
        .copy_from_slice(&0x419A_0010u32.to_be_bytes());
    // fn+0x3C: blr
    data[0x3C..0x40].copy_from_slice(&0x4E80_0020u32.to_be_bytes());

    let mut relocations = ObjRelocations::default();
    relocations
        .insert(BRANCH_OFF, ObjReloc {
            kind: ObjRelocKind::PpcRel14,
            target_symbol: 0, // the enclosing function itself
            addend: (BRANCH_DEST - FN_START) as i64,
            module: None,
        })
        .unwrap();

    let mut obj = ObjInfo::new(
        ObjKind::Relocatable,
        ObjArchitecture::PowerPc,
        "shape2.obj".into(),
        vec![],
        vec![text_section(data, relocations)],
    );
    obj.symbols.add_direct(global_fn("Curl_resolv_unlock", FN_START, FN_SIZE)).unwrap();

    let coff = write_coff(&obj, &empty_except_data()).unwrap();
    let (_, records) = read_section(&coff, ".text");

    // An intra-function REL14 = a REL14 record whose site lies inside
    // [FN_START, FN_START+FN_SIZE) and whose anchor symbol is that same function.
    let offenders: Vec<_> = records
        .iter()
        .filter(|r| r.typ == IMAGE_REL_PPC_REL14)
        .filter(|r| r.offset >= FN_START && r.offset < FN_START + FN_SIZE)
        .filter(|r| r.symbol_name == "Curl_resolv_unlock")
        .collect();

    assert!(
        offenders.is_empty(),
        "write_coff emitted {} intra-function IMAGE_REL_PPC_REL14 record(s); MSVC emits zero \
         REL14 in 2,193 compiler-produced objects across dc3 and rb3-xenon \
         (session NOTES.md FINDING 3). Offenders: {:#x?}\nAll .text records: {:#x?}",
        offenders.len(),
        offenders,
        records,
    );
}

// ---------------------------------------------------------------------------
// (2) DS-FORM — the REFHI/REFLO immediate zeroing must not clear the XO bits
// ---------------------------------------------------------------------------

/// FINDING 8 / open question Q8: `write_coff`'s `PpcAddr16Ha | PpcAddr16Lo` arm
/// does `insn & 0xFFFF0000` (`src/util/xex.rs:2123-2138`). On a **DS-form**
/// instruction — primary opcode 58 (`ld`/`ldu`/`lwa`) or 62 (`std`/`stdu`) —
/// the low two bits are an opcode extension (XO), not displacement. Zeroing all
/// 16 low bits silently rewrites `lwa` -> `ld` and `stdu` -> `std`.
///
/// The correct behaviour is to zero the *displacement* only: bits [15:2] for a
/// DS-form instruction, bits [15:0] for a D-form one.
///
/// Words used here are real shapes:
/// * `0xE96B0002` = `lwa r11, 0(r11)` — measured verbatim at three REFLO sites
///   in our own compiler object `system/gesture/ArcDetector.obj` (NOTES.md
///   FINDING 8).
/// * `0xE96B004A` = the same `lwa` with a nonzero 0x48 displacement, which
///   proves the displacement really is zeroed rather than the arm being
///   deleted wholesale.
/// * `0x398C0048` = `addi r12, r12, 0x48`, a D-form control that must keep
///   losing all 16 bits. It passes today and must keep passing — a "fix" that
///   simply stops zeroing would break it.
///
/// EXPECTED TO FAIL at `main` = `8a42efb` on the two DS-form sites.
///
/// HISTORY, because this test was red, then green, then ignored, then green:
/// T5 (`b204ebd`) made it pass; the integrator reverted that fix (`dbc887a`)
/// and marked this `#[ignore]` after a relink showed MSVC's REFLO is
/// **additive**, so with the analysis side minting the DS-form anchor two bytes
/// past the real datum (`lbl_82F446EE` where the EA is `sDefaultHoverTimer` at
/// `0x82F446EC`) the two defects cancelled at link time and fixing only the
/// writer made the linked image worse. The analysis-side decode is now fixed
/// (`analysis::vm::load_store_displacement`), so the writer fix is restored and
/// this test is live again. Do NOT weaken the assertion: XO must survive, and
/// that claim is measured against the compiler's own objects.
#[test]
fn ds_form_immediate_zeroing_must_preserve_xo_bits() {
    // offset -> (input word, expected word after the write_coff data fixup)
    let sites: [(u32, u32, u32); 3] = [
        // DS-form lwa, displacement already 0: XO=2 must survive.
        (0x00, 0xE96B_0002, 0xE96B_0002),
        // DS-form lwa, displacement 0x48: displacement zeroed, XO=2 survives.
        (0x04, 0xE96B_004A, 0xE96B_0002),
        // D-form addi control: the whole 16-bit immediate is displacement.
        (0x08, 0x398C_0048, 0x398C_0000),
    ];

    let mut data = vec![0u8; 0x10];
    let mut relocations = ObjRelocations::default();
    for &(off, input, _) in &sites {
        data[off as usize..off as usize + 4].copy_from_slice(&input.to_be_bytes());
        relocations
            .insert(off, ObjReloc {
                kind: ObjRelocKind::PpcAddr16Lo,
                target_symbol: 1, // the .rdata object below
                addend: 0,
                module: None,
            })
            .unwrap();
    }
    data[0x0C..0x10].copy_from_slice(&0x4E80_0020u32.to_be_bytes()); // blr

    let mut obj = ObjInfo::new(
        ObjKind::Relocatable,
        ObjArchitecture::PowerPc,
        "dsform.obj".into(),
        vec![],
        vec![text_section(data, relocations), rdata_section(vec![0u8; 4])],
    );
    obj.symbols.add_direct(global_fn("ds_form_fn", 0, 0x10)).unwrap();
    obj.symbols
        .add_direct(ObjSymbol {
            name: "?g_target@@3HA".into(),
            address: 0x1000,
            section: Some(1),
            size: 4,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: ObjSymbolKind::Object,
            ..Default::default()
        })
        .unwrap();

    let coff = write_coff(&obj, &empty_except_data()).unwrap();
    let (text, _) = read_section(&coff, ".text");

    let mut failures = Vec::new();
    for &(off, input, expected) in &sites {
        let actual = word_at(&text, off as usize);
        if actual != expected {
            failures.push(format!(
                "  +{off:#04x}: in {input:#010X} -> out {actual:#010X}, expected {expected:#010X} \
                 (XO bits in={:#x} out={:#x} expected={:#x})",
                input & 0x3,
                actual & 0x3,
                expected & 0x3,
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "write_coff's REFHI/REFLO immediate zeroing corrupted {} of {} sites.\n{}\n\
         `insn & 0xFFFF0000` clears the low two bits, which on a DS-form opcode \
         (primary 58/62) are the opcode extension, not displacement: `lwa` becomes \
         `ld`. Session NOTES.md FINDING 8 / README Q8.",
        failures.len(),
        sites.len(),
        failures.join("\n"),
    );
}

// ---------------------------------------------------------------------------
// (3) Characterization — pin today's REFHI/REFLO + PAIR record shape
// ---------------------------------------------------------------------------

/// Characterization test. Not a bug: this pins the record layout `write_coff`
/// emits today so that future anchor/label work cannot change it silently.
///
/// The shape is measured, not guessed. Across all 989 dc3 compiler-produced
/// objects there are 342,386 REFHI/REFLO relocations and the PAIR displacement
/// is 0 in **342,386 of 342,386** (session NOTES.md FINDING 2). MSVC never uses
/// the PAIR `SymbolTableIndex` displacement channel; its convention is an
/// anchor symbol whose *value* sits at the target address, with a zero in-place
/// immediate. Any fix that starts carrying the intra-function offset in the
/// PAIR displacement would move the artifact rather than remove it, and would
/// trip this test.
///
/// Pinned invariants:
/// 1. exactly one PAIR record per REFHI and per REFLO;
/// 2. each PAIR sits at the same section offset as, and immediately after, the
///    record it pairs with;
/// 3. the PAIR's `SymbolTableIndex` field is 0;
/// 4. the in-place 16-bit immediate at each REFHI/REFLO site is 0.
///
/// EXPECTED TO PASS at `main` = `8a42efb`.
#[test]
fn refhi_reflo_pair_record_shape_is_pinned() {
    // lis r12, hi(g_target) ; nop ; addi r12, r12, lo(g_target) ; blr
    // Immediates start nonzero (as a raw XEX split would) so invariant 4 is a
    // real assertion about the fixup rather than about the input.
    let words: [u32; 4] = [0x3D80_8200, 0x6000_0000, 0x398C_1234, 0x4E80_0020];
    let mut data = Vec::with_capacity(16);
    for w in words {
        data.extend_from_slice(&w.to_be_bytes());
    }

    let mut relocations = ObjRelocations::default();
    relocations
        .insert(0x00, ObjReloc {
            kind: ObjRelocKind::PpcAddr16Ha,
            target_symbol: 1,
            addend: 0,
            module: None,
        })
        .unwrap();
    relocations
        .insert(0x08, ObjReloc {
            kind: ObjRelocKind::PpcAddr16Lo,
            target_symbol: 1,
            addend: 0,
            module: None,
        })
        .unwrap();

    let mut obj = ObjInfo::new(
        ObjKind::Relocatable,
        ObjArchitecture::PowerPc,
        "pair.obj".into(),
        vec![],
        vec![text_section(data, relocations), rdata_section(vec![0u8; 4])],
    );
    obj.symbols.add_direct(global_fn("pair_fn", 0, 0x10)).unwrap();
    obj.symbols
        .add_direct(ObjSymbol {
            name: "?g_target@@3HA".into(),
            address: 0x1000,
            section: Some(1),
            size: 4,
            size_known: true,
            flags: ObjSymbolFlagSet(ObjSymbolFlags::Global.into()),
            kind: ObjSymbolKind::Object,
            ..Default::default()
        })
        .unwrap();

    let coff = write_coff(&obj, &empty_except_data()).unwrap();
    let (text, records) = read_section(&coff, ".text");

    // (1) one PAIR per REFHI/REFLO
    let n_refhi = records.iter().filter(|r| r.typ == IMAGE_REL_PPC_REFHI).count();
    let n_reflo = records.iter().filter(|r| r.typ == IMAGE_REL_PPC_REFLO).count();
    let n_pair = records.iter().filter(|r| r.typ == IMAGE_REL_PPC_PAIR).count();
    assert_eq!(n_refhi, 1, "expected 1 REFHI, records: {records:#x?}");
    assert_eq!(n_reflo, 1, "expected 1 REFLO, records: {records:#x?}");
    assert_eq!(
        n_pair,
        n_refhi + n_reflo,
        "expected one PAIR per REFHI/REFLO, records: {records:#x?}"
    );

    // (2) + (3) each PAIR immediately follows its partner, same offset, symbol index 0
    for (i, rec) in records.iter().enumerate() {
        if rec.typ != IMAGE_REL_PPC_REFHI && rec.typ != IMAGE_REL_PPC_REFLO {
            continue;
        }
        let pair = records
            .get(i + 1)
            .unwrap_or_else(|| panic!("no record follows {rec:#x?}; records: {records:#x?}"));
        assert_eq!(
            pair.typ, IMAGE_REL_PPC_PAIR,
            "record after {rec:#x?} should be IMAGE_REL_PPC_PAIR; records: {records:#x?}"
        );
        assert_eq!(
            pair.offset, rec.offset,
            "PAIR must sit at the same offset as its partner; records: {records:#x?}"
        );
        assert_eq!(
            pair.symbol_index, 0,
            "PAIR SymbolTableIndex is a displacement and MSVC writes 0 there \
             (342,386 of 342,386 dc3 compiler REFHI/REFLO measure 0); records: {records:#x?}"
        );
    }

    // (4) in-place immediates zeroed at the REFHI/REFLO sites
    assert_eq!(
        word_at(&text, 0x00) & 0xFFFF,
        0,
        "REFHI site immediate should be 0, word is {:#010X}",
        word_at(&text, 0x00)
    );
    assert_eq!(
        word_at(&text, 0x08) & 0xFFFF,
        0,
        "REFLO site immediate should be 0, word is {:#010X}",
        word_at(&text, 0x08)
    );
    // The rest of each instruction must survive.
    assert_eq!(word_at(&text, 0x00), 0x3D80_0000);
    assert_eq!(word_at(&text, 0x08), 0x398C_0000);
}
