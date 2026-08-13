#!/usr/bin/env python3
"""T6 — turn the self-reference census into a defect count.

The validator's census (NOTES.md, FINDING 3) counted *self-referential*
REFHI/REFLO relocations: relocations whose anchor symbol is the function that
encloses the relocation site.  That is an UPPER BOUND on the addend-loss defect,
not a defect count, because a function legitimately taking its own entry address
(`&fn`, target genuinely fn+0) produces the same record shape.

This script does two things.

1. **Census (self-check).**  Reproduces the validator's four upper-bound totals
   from the raw COFF objects:

       dc3 TARGET 350 / 154 fns      dc3 OURS 6 / 3 fns
       rb3-xenon TARGET 262 / 110    rb3-xenon OURS 20 / 10 fns

   It exits non-zero if any of them fails to reproduce, so a drifted object tree
   can never be silently reported as a result.

2. **Classification.**  Splits the census into `real_loss` (the splitter dropped
   a nonzero intra-function addend) and `legitimate` (the reference really is
   fn+0).

   The discriminator CANNOT come from the target .obj alone — the addend is gone
   by construction (`write_coff`'s `insn & 0xFFFF0000`, xex.rs:2123-2138).  Two
   independent witnesses are used instead, and both are checked against each
   other on every site:

   * **W1 — the splitter's own in-memory ObjInfo.**  `split_write_obj_exe`
     (src/cmd/xex.rs:2771-2813, :2920-2945) builds `split_objs` ONCE and hands
     the same immutable slice to `write_coff` and to `write_asm`.  The asm
     writer renders a relocation as `SYM+0xNNN@ha`, i.e. it serialises exactly
     the `(symbol_idx, target.address - symbol_address)` pair that
     tracker.rs:860 recorded.  So `build/<id>/asm/**.s` IS the pre-write_coff
     ObjInfo addend, in text, from the same run that wrote `obj/**.obj` — no
     re-split and no rebuild required.

   * **W2 — the original retail immediates.**  The byte comment on each asm line
     (`/* VA FILEOFF  3D 80 82 8A */`) is the *original* instruction word, taken
     from the module section data, before `write_coff` zeroes the immediate in
     its output copy.  So the real `@ha`/`@l` halves are still there and the
     materialised address can be recomputed independently of the anchor choice:
     REFHI expects `((target + 0x8000) >> 16) & 0xFFFF`, REFLO expects
     `target & 0xFFFF`.  Any site where W2 disagrees with W1 is reported as
     `witness_disagreement` and is NOT counted as either class.

   For the OURS (compiler-produced) trees there is no asm, and none is needed:
   MSVC's convention is an anchor symbol whose *value* sits at the target
   address, with a zero in-place immediate and a zero PAIR displacement
   (measured 342,386/342,386 by the validator, FINDING 2).  A compiler self-ref
   with both channels zero therefore references fn+0 exactly, and is
   legitimate.  A nonzero channel would be a real addend and is reported.

Known cases the classifier must get right (task acceptance):
    ?CharTerminate@@YAXXZ                                  -> legitimate (fn+0)
    ?HandleEventResponse@SaveLoadManager@@QAAXPAVHamProfile@@H@Z -> real loss, delta 0x164

Read-only.  Touches no build tree, no shared output, no cargo target dir.

Usage:
    python3 selfref_census.py [--dc3 DIR] [--rb3-xenon DIR] [--json OUT.json]
                             [--no-selfcheck] [--verbose]

COFF parsing adapted from the gap-bug-hunt reviewer's parser
(decomp-bench/archive/runs/2026-08-12-gap-bug-hunt/work/review/coff.py) with the
aux-record and section-flag fields this classifier needs added.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import struct
import sys
from collections import defaultdict

# ---------------------------------------------------------------- COFF parser

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SYM_DTYPE_FUNCTION = 0x20
REFHI, REFLO, PAIR = 0x10, 0x11, 0x12


def load_coff(path):
    """Return (data, sections, symbols) for a PPC COFF object."""
    d = open(path, "rb").read()
    _mach, nsec, _ts, psym, nsym, osz, _ch = struct.unpack_from("<HHIIIHH", d, 0)
    secs = []
    off = 20 + osz
    for i in range(nsec):
        name = d[off : off + 8].rstrip(b"\0").decode("latin1")
        (_vsz, _va, rawsz, rawptr, relptr, _lnptr, nrel, _nln, flags) = struct.unpack_from(
            "<IIIIIIHHI", d, off + 8
        )
        secs.append(
            dict(
                idx=i + 1,
                name=name,
                rawsz=rawsz,
                rawptr=rawptr,
                relptr=relptr,
                nrel=nrel,
                flags=flags,
            )
        )
        off += 40
    syms = []
    i = 0
    while i < nsym:
        e = d[psym + i * 18 : psym + i * 18 + 18]
        if e[0:4] == b"\0\0\0\0":
            nm = struct.unpack_from("<I", e, 4)[0]
            s = d[psym + nsym * 18 + nm :]
            name = s[: s.index(b"\0")].decode("latin1")
        else:
            name = e[:8].rstrip(b"\0").decode("latin1")
        val, secn, typ, cls, naux = struct.unpack_from("<IhHBB", e, 8)
        total_size = None
        if naux and typ == IMAGE_SYM_DTYPE_FUNCTION:
            aux = d[psym + (i + 1) * 18 : psym + (i + 1) * 18 + 18]
            total_size = struct.unpack_from("<I", aux, 4)[0] or None
        syms.append(
            dict(name=name, value=val, sec=secn, cls=cls, typ=typ, idx=i, size=total_size)
        )
        i += 1 + naux
    return d, secs, syms


def read_relocs(d, sec):
    return [
        struct.unpack_from("<IIH", d, sec["relptr"] + i * 10) for i in range(sec["nrel"])
    ]


# ------------------------------------------------------------ census predicate


def function_extent(sym, sec, section_functions):
    """Extent of a function symbol: its aux TotalSize when MSVC emitted one,
    else up to the next function symbol in the same section, else section end.

    The fallback matters: dc3 target objects carve one COFF section per function
    (extent == section), but rb3-xenon's OURS objects use a flat `.text` holding
    many functions, where "same section" alone would count a reference to a
    NEIGHBOURING function as self-referential.  That over-counts rb3-xenon OURS
    22/11 against the validator's 20/10.
    """
    if sym["size"]:
        return sym["size"]
    later = [s["value"] for s in section_functions if s["value"] > sym["value"]]
    end = min(later) if later else sec["rawsz"]
    return end - sym["value"]


def collect_selfrefs(root):
    """Every self-referential REFHI/REFLO in an object tree.

    Self-referential := the relocation's anchor symbol is a function symbol whose
    extent contains the relocation site.
    """
    out = []
    n_objs = 0
    n_unreadable = 0
    for path in sorted(glob.glob(os.path.join(root, "**", "*.obj"), recursive=True)):
        try:
            d, secs, syms = load_coff(path)
        except Exception:
            n_unreadable += 1
            continue
        n_objs += 1
        byidx = {s["idx"]: s for s in syms}
        fns_by_sec = defaultdict(list)
        for s in syms:
            if s["typ"] == IMAGE_SYM_DTYPE_FUNCTION and s["sec"] > 0:
                fns_by_sec[s["sec"]].append(s)
        rel = os.path.relpath(path, root)
        for sec in secs:
            if not sec["nrel"] or not (sec["flags"] & IMAGE_SCN_CNT_CODE):
                continue
            rl = read_relocs(d, sec)
            pair_after = {}
            for i, (va, si, ty) in enumerate(rl):
                if ty != PAIR and i + 1 < len(rl) and rl[i + 1][2] == PAIR:
                    # IMAGE_REL_PPC_PAIR's SymbolTableIndex field is a
                    # displacement, not a symbol index (xex.rs:2468-2471).
                    pair_after[va] = rl[i + 1][1]
            for va, si, ty in rl:
                if ty not in (REFHI, REFLO):
                    continue
                t = byidx.get(si)
                if not t or t["sec"] != sec["idx"] or t["typ"] != IMAGE_SYM_DTYPE_FUNCTION:
                    continue
                if not (t["value"] <= va < t["value"] + function_extent(t, sec, fns_by_sec[sec["idx"]])):
                    continue
                word = struct.unpack_from(">I", d, sec["rawptr"] + va)[0]
                out.append(
                    dict(
                        obj=rel,
                        section=sec["name"],
                        fn=t["name"],
                        fn_value=t["value"],
                        off=va - t["value"],
                        kind="REFHI" if ty == REFHI else "REFLO",
                        word=word,
                        imm=word & 0xFFFF,
                        pair_disp=pair_after.get(va),
                    )
                )
    return out, n_objs, n_unreadable


# ----------------------------------------------------- witness 1: splitter asm

# `/* 8289B36C 0088FD6C  3D 80 82 8A */\tlis r12, "?Fn"+0x164@ha`
ASM_LINE = re.compile(
    r"^/\*\s*([0-9A-Fa-f]{8})\s+[0-9A-Fa-f]{8}\s+((?:[0-9A-Fa-f]{2} ){3}[0-9A-Fa-f]{2})\s*\*/\s*(.*)$"
)
ASM_FN = re.compile(r'^\.fn\s+(?:"([^"]*)"|([^\s,]+))')
ASM_ENDFN = re.compile(r"^\.endfn\b")
# operand reference: quoted or bare symbol, optional +0xNNN, then @ha / @l
ASM_REF = re.compile(r'(?:"([^"]+)"|([A-Za-z_$.@?][\w$.@?<>]*))(?:\+0x([0-9A-Fa-f]+))?@(ha|l)\b')


def parse_asm_unit(path):
    """{fn_name: {"va": start_va, "insns": {offset: (word, text)}}} for one .s."""
    fns = {}
    cur = None
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            s = line.strip()
            m = ASM_FN.match(s)
            if m:
                cur = m.group(1) if m.group(1) is not None else m.group(2)
                fns.setdefault(cur, dict(va=None, insns={}))
                continue
            if ASM_ENDFN.match(s):
                cur = None
                continue
            if cur is None:
                continue
            m = ASM_LINE.match(s)
            if not m:
                continue
            va = int(m.group(1), 16)
            word = int(m.group(2).replace(" ", ""), 16)
            text = m.group(3)
            rec = fns[cur]
            if rec["va"] is None:
                rec["va"] = va
            rec["insns"][va - rec["va"]] = (word, text)
    return fns


FN_ADDR_NAME = re.compile(r"^fn_([0-9A-Fa-f]{8})$")


class AsmIndex:
    """Lazy per-unit index of the splitter's own asm output.

    Joining obj -> asm by symbol NAME is enough on dc3 but not on rb3-xenon: that
    project runs `scripts/obj_target_symbol_renamer.py` as a post-SPLIT ninja step
    which rewrites `fn_<addr>` symbols in the .obj to MSVC mangled names from
    `scripts/target_symbol_map.json`.  The asm files keep the splitter's original
    `fn_<addr>` names, so 180 of 262 rb3-xenon sites fail a name join.  Passing
    that rename map lets the join fall back to address.
    """

    def __init__(self, asm_root, rename_map=None):
        self.root = asm_root
        self._cache = {}
        # Inverse of the post-split renamer's map.  That renamer keys on the
        # SYMBOL NAME `fn_%08X` / `lbl_%08X` built from the map key, not on the
        # symbol's address (obj_target_symbol_renamer.py load_address_map), and
        # on rb3-xenon the two differ: `fn_82C27048` actually starts at
        # 0x82C26F98.  Joining on the address would silently miss those.
        self.name_to_asmnames = defaultdict(list)
        self.name_to_vas = defaultdict(list)
        for va, name in (rename_map or {}).items():
            # the map also carries a few `_`-prefixed metadata keys with list values
            if not va.lower().startswith("0x") or not isinstance(name, str):
                continue
            addr = int(va, 16)
            self.name_to_asmnames[name].append("fn_%08X" % addr)
            self.name_to_asmnames[name].append("lbl_%08X" % addr)
            self.name_to_vas[name].append(addr)

    def unit(self, obj_relpath):
        rel = obj_relpath[:-4] + ".s" if obj_relpath.endswith(".obj") else obj_relpath + ".s"
        if rel not in self._cache:
            p = os.path.join(self.root, rel)
            fns = parse_asm_unit(p) if os.path.exists(p) else None
            if fns is not None:
                by_va = {}
                for nm, rec in fns.items():
                    if rec["va"] is not None:
                        by_va[rec["va"]] = (nm, rec)
                fns = {"_by_name": fns, "_by_va": by_va}
            self._cache[rel] = fns
        return self._cache[rel]

    def lookup(self, unit, obj_sym_name):
        """(asm_name, record) for an obj function symbol, or (None, None)."""
        rec = unit["_by_name"].get(obj_sym_name)
        if rec is not None and rec["va"] is not None:
            return obj_sym_name, rec
        m = FN_ADDR_NAME.match(obj_sym_name)
        if m:
            hit = unit["_by_va"].get(int(m.group(1), 16))
            if hit:
                return hit
        named = [
            n for n in self.name_to_asmnames.get(obj_sym_name, [])
            if unit["_by_name"].get(n, {}).get("va") is not None
        ]
        if len(set(named)) == 1:
            return named[0], unit["_by_name"][named[0]]
        cands = [va for va in self.name_to_vas.get(obj_sym_name, []) if va in unit["_by_va"]]
        if len(set(cands)) == 1:
            return unit["_by_va"][cands[0]]
        return None, None


def asm_addend(text, names):
    """Addend the splitter's ObjInfo carried for a self-reference on this fn.

    `names` is the set of names the anchor may go by — the obj symbol name and,
    where a post-split renamer moved it, the splitter's own `fn_<addr>` name.

    Returns (addend, ok).  ok is False when the asm operand does not reference
    this function at all — that means the obj and the asm disagree about the
    site and the row must not be classified.
    """
    for m in ASM_REF.finditer(text):
        name = m.group(1) if m.group(1) is not None else m.group(2)
        if name in names:
            return (int(m.group(3), 16) if m.group(3) else 0), True
    return 0, False


SYMLINE = re.compile(r"^(\S+)\s*=\s*\.[\w$.]+:0x([0-9A-Fa-f]+)\s*;")


def parse_symbols_txt(path):
    """name -> virtual address, from the splitter's own symbols file.

    Needed because the asm VA column is NOT a reliable function address on
    rb3-xenon: in `xdk/xmic/xmicapi.s` the `.fn fn_82C27048` block prints its
    first instruction at 0x82C26F98, 0xB0 below the address symbols.txt gives
    for that symbol, and the drift is not uniform across a unit.  The addend
    text in the asm operand is unaffected (it is the ObjInfo addend, not an
    address), so only witness 2 needs this.
    """
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            m = SYMLINE.match(line.strip())
            if m:
                out.setdefault(m.group(1), int(m.group(2), 16))
    return out


# ------------------------------------------- witness 2: original retail immediate


def expected_immediate(kind, target_va):
    if kind == "REFHI":
        return ((target_va + 0x8000) >> 16) & 0xFFFF
    return target_va & 0xFFFF


def check_original_immediate(kind, word, target_va):
    """Does the ORIGINAL instruction word materialise `target_va`?

    Returns (agrees, note).  DS-form instructions (primary opcode 58/62) hold the
    displacement in bits 0..13 with the low two bits as opcode extension, so only
    the top 14 bits of the field are compared there.
    """
    want = expected_immediate(kind, target_va)
    got = word & 0xFFFF
    opcode = (word >> 26) & 0x3F
    if kind == "REFLO" and opcode in (58, 62):
        return (got & 0xFFFC) == (want & 0xFFFC), "ds-form"
    return got == want, ""


# ------------------------------------------------------ dispatch-context probe

DISPATCH_LOAD = re.compile(r"\b(lbzx|lhzx|lwzx|lhax|lbz|lhz|lwz)\b")


def dispatch_context(insns, off, window=8):
    """Corroborating instruction context: does this site feed a switch dispatch?

    A jump-table base is consumed by an indexed load / add / mtctr / bctr within a
    few instructions.  A plain address-of is not.  Advisory only — the addend
    witnesses decide the class; this is reported so the two can be compared.
    """
    seen = set()
    for i in range(0, window + 1):
        ins = insns.get(off + 4 * i)
        if not ins:
            continue
        text = ins[1]
        if DISPATCH_LOAD.search(text):
            seen.add("load")
        if re.search(r"\badd\b", text):
            seen.add("add")
        if "mtctr" in text:
            seen.add("mtctr")
        if "bctr" in text:
            seen.add("bctr")
    return {"mtctr", "bctr"} <= seen


# ----------------------------------------------------------------- classifier


def classify_target_tree(sites, asm_root, rename_map=None, sym_vas=None):
    idx = AsmIndex(asm_root, rename_map)
    sym_vas = sym_vas or {}
    for s in sites:
        unit = idx.unit(s["obj"])
        if unit is None:
            s["verdict"] = "unclassified"
            s["why"] = "no asm unit"
            continue
        asm_name, rec = idx.lookup(unit, s["fn"])
        if rec is None:
            s["verdict"] = "unclassified"
            s["why"] = "fn not in asm"
            continue
        s["asm_fn"] = asm_name
        ins = rec["insns"].get(s["off"])
        if ins is None:
            s["verdict"] = "unclassified"
            s["why"] = "offset not in asm"
            continue
        word, text = ins
        addend, ok = asm_addend(text, {s["fn"], asm_name})
        if not ok:
            s["verdict"] = "unclassified"
            s["why"] = "asm operand does not reference this fn: %r" % text
            continue
        fn_va = sym_vas.get(asm_name, sym_vas.get(s["fn"], rec["va"]))
        s["fn_va"] = fn_va
        s["fn_va_source"] = "symbols.txt" if fn_va != rec["va"] else "asm"
        s["addend"] = addend
        s["orig_word"] = word
        s["asm"] = text
        s["dispatch_context"] = dispatch_context(rec["insns"], s["off"])
        agrees, note = check_original_immediate(s["kind"], word, fn_va + addend)
        s["w2_agrees"] = agrees
        s["w2_note"] = note
        if not agrees:
            s["verdict"] = "witness_disagreement"
            s["why"] = "orig imm 0x%04x != expected 0x%04x for %s+0x%x" % (
                word & 0xFFFF,
                expected_immediate(s["kind"], fn_va + addend),
                s["fn"],
                addend,
            )
            continue
        s["verdict"] = "real_loss" if addend else "legitimate"
    return sites


def classify_ours_tree(sites):
    """Compiler-produced objects: the anchor's VALUE sits at the target address.

    Both addend channels (the in-place immediate and the PAIR displacement) being
    zero means the site references the anchor exactly, i.e. fn+0.
    """
    for s in sites:
        s["addend"] = 0
        chans = []
        if s["imm"]:
            chans.append("imm=0x%04x" % s["imm"])
        if s["pair_disp"]:
            chans.append("pair_disp=0x%x" % s["pair_disp"])
        if chans:
            s["verdict"] = "real_loss"
            s["why"] = "nonzero compiler addend channel: " + ", ".join(chans)
        else:
            s["verdict"] = "legitimate"
            s["why"] = "imm=0 and PAIR displacement=0 -> anchor value IS the target"
    return sites


# ---------------------------------------------------------------------- report


def our_function_names(root):
    """Every function symbol name in a compiler-produced object tree.

    Used to say how much of the real-loss population is on a function we
    actually compile and score today — i.e. how much of the defect the campaign
    can currently see move.
    """
    names = set()
    for path in glob.glob(os.path.join(root, "**", "*.obj"), recursive=True):
        try:
            _d, _secs, syms = load_coff(path)
        except Exception:
            continue
        for s in syms:
            if s["typ"] == IMAGE_SYM_DTYPE_FUNCTION and s["sec"] > 0:
                names.add(s["name"])
    return names


def pairing_check(sites):
    """Every self-ref should be one REFHI + one REFLO at the same addend.

    An unpaired REFHI or a HI/LO pair carrying different addends would mean the
    census predicate or the asm join drifted; report it rather than average it
    away.
    """
    by_fn = defaultdict(list)
    for s in sites:
        by_fn[(s["obj"], s["fn"])].append(s)
    bad = []
    for key, rows in by_fn.items():
        hi = sum(1 for r in rows if r["kind"] == "REFHI")
        lo = sum(1 for r in rows if r["kind"] == "REFLO")
        if hi != lo:
            bad.append("%s :: %s has %d REFHI / %d REFLO" % (key[0], key[1], hi, lo))
    return bad


def fns_of(sites, verdict=None):
    return {
        (s["obj"], s["fn"]) for s in sites if verdict is None or s["verdict"] == verdict
    }


def summarise(sites):
    v = defaultdict(list)
    for s in sites:
        v[s["verdict"]].append(s)
    return {
        "total_sites": len(sites),
        "total_fns": len(fns_of(sites)),
        "real_loss_sites": len(v["real_loss"]),
        "real_loss_fns": len(fns_of(sites, "real_loss")),
        "legitimate_sites": len(v["legitimate"]),
        "legitimate_fns": len(fns_of(sites, "legitimate")),
        "unclassified_sites": len(v["unclassified"]),
        "witness_disagreement_sites": len(v["witness_disagreement"]),
    }


UPPER_BOUND = {
    ("dc3", "target"): (350, 154),
    ("dc3", "ours"): (6, 3),
    ("rb3-xenon", "target"): (262, 110),
    ("rb3-xenon", "ours"): (20, 10),
}

ACCEPTANCE = [
    ("dc3", "ours", "?CharTerminate@@YAXXZ", "legitimate"),
    (
        "dc3",
        "target",
        "?HandleEventResponse@SaveLoadManager@@QAAXPAVHamProfile@@H@Z",
        "real_loss",
    ),
]


def find_sibling(name):
    """Locate a sibling checkout by walking up from this file.

    Works from the main checkout and from a git worktree under `.worktrees/`,
    which sits one or two levels deeper.  No absolute machine path is baked in;
    `--dc3` / `--rb3-xenon` or $DC3_ROOT / $RB3_XENON_ROOT override.
    """
    d = os.path.dirname(os.path.abspath(__file__))
    while True:
        cand = os.path.join(d, name)
        if os.path.isdir(cand):
            return cand
        parent = os.path.dirname(d)
        if parent == d:
            return os.path.join("~", name)
        d = parent


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--dc3",
        default=os.environ.get("DC3_ROOT") or find_sibling("dc3-decomp"),
        help="dc3-decomp checkout (default: nearest sibling checkout, or $DC3_ROOT)",
    )
    ap.add_argument("--dc3-build", default="build/373307D9")
    ap.add_argument(
        "--rb3-xenon",
        default=os.environ.get("RB3_XENON_ROOT") or find_sibling("rb3-xenon"),
        help="rb3-xenon checkout (default: nearest sibling checkout, or $RB3_XENON_ROOT)",
    )
    ap.add_argument("--rb3-xenon-build", default="build/45410914")
    ap.add_argument("--json", help="write the full per-site classification here")
    ap.add_argument("--no-selfcheck", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    games = [
        ("dc3", args.dc3, args.dc3_build),
        ("rb3-xenon", args.rb3_xenon, args.rb3_xenon_build),
    ]

    results = {}
    failures = []
    our_names = {}
    for game, root, build in games:
        base = os.path.join(root, build)
        asm_root = os.path.join(base, "asm")
        # Post-SPLIT symbol renamer map, when the project has one (rb3-xenon).
        rename_map = None
        rm_path = os.path.join(root, "scripts", "target_symbol_map.json")
        if os.path.exists(rm_path):
            with open(rm_path) as fh:
                rename_map = json.load(fh)
        sym_vas = parse_symbols_txt(
            os.path.join(root, "config", os.path.basename(build), "symbols.txt")
        )
        for arm, sub in (("target", "obj"), ("ours", "src")):
            tree = os.path.join(base, sub)
            if not os.path.isdir(tree):
                failures.append("%s/%s: missing tree %s" % (game, arm, tree))
                continue
            sites, n_objs, n_bad = collect_selfrefs(tree)
            if arm == "ours":
                our_names[game] = our_function_names(tree)
            if arm == "target":
                classify_target_tree(sites, asm_root, rename_map, sym_vas)
            else:
                classify_ours_tree(sites)
            summ = summarise(sites)
            summ["objects_parsed"] = n_objs
            summ["objects_unreadable"] = n_bad
            summ["tree"] = os.path.join(build, sub)
            results[(game, arm)] = (summ, sites)

            exp = UPPER_BOUND.get((game, arm))
            if exp and not args.no_selfcheck:
                got = (summ["total_sites"], summ["total_fns"])
                if got != exp:
                    failures.append(
                        "SELFCHECK %s/%s upper bound: expected %s sites / %s fns, got %s / %s"
                        % (game, arm, exp[0], exp[1], got[0], got[1])
                    )

    # acceptance: two named functions must land in named classes
    for game, arm, fn, want in ACCEPTANCE:
        if (game, arm) not in results:
            continue
        rows = [s for s in results[(game, arm)][1] if s["fn"] == fn]
        if not rows:
            failures.append("ACCEPTANCE %s/%s: %s not found in census" % (game, arm, fn))
            continue
        got = sorted({s["verdict"] for s in rows})
        if got != [want]:
            failures.append(
                "ACCEPTANCE %s/%s: %s classified %s, expected [%r]" % (game, arm, fn, got, want)
            )

    # ------------------------------------------------------------ text report
    print("=" * 78)
    print("Self-reference census -> defect count  (REFHI/REFLO anchored on the")
    print("function enclosing the relocation site)")
    print("=" * 78)
    hdr = "%-11s %-7s %5s  %5s %5s   %5s %5s   %5s %5s   %4s %4s" % (
        "game", "arm", "objs", "sites", "fns", "loss", "fns", "legit", "fns", "unk", "dis",
    )
    print(hdr)
    print("-" * len(hdr))
    for (game, arm), (s, _) in results.items():
        print(
            "%-11s %-7s %5d  %5d %5d   %5d %5d   %5d %5d   %4d %4d"
            % (
                game, arm, s["objects_parsed"], s["total_sites"], s["total_fns"],
                s["real_loss_sites"], s["real_loss_fns"],
                s["legitimate_sites"], s["legitimate_fns"],
                s["unclassified_sites"], s["witness_disagreement_sites"],
            )
        )
    print()

    for (game, arm), (s, sites) in results.items():
        if arm != "target":
            continue
        unpaired = pairing_check(sites)
        if unpaired:
            failures.extend("PAIRING %s: %s" % (game, u) for u in unpaired)
        legit = sorted(fns_of(sites, "legitimate"))
        print("%s target — legitimate address-of-own-entry (%d fns):" % (game, len(legit)))
        for obj, fn in legit:
            print("    %s :: %s" % (obj, fn))
        ctx_loss = [x for x in sites if x["verdict"] == "real_loss"]
        with_ctx = sum(1 for x in ctx_loss if x.get("dispatch_context"))
        ctx_legit = [x for x in sites if x["verdict"] == "legitimate"]
        print(
            "    dispatch context (mtctr+bctr within 8 insns): %d/%d real_loss, %d/%d legitimate"
            % (with_ctx, len(ctx_loss), sum(1 for x in ctx_legit if x.get("dispatch_context")), len(ctx_legit))
        )
        deltas = sorted({x["addend"] for x in ctx_loss})
        print("    distinct nonzero deltas: %d (min 0x%x, max 0x%x)"
              % (len(deltas), min(deltas), max(deltas)) if deltas else "    no nonzero deltas")
        ours = our_names.get(game)
        if ours is not None:
            loss_fns = fns_of(sites, "real_loss")
            hit = {f for (_o, f) in loss_fns if f in ours}
            print("    real-loss functions also present in OUR object tree: %d / %d"
                  % (len(hit), len(loss_fns)))
        print()

    if args.verbose:
        for (game, arm), (_s, sites) in results.items():
            for x in sites:
                if x["verdict"] in ("unclassified", "witness_disagreement"):
                    print("  !! %s/%s %s :: %s+0x%x %s -> %s"
                          % (game, arm, x["obj"], x["fn"], x["off"], x["kind"], x.get("why")))

    if args.json:
        blob = {
            "%s/%s" % (g, a): {"summary": s, "sites": sites}
            for (g, a), (s, sites) in results.items()
        }
        with open(args.json, "w") as fh:
            json.dump(blob, fh, indent=1, sort_keys=True)
        print("wrote %s" % args.json)

    if failures:
        print()
        print("FAILED (%d):" % len(failures))
        for f in failures:
            print("  " + f)
        return 1
    print("self-check: all four upper-bound totals reproduced; "
          "both acceptance cases classified as required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
