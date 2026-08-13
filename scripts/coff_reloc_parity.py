#!/usr/bin/env python3
"""Record-level relocation parity for a splitter A/B, over the campaign's coff.py.

Two modes.

  shape <tree> [<tree>...]
      Per tree, over every .obj:
        * REFHI/REFLO + PAIR record shape: every REFHI and every REFLO must be
          followed immediately by exactly one PAIR at the SAME offset whose
          SymbolTableIndex field is 0 (that field is a *displacement*, not a
          symbol index -- MS PE/COFF; see xex.rs:2468-2471 and NOTES FINDING 2).
          No orphan PAIRs, no double PAIRs.
        * the in-place immediate at every REFHI/REFLO site.  D-form: the whole
          low 16 bits must be 0.  DS-form (primary opcode 58 = ld/ldu/lwa,
          62 = std/stdu): bits [15:2] are the displacement and must be 0, bits
          [1:0] are the opcode extension (XO) and are NOT displacement -- they
          are reported, not required to be zero, because the compiler's own
          objects carry XO=2 there.
        * every IMAGE_REL_PPC_REL14, classified intra-function two ways:
          W1 = the relocation's target symbol IS the function symbol enclosing
          the site; W2 = the *encoded* branch destination lands inside the
          enclosing function symbol's [value, next function symbol) range.
          W2 is the T2 classifier and does not depend on symbol naming.

  objdiff <base_tree> <fix_tree>
      For every .obj that differs, enumerate exactly what moved: relocation
      records removed/added (with the in-place instruction word, the target
      symbol and the enclosing function), and raw section-data byte deltas.

Exit status is 0 always; the caller reads the printed counters.  Nothing is
written anywhere.
"""
import collections
import json
import os
import struct
import sys

COFF_PY = os.environ.get(
    "T7_COFF_PY",
    "/home/free/code/milohax/decomp-bench/archive/runs/2026-08-12-gap-bug-hunt/work/review",
)
sys.path.insert(0, COFF_PY)
from coff import load, relocs  # noqa: E402


def sym_types(path):
    """{symbol index: COFF Type field} for one object.

    coff.py is the campaign's record-level instrument and is used unchanged for
    everything else here, but its symbol dicts drop the 2-byte `Type` field --
    and function-ness (Type == 0x20, DTYPE_FUNCTION) is exactly what the REL14
    intra-function classifiers key on.  This reads that one field back, over the
    same layout coff.py walks.
    """
    d = open(path, "rb").read()
    _, _, _, psym, nsym, _, _ = struct.unpack_from("<HHIIIHH", d, 0)
    out, i = {}, 0
    while i < nsym:
        e = d[psym + i * 18:psym + i * 18 + 18]
        _, _, typ, _, naux = struct.unpack_from("<IhHBB", e, 8)
        out[i] = typ
        i += 1 + naux
    return out

REFHI, REFLO, PAIR, REL14 = 0x0010, 0x0011, 0x0012, 0x0007
TYPE_NAMES = {0x0001: "ADDR32", 0x0006: "ADDR24", 0x0007: "REL14",
              0x0010: "REFHI", 0x0011: "REFLO", 0x0012: "PAIR", 0x0018: "REL24"}
IMAGE_SYM_TYPE_FUNC = 0x20
DS_FORM_OPCODES = (58, 62)


def walk(root):
    for dp, _, fs in os.walk(root):
        for f in sorted(fs):
            if f.endswith(".obj"):
                yield os.path.join(dp, f)


def sxt(v, bits):
    m = 1 << (bits - 1)
    return (v ^ m) - m


def secdata(d, sec):
    return d[sec["rawptr"]:sec["rawptr"] + sec["rawsz"]] if sec["rawptr"] else b""


def word_at(d, sec, off):
    p = sec["rawptr"] + off
    if not sec["rawptr"] or p + 4 > len(d):
        return None
    return struct.unpack_from(">I", d, p)[0]


def fn_symbols(syms, types, secidx):
    return sorted([s for s in syms
                   if s["sec"] == secidx and types.get(s["idx"], 0) == IMAGE_SYM_TYPE_FUNC],
                  key=lambda s: s["value"])


def enclosing(fns, off):
    lo = None
    hi = None
    for s in fns:
        if s["value"] <= off:
            lo = s
        else:
            hi = s
            break
    return lo, hi


def shape(root, limit_examples=8):
    c = collections.Counter()
    viol = []
    xo_sites = []
    for p in walk(root):
        try:
            d, secs, syms = load(p)
            types = sym_types(p)
        except Exception as e:
            # a zero-byte or truncated .obj is not a relocation-shape finding;
            # count it and keep going rather than losing the whole tree.
            c["UNPARSEABLE_OBJECT"] += 1
            viol.append((p, "-", 0, "unparseable: %s" % e))
            continue
        byidx = {s["idx"]: s for s in syms}
        for sec in secs:
            if not sec["nrel"]:
                continue
            rr = relocs(d, sec)
            for i, (off, si, ty) in enumerate(rr):
                c["reloc_total"] += 1
                c["type_" + TYPE_NAMES.get(ty, hex(ty))] += 1
                if ty in (REFHI, REFLO):
                    nxt = rr[i + 1] if i + 1 < len(rr) else None
                    if nxt is None or nxt[2] != PAIR:
                        c["VIOL_no_pair_after"] += 1
                        viol.append((p, sec["name"], off, "no PAIR follows %s" % TYPE_NAMES[ty]))
                    else:
                        if nxt[0] != off:
                            c["VIOL_pair_offset"] += 1
                            viol.append((p, sec["name"], off, "PAIR offset %#x != %#x" % (nxt[0], off)))
                        if nxt[1] != 0:
                            c["VIOL_pair_displacement_nonzero"] += 1
                            viol.append((p, sec["name"], off, "PAIR displacement %d" % nxt[1]))
                        else:
                            c["pair_displacement_zero"] += 1
                    w = word_at(d, sec, off)
                    if w is None:
                        c["VIOL_site_outside_raw_data"] += 1
                        continue
                    prim = (w >> 26) & 0x3F
                    imm = w & 0xFFFF
                    if prim in DS_FORM_OPCODES:
                        c["dsform_site"] += 1
                        if imm & 0xFFFC:
                            c["VIOL_dsform_displacement_nonzero"] += 1
                            viol.append((p, sec["name"], off, "DS-form disp %#x in %08x" % (imm & 0xFFFC, w)))
                        else:
                            c["dsform_displacement_zero"] += 1
                        if imm & 0x3:
                            c["dsform_xo_nonzero"] += 1
                            if len(xo_sites) < 40:
                                xo_sites.append((os.path.relpath(p, root), sec["name"], off, "%08x" % w))
                        else:
                            c["dsform_xo_zero"] += 1
                    else:
                        c["dform_site"] += 1
                        if imm:
                            c["VIOL_dform_immediate_nonzero"] += 1
                            viol.append((p, sec["name"], off, "D-form imm %#x in %08x" % (imm, w)))
                        else:
                            c["dform_immediate_zero"] += 1
                elif ty == PAIR:
                    prv = rr[i - 1] if i else None
                    if prv is None or prv[2] not in (REFHI, REFLO):
                        c["VIOL_orphan_pair"] += 1
                        viol.append((p, sec["name"], off, "PAIR with no REFHI/REFLO before it"))
                elif ty == REL14:
                    c["rel14"] += 1
                    t = byidx.get(si, {"name": "?", "value": 0, "sec": 0})
                    fns = fn_symbols(syms, types, sec["idx"])
                    lo, hi = enclosing(fns, off)
                    w = word_at(d, sec, off) or 0
                    bd = sxt(w & 0xFFFC, 16)
                    aa = (w >> 1) & 1
                    dest = (bd & 0xFFFFFFFF) if aa else (off + bd) & 0xFFFFFFFF
                    if t["sec"] != sec["idx"]:
                        c["rel14_cross_section"] += 1
                    else:
                        c["rel14_same_section"] += 1
                    if lo is not None and t["name"] == lo["name"]:
                        c["rel14_intra_fn_W1_target_is_enclosing_fn"] += 1
                    if lo is not None and lo["value"] <= dest < (hi["value"] if hi else sec["rawsz"]):
                        c["rel14_intra_fn_W2_encoded_dest_inside_enclosing_fn"] += 1
    print("== %s" % root)
    for k in sorted(c):
        print("   %-52s %d" % (k, c[k]))
    if xo_sites:
        print("   DS-form sites with XO != 0 (opcode extension preserved):")
        for s in xo_sites:
            print("      %s %s +%#x %s" % s)
    if viol:
        print("   VIOLATION EXAMPLES (%d total):" % len(viol))
        for v in viol[:limit_examples]:
            print("      %s %s +%#x  %s" % (os.path.relpath(v[0], root), v[1], v[2], v[3]))
    print()
    return c, viol


def describe(path):
    d, secs, syms = load(path)
    types = sym_types(path)
    byidx = {s["idx"]: s for s in syms}
    out = {}
    for sec in secs:
        rr = []
        for off, si, ty in relocs(d, sec):
            t = byidx.get(si, {"name": "?%d" % si, "value": 0, "sec": 0})
            w = word_at(d, sec, off)
            fns = fn_symbols(syms, types, sec["idx"])
            lo, _ = enclosing(fns, off)
            rr.append((off, ty, t["name"], "%08x" % (w or 0), (lo or {}).get("name")))
        out[sec["name"] + "#%d" % sec["idx"]] = dict(data=secdata(d, sec), relocs=rr,
                                                     size=sec["rawsz"], flags=sec["flags"])
    return out


def objdiff(base_root, fix_root):
    rows = []
    tot = collections.Counter()
    for p in walk(base_root):
        rel = os.path.relpath(p, base_root)
        q = os.path.join(fix_root, rel)
        if not os.path.exists(q):
            rows.append(dict(obj=rel, note="MISSING IN FIX TREE"))
            continue
        b, f = open(p, "rb").read(), open(q, "rb").read()
        if b == f:
            continue
        B, F = describe(p), describe(q)
        removed, added, databytes = [], [], []
        for k in sorted(set(B) | set(F)):
            bb, ff = B.get(k), F.get(k)
            if bb is None or ff is None:
                databytes.append((k, "SECTION ADDED/REMOVED"))
                continue
            cb, cf = collections.Counter(bb["relocs"]), collections.Counter(ff["relocs"])
            for r, n in (cb - cf).items():
                removed.extend([(k,) + r] * n)
            for r, n in (cf - cb).items():
                added.extend([(k,) + r] * n)
            if bb["data"] != ff["data"]:
                for i in range(min(len(bb["data"]), len(ff["data"]))):
                    if bb["data"][i] != ff["data"][i]:
                        databytes.append((k, i, "%02x" % bb["data"][i], "%02x" % ff["data"][i]))
        rows.append(dict(obj=rel,
                         removed=[dict(sec=r[0], off=r[1], typ=TYPE_NAMES.get(r[2], hex(r[2])),
                                       target=r[3], word=r[4], encl=r[5]) for r in removed],
                         added=[dict(sec=r[0], off=r[1], typ=TYPE_NAMES.get(r[2], hex(r[2])),
                                     target=r[3], word=r[4], encl=r[5]) for r in added],
                         data_bytes=[list(map(str, x)) for x in databytes]))
        tot["objects_changed"] += 1
        tot["records_removed"] += len(removed)
        tot["records_added"] += len(added)
        tot["data_bytes_changed"] += len([x for x in databytes if len(x) == 4])
    # objects present only in fix
    for p in walk(fix_root):
        rel = os.path.relpath(p, fix_root)
        if not os.path.exists(os.path.join(base_root, rel)):
            rows.append(dict(obj=rel, note="ONLY IN FIX TREE"))
    print(json.dumps(dict(summary=dict(tot), objects=rows), indent=1))
    for k in sorted(tot):
        print("# %-24s %d" % (k, tot[k]), file=sys.stderr)


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "shape":
        for t in sys.argv[2:]:
            shape(t)
    elif mode == "objdiff":
        objdiff(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("usage: coff_reloc_parity.py shape <tree>... | objdiff <base> <fix>")
