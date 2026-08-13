#!/usr/bin/env python3
"""A/B two trees of PPC-COFF objects and classify every difference.

Usage: t4_obj_ab_diff.py <base_obj_root> <fix_obj_root>

For every .obj present in either tree, compare:
  * the set of object files                (added / removed)
  * section headers: name, raw size, flags (layout change -> COMDAT movement)
  * section raw data, byte for byte        (codegen / fixup change)
  * the symbol table (name, value, section, storage class)
  * the relocation records (offset, type, target symbol NAME)

Everything is reported as a typed delta so a parity account can say what moved
and why, rather than "N objects differ".
"""
import os
import struct
import sys
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rel14_census import load, relocs  # noqa: E402

REL_TYPE_NAMES = {
    0x0001: "ADDR32", 0x0006: "ADDR24", 0x0007: "REL14",
    0x0010: "REFHI", 0x0011: "REFLO", 0x0012: "PAIR", 0x0018: "REL24",
}


def summarize(path):
    d, secs, syms = load(path)
    byidx = {s["idx"]: s for s in syms}
    sections = []
    for s in secs:
        data = d[s["rawptr"]:s["rawptr"] + s["rawsz"]] if s["rawptr"] else b""
        rr = []
        for va, si, ty in relocs(d, s):
            t = byidx.get(si, {"name": "?%d" % si})
            rr.append((va, ty, t["name"]))
        sections.append(dict(name=s["name"], size=s["rawsz"], flags=s["flags"],
                             data=data, relocs=rr))
    symbols = [(x["name"], x["value"], x["sec"], x["cls"]) for x in syms]
    return sections, symbols


def main(base_root, fix_root):
    base_files = {os.path.relpath(os.path.join(dp, f), base_root)
                  for dp, _, fs in os.walk(base_root) for f in fs if f.endswith(".obj")}
    fix_files = {os.path.relpath(os.path.join(dp, f), fix_root)
                 for dp, _, fs in os.walk(fix_root) for f in fs if f.endswith(".obj")}
    c = collections.Counter()
    reloc_delta = collections.Counter()
    unexplained = []
    print("objects: base=%d fix=%d  only_base=%d only_fix=%d"
          % (len(base_files), len(fix_files),
             len(base_files - fix_files), len(fix_files - base_files)))
    for rel in sorted(base_files & fix_files):
        bp, fp = os.path.join(base_root, rel), os.path.join(fix_root, rel)
        b_raw, f_raw = open(bp, "rb").read(), open(fp, "rb").read()
        if b_raw == f_raw:
            c["identical"] += 1
            continue
        c["differs"] += 1
        bs, bsy = summarize(bp)
        fs, fsy = summarize(fp)
        why = set()
        if [(s["name"], s["size"], s["flags"]) for s in bs] != \
           [(s["name"], s["size"], s["flags"]) for s in fs]:
            why.add("SECTION_LAYOUT")
        if len(bs) == len(fs):
            for a, b in zip(bs, fs):
                if a["data"] != b["data"]:
                    why.add("SECTION_DATA")
                ra, rb = collections.Counter(a["relocs"]), collections.Counter(b["relocs"])
                for k, n in (ra - rb).items():
                    why.add("RELOC_REMOVED_" + REL_TYPE_NAMES.get(k[1], hex(k[1])))
                    reloc_delta["-" + REL_TYPE_NAMES.get(k[1], hex(k[1]))] += n
                for k, n in (rb - ra).items():
                    why.add("RELOC_ADDED_" + REL_TYPE_NAMES.get(k[1], hex(k[1])))
                    reloc_delta["+" + REL_TYPE_NAMES.get(k[1], hex(k[1]))] += n
        if bsy != fsy:
            why.add("SYMBOL_TABLE")
        key = "|".join(sorted(why)) or "UNKNOWN(byte-level only)"
        c["why:" + key] += 1
        if key != "RELOC_REMOVED_REL14":
            unexplained.append((rel, key))
    print()
    for k, v in sorted(c.items()):
        print("%-60s %d" % (k, v))
    print()
    print("relocation record delta (fix - base):", dict(reloc_delta))
    print()
    print("objects whose ONLY difference is not 'REL14 records removed': %d" % len(unexplained))
    for rel, key in unexplained[:40]:
        print("   ", rel, "->", key)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
