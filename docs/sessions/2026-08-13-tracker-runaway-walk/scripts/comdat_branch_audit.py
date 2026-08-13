#!/usr/bin/env python3
"""Audit every extracted COMDAT code section for conditional branches that leave it.

`write_coff` extracts a COMDAT region into its own `.text$dup` COFF section and
ZEROES the region's bytes in the parent `.text` (util/xex.rs, "Zero out COMDAT
bytes in parent section"). A `bc` carries 14 bits of PC-relative displacement and
gets no fixup at all, so a conditional branch whose destination lies OUTSIDE the
extracted region is broken by that extraction twice over: the linker may lay the
two ends out arbitrarily far apart, and the bytes the branch used to reach are
now dead zeros in the parent section.

So "does any extracted COMDAT code section contain a `bc` (primary opcode 16,
AA = 0) whose destination leaves that section?" is a naming-independent,
byte-level witness for whether the COMDAT keep-back rule is doing its job.
A correct keep-back gives ZERO hits. Exit status is 1 if any tree has a hit.

Usage: comdat_branch_audit.py <obj_root> [<obj_root> ...]
"""
import os
import struct
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "2026-08-12-splitter-reloc-addend", "findings", "scripts",
    ),
)
from rel14_census import load  # noqa: E402

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_LNK_COMDAT = 0x00001000


def escaping_branches(data):
    """(offset, word, dest) for every relative `bc` whose destination leaves `data`."""
    hits = []
    for i in range(0, len(data) - 3, 4):
        ins = struct.unpack_from(">I", data, i)[0]
        if ins >> 26 != 16:
            continue
        if ins & 0b10:  # AA = 1, absolute: layout-independent
            continue
        disp = struct.unpack(">h", struct.pack(">H", ins & 0xFFFC))[0]
        dest = i + disp
        if dest < 0 or dest >= len(data):
            hits.append((i, ins, dest))
    return hits


def main():
    rc = 0
    for root in sys.argv[1:]:
        n_obj = n_comdat = n_bad = 0
        bad = []
        for dirpath, _, files in os.walk(root):
            for f in sorted(files):
                if not f.endswith(".obj"):
                    continue
                p = os.path.join(dirpath, f)
                rel = os.path.relpath(p, root)
                n_obj += 1
                d, secs, _syms = load(p)
                for s in secs:
                    if not (s["flags"] & IMAGE_SCN_LNK_COMDAT):
                        continue
                    if not (s["flags"] & IMAGE_SCN_CNT_CODE):
                        continue
                    n_comdat += 1
                    data = d[s["rawptr"]:s["rawptr"] + s["rawsz"]] if s["rawptr"] else b""
                    hits = escaping_branches(data)
                    if hits:
                        n_bad += 1
                        bad.append((rel, s["name"], len(data), hits))
        print("%s\n    %d objects, %d extracted COMDAT code sections, "
              "%d with an escaping conditional branch" % (root, n_obj, n_comdat, n_bad))
        for rel, name, sz, hits in bad:
            print("    %s [%s size=%#x]" % (rel, name, sz))
            for off, ins, dest in hits[:8]:
                print("        +%#06x  %08x  -> offset %d, outside [0,%#x)"
                      % (off, ins, dest, sz))
        if n_bad:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
