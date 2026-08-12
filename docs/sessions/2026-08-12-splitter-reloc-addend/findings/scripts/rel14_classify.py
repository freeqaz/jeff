#!/usr/bin/env python3
"""Resolve each REL14 to a VA and classify it against the declared function ranges
in the project's config/<ver>/symbols.txt.

Section base VA is recovered from any symbol in the object whose name appears in
symbols.txt (base = symbols_txt_VA - coff_symbol_value), taking the modal answer.
"""
import struct, sys, os, re, json, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rel14_census import load, relocs, sxt, REL14

SYMRE = re.compile(r'^(\S+)\s*=\s*\.(\w+):0x([0-9A-Fa-f]+);(.*)$')


def read_symbols_txt(p):
    name2va, funcs = {}, []
    for line in open(p, encoding='utf-8', errors='replace'):
        m = SYMRE.match(line.strip())
        if not m:
            continue
        name, sec, va, rest = m.group(1), m.group(2), int(m.group(3), 16), m.group(4)
        name2va[name] = va
        if 'type:function' in rest:
            sz = re.search(r'size:0x([0-9A-Fa-f]+)', rest)
            funcs.append((va, va + (int(sz.group(1), 16) if sz else 0), name))
    funcs.sort()
    return name2va, funcs


def enclosing(funcs, va):
    lo, hi = 0, len(funcs)
    while lo < hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= va:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None
    return funcs[lo - 1]


def run(objroot, symtxt):
    name2va, funcs = read_symbols_txt(symtxt)
    c = collections.Counter()
    detail = []
    for dirpath, _, files in os.walk(objroot):
        for f in files:
            if not f.endswith('.obj'):
                continue
            p = os.path.join(dirpath, f)
            try:
                d, secs, syms = load(p)
            except Exception:
                continue
            byidx = {s['idx']: s for s in syms}
            for sec in secs:
                if not sec['nrel']:
                    continue
                rr = [r for r in relocs(d, sec) if r[2] == REL14]
                if not rr:
                    continue
                votes = collections.Counter(
                    name2va[s['name']] - s['value']
                    for s in syms if s['sec'] == sec['idx'] and s['name'] in name2va
                    and name2va[s['name']] >= s['value'])
                if not votes:
                    c['no_base'] += len(rr)
                    continue
                base = votes.most_common(1)[0][0]
                for va, si, ty in rr:
                    site = base + va
                    word = struct.unpack_from('>I', d, sec['rawptr'] + va)[0]
                    dest = site + sxt(word & 0xFFFC, 16)
                    t = byidx.get(si, {'name': '??', 'value': 0, 'sec': 0})
                    tva = base + t['value'] if t['sec'] == sec['idx'] else None
                    ef = enclosing(funcs, site)
                    site_in_fn = ef is not None and ef[0] <= site < ef[1]
                    dest_in_same_fn = ef is not None and ef[0] <= dest < ef[1]
                    c['total'] += 1
                    if not site_in_fn:
                        c['A_site_outside_declared_function'] += 1
                    elif dest_in_same_fn:
                        c['B_site_in_fn_and_dest_in_same_fn'] += 1
                    else:
                        c['C_site_in_fn_dest_elsewhere'] += 1
                    if tva is not None and tva == site + 4:
                        c['fallthrough_anchored(target==site+4)'] += 1
                    if tva is not None and tva != dest:
                        c['reloc_target_ne_encoded_dest'] += 1
                    detail.append(dict(obj=os.path.relpath(p, objroot), site=site, dest=dest,
                                       target=t['name'], tva=tva,
                                       encl=ef[2] if ef else None,
                                       encl_lo=ef[0] if ef else None,
                                       encl_hi=ef[1] if ef else None,
                                       site_in_fn=site_in_fn,
                                       same_section=(t['sec'] == sec['idx'])))
    return c, detail


if __name__ == '__main__':
    c, detail = run(sys.argv[1], sys.argv[2])
    json.dump(detail, open(sys.argv[3], 'w'), indent=1)
    print(dict(c))
