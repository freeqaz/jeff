#!/usr/bin/env python3
"""Census every IMAGE_REL_PPC_REL14 in a tree of PPC-COFF objects.

For each REL14 record classify:
  same_section  - target symbol lives in the same COFF section as the reloc site
  intra_fn      - target symbol IS the function symbol that encloses the site
                  (enclosing = nearest preceding function-ish symbol in section)
  encoded_dest  - site + sign-extended BD field (what the instruction really says)
"""
import struct, sys, os, json

REL14 = 0x0007


def load(p):
    d = open(p, 'rb').read()
    mach, nsec, ts, psym, nsym, osz, ch = struct.unpack_from('<HHIIIHH', d, 0)
    secs = []
    off = 20 + osz
    for i in range(nsec):
        name = d[off:off + 8].rstrip(b'\0').decode('latin1')
        vsz, va, rawsz, rawptr, relptr, lnptr, nrel, nln, flags = struct.unpack_from('<IIIIIIHHI', d, off + 8)
        secs.append(dict(idx=i + 1, name=name, rawsz=rawsz, rawptr=rawptr,
                         relptr=relptr, nrel=nrel, flags=flags))
        off += 40
    syms = []
    i = 0
    while i < nsym:
        e = d[psym + i * 18:psym + i * 18 + 18]
        if e[0:4] == b'\0\0\0\0':
            nm = struct.unpack_from('<I', e, 4)[0]
            s = d[psym + nsym * 18 + nm:]
            name = s[:s.index(b'\0')].decode('latin1')
        else:
            name = e[:8].rstrip(b'\0').decode('latin1')
        val, secn, typ, cls, naux = struct.unpack_from('<IhHBB', e, 8)
        syms.append(dict(name=name, value=val, sec=secn, cls=cls, typ=typ, idx=i))
        i += 1 + naux
    return d, secs, syms


def relocs(d, sec):
    out = []
    for i in range(sec['nrel']):
        va, symidx, typ = struct.unpack_from('<IIH', d, sec['relptr'] + i * 10)
        out.append((va, symidx, typ))
    return out


def sxt(v, bits):
    m = 1 << (bits - 1)
    return (v ^ m) - m


def census(root):
    rows = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if not f.endswith('.obj'):
                continue
            p = os.path.join(dirpath, f)
            try:
                d, secs, syms = load(p)
            except Exception as e:
                print('SKIP', p, e, file=sys.stderr)
                continue
            byidx = {s['idx']: s for s in syms}
            for sec in secs:
                if not sec['nrel']:
                    continue
                # function-ish symbols in this section, sorted by value
                fns = sorted([s for s in syms
                              if s['sec'] == sec['idx'] and s['typ'] == 0x20],
                             key=lambda s: s['value'])
                for va, si, ty in relocs(d, sec):
                    if ty != REL14:
                        continue
                    t = byidx.get(si, {'name': '??', 'value': 0, 'sec': 0})
                    word = struct.unpack_from('>I', d, sec['rawptr'] + va)[0]
                    bd = sxt(word & 0xFFFC, 16)
                    aa = (word >> 1) & 1
                    encoded = (bd & 0xFFFFFFFF) if aa else (va + bd) & 0xFFFFFFFF
                    encl = None
                    for s in fns:
                        if s['value'] <= va:
                            encl = s
                        else:
                            break
                    rows.append(dict(
                        obj=os.path.relpath(p, root), sec=sec['name'], off=va,
                        word='%08x' % word,
                        target=t['name'], tval=t['value'], tsec=t['sec'],
                        same_section=(t['sec'] == sec['idx']),
                        encl=(encl or {}).get('name'), enclval=(encl or {}).get('value'),
                        intra_fn=(encl is not None and t['name'] == encl['name']),
                        encoded_dest=encoded,
                        encoded_in_encl=(encl is not None and encl['value'] <= encoded),
                    ))
    return rows


if __name__ == '__main__':
    rows = census(sys.argv[1])
    print(json.dumps(rows, indent=1))
    n = len(rows)
    intra = sum(1 for r in rows if r['intra_fn'])
    same = sum(1 for r in rows if r['same_section'])
    print('TOTAL REL14=%d  intra_fn=%d  same_section=%d  cross_section=%d'
          % (n, intra, same, n - same), file=sys.stderr)
