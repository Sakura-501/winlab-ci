#!/usr/bin/env python3
"""Lookup symbol RVAs in an msfpdb tsv (image space, OMAP-applied) and emit a
cdb breakpoint command file. Usage: mkbp.py <mso.tsv> <ppcore.tsv> <out.txt>"""
import sys

WANT = {
    'mso': ['?CbOAFromHENHMETAFILE@@'],
    'ppcore': ['?FIsIconOnlyComment@@', '?EnumEmfExtractIcon@@',
               '?UpdateObjectCache@CtBase@@AEAAXPEAVTransaction@@_N1@Z',
               '?GetMetaPictStream@ExOleObj@@EEAA'],
}

def load(p):
    out = {}
    for line in open(p, encoding='utf-8', errors='replace'):
        q = line.rstrip('\n').split('\t')
        if len(q) >= 2 and q[0].strip():
            out.setdefault(q[1], q[0])
    return out

def main():
    mso_t, ppc_t, outp = sys.argv[1], sys.argv[2], sys.argv[3]
    lines = ['.echo ===ATTACHED===']
    found = {}
    for mod, tsv in (('mso', mso_t), ('ppcore', ppc_t)):
        syms = load(tsv)
        for pat in WANT[mod]:
            hit = None
            for name, rva in syms.items():
                if pat in name:
                    hit = (name, rva); break
            if hit:
                tag = pat.strip('?@').split('@@')[0][:30]
                lines.append(f'bp {mod}+0x{int(hit[1],16):x} ".echo ===HIT_{mod}_{tag}===; g"')
                found[f'{mod}:{pat}'] = hit
            else:
                lines.append(f'.echo MISSING_{mod}_{pat[:40]}')
    lines.append('sxe -c ".echo ===AV===; r; kvn 12; qd" av')
    lines.append('bl')
    lines.append('g')
    open(outp, 'w', newline='\n').write('\n'.join(lines) + '\n')
    for k, v in found.items():
        print(f'BP {k} -> {v[1]} {v[0][:70]}')

if __name__ == '__main__':
    main()
