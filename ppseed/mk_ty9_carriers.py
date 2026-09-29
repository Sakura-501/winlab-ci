#!/usr/bin/env python3
"""Size-invariant carriers aimed at the OE-metadata leg of the OneNote find path.

The per-OE visitor `Traversal::__R_lambda_3_@?O@??$GetIsPageHitAndPageElementHits_Impl@...`
(0x180652560 in onmain 20430.20048) opens with

    if ( *(DWORD *)( *(QWORD *)(a2 + 40) + 4 ) == 393228 )      // 0x6000C
        pset = CPageElementOnMainGraph::UseMetadata()
        slot48 = pset->vtbl[48]        // IPropertySet::FGetProperty_Imp(const PropertyInfo&, void*)

so only an object whose jcid is 0x6000C has its metadata property pulled into the sink.
Scanning the local .one corpus with s2map shows exactly one such object:

    full.one (2,316 B)  jcid=0x6000C prtid=0x1C20 ty=9      <- a u32 array: [u32 count][count*4 bytes]
                        jcid=0x6000E prtid=0x1C22 ty=7 n=22 <- sibling class, binary value

`ty` is odd in both cases, which is the same bit the sink's gate reads (`type >> 26 & 1`).
This script enlarges the count dword (for ty 9/0xB/0xD) and, where present, a ty==7 length,
leaving the file byte length untouched.

Usage: mk_ty9_carriers.py <base.one> <out_dir> [prefix]
"""
import os
import struct
import sys

sys.path.insert(0, "/Users/nonoge/Desktop/src_all_in_one/findings/MSRC/M365-Insider/onenote-onestore-hunt-20260902")
from s2map import S2  # noqa: E402

BYTES_TIERS = (24, 64, 256, 4096)

base = sys.argv[1] if len(sys.argv) > 1 else "full.one"
outdir = sys.argv[2] if len(sys.argv) > 2 else "carriers_t9"
prefix = sys.argv[3] if len(sys.argv) > 3 else "t9"
os.makedirs(outdir, exist_ok=True)

s = S2(base)
sites = []
for r in s.decls:
    for pr in r.props:
        if pr.ty in (9, 0xB, 0xD, 7):
            try:
                v = struct.unpack_from("<I", s.d, pr.off)[0]
            except Exception:
                continue
            if pr.ty == 7:
                nbytes = v
            else:
                nbytes = 4 * v
            if 0 < nbytes <= 0x4000:
                sites.append((r.jcid, pr.pid, pr.ty, pr.off, v, nbytes))

seen, uniq = set(), []
for jcid, pid, ty, off, v, nbytes in sites:
    k = (jcid, pid, ty, off)
    if k in seen:
        continue
    seen.add(k)
    uniq.append((jcid, pid, ty, off, v, nbytes))

print("base=%s size=%d sites=%d" % (os.path.basename(base), len(s.d), len(uniq)))
made = 0
for idx, (jcid, pid, ty, off, v, nbytes) in enumerate(uniq):
    for target in BYTES_TIERS:
        if target <= nbytes:
            continue
        d = bytearray(s.d)
        newv = target if ty == 7 else (target // 4)
        struct.pack_into("<I", d, off, newv)
        assert len(d) == len(s.d)
        name = "%s_%03d_j%04x_p%04x_t%X_B%x.one" % (prefix, idx, jcid & 0xFFFF, pid & 0xFFFF, ty, target)
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(bytes(d))
        print("%s jcid=0x%04X prtid=0x%04X ty=%d off=0x%x val_old=%d bytes_old=%d bytes_new=%d unchanged=True"
              % (name, jcid, pid, ty, off, v, nbytes, target))
        made += 1
with open(os.path.join(outdir, "manifest.txt"), "w") as f:
    f.write("base=%s size=%d sites=%d files=%d\n" % (base, len(s.d), len(uniq), made))
print("wrote %d carriers to %s" % (made, outdir))
