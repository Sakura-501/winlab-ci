#!/usr/bin/env python3
"""Direct-call xrefs for an x64 PE, computed from E8 rel32 (and FF 15 IAT) without any symbols.
Used to triage byte-scanned sites: a site with hundreds of callers is a generic allocator, one with
a handful can be read caller by caller."""
import struct, sys
path, targets = sys.argv[1], [int(a, 16) for a in sys.argv[2:]]
b = open(path, "rb").read()
pe = struct.unpack_from("<I", b, 0x3C)[0]
nsec = struct.unpack_from("<H", b, pe + 6)[0]
optsz = struct.unpack_from("<H", b, pe + 20)[0]
so = pe + 24 + optsz
secs = []
for i in range(nsec):
    e = so + i * 40
    secs.append(dict(name=b[e:e+8].rstrip(b"\0").decode("latin1"),
                     vs=struct.unpack_from("<I", b, e + 8)[0], va=struct.unpack_from("<I", b, e + 12)[0],
                     rawsz=struct.unpack_from("<I", b, e + 16)[0], raw=struct.unpack_from("<I", b, e + 20)[0],
                     ch=struct.unpack_from("<I", b, e + 36)[0]))
text = [s for s in secs if (s["ch"] & 0x20000000) and not (s["ch"] & 0x80000000)]
blob = [(s, b[s["raw"]:s["raw"] + s["rawsz"]]) for s in text]
pf = [s for s in secs if s["name"] == ".pdata"]
funcs = []
if pf:
    s0 = pf[0]; tbl = b[s0["raw"]:s0["raw"] + s0["rawsz"]]
    for i in range(0, len(tbl) - 11, 12):
        a, e = struct.unpack_from("<II", tbl, i)
        if a and e > a: funcs.append((a, e))
funcs.sort()
def fn_of(rva):
    lo, hi = 0, len(funcs) - 1
    while lo <= hi:
        m = (lo + hi) // 2; a, e = funcs[m]
        if rva < a: hi = m - 1
        elif rva >= e: lo = m + 1
        else: return (a, e)
    return None
for t in targets:
    hits = []
    for s, blk in blob:
        for i in range(len(blk) - 5):
            if blk[i] != 0xE8: continue
            rel = struct.unpack_from("<i", blk, i + 1)[0]
            if s["va"] + i + 5 + rel == t:
                hits.append(s["va"] + i)
    fs = sorted({fn_of(h)[0] for h in hits if fn_of(h)})
    print("target 0x%X  direct_calls=%d  distinct_caller_functions=%d" % (t, len(hits), len(fs)))
    for f in fs[:24]:
        print("     caller_fn=0x%X size=%d" % (f, fn_of(f)[1] - f))
