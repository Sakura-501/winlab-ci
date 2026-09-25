#!/usr/bin/env python3
"""ppt_rec_mutate.py - record-header mutator for the PowerPoint 97-2003 binary `.ppt` container.

Why this shape: ppcore.dll is loaded the moment POWERPNT opens a .ppt (measured 2026-09-25 on
16.0.20430.20092 with ZoneId=3: ppcore.dll is in the process module list at the first poll), so the
record stream is handed to the parser before any user action. The stream is a tree of
    RecordHeader { WORD recVer:4 | recInstance:12 ; WORD recType ; DWORD recLen }
where recVer == 0xF marks a *container* (recLen = byte size of the child records) and any other value
marks an *atom* (recLen = payload size). A header whose declared length disagrees with the payload the
handler walks is the class of defect that turns into an out-of-bounds copy, so the mutations here are
addressed by record type and by nesting depth rather than by file offset.

The August 2026 pass (findings/MSRC/Office/ppt-mem-fuzz-20260815) drove 122 cases on build
20326.20072 with a 7-top-level-record seed and crash-only detection; this tool is meant to aim
mutations at a record type that the static pass names, on the current build, under an armed page heap.

    ppt_rec_mutate.py <seed.ppt> <outdir> [--types 4000,4001,...] [--depth 0,1,2] [--limit N]
"""
import argparse
import os
import struct
import sys

try:
    import olefile
except ImportError:
    sys.exit("needs olefile: python3 -m pip install olefile")

STREAM = "PowerPoint Document"
CONTAINER_VER = 0xF


def walk(buf, base=0, depth=0, out=None):
    """Yield (offset, recType, recVer, recInstance, recLen, depth) for every header in a record tree."""
    if out is None:
        out = []
    pos = base
    end = len(buf)
    while pos + 8 <= end:
        vi, rt, rl = struct.unpack_from("<HHI", buf, pos)
        ver = vi & 0xF
        inst = vi >> 4
        out.append((pos, rt, ver, inst, rl, depth))
        if ver == CONTAINER_VER and rl >= 8 and depth < 12:
            walk(buf, pos + 8, depth + 1, out) if False else None
            # recurse into the container body (its children live in [pos+8, pos+8+rl))
            sub = memoryview(buf)[pos + 8:pos + 8 + rl]
            walk(bytes(sub), 0, depth + 1, out) if False else None
            for row in walk(bytes(sub), 0, depth + 1, []):
                out.append((row[0] + pos + 8, row[1], row[2], row[3], row[4], row[5]))
        pos += 8 + (rl if ver != CONTAINER_VER else rl)
    return out


LEN_VALUES = {
    "zero": 0,
    "ffff": 0xFFFF,
    "maxi": 0x7FFFFFFF,
    "minus1": 0xFFFFFFFF,
    "plus8": None,      # relative: current + 8
    "plus1": None,
    "half": None,
}


def mutate(buf, hits, kinds, limit):
    """Return list of (name, mutated_bytes) applying each kind at each hit header."""
    outs = []
    for (off, rt, ver, inst, rl, depth) in hits:
        for kind in kinds:
            if kind in ("plus8", "plus1", "half"):
                if kind == "plus8":
                    new = rl + 8
                elif kind == "plus1":
                    new = rl + 1
                else:
                    new = rl // 2
            else:
                new = {"zero": 0, "ffff": 0xFFFF, "maxi": 0x7FFFFFFF, "minus1": 0xFFFFFFFF}[kind]
            if new == rl or new > 0xFFFFFFFF:
                continue
            b = bytearray(buf)
            struct.pack_into("<I", b, off + 4, new)
            outs.append(("rec%04x_d%d_%s_off%x_old%x" % (rt, depth, kind, off, rl), bytes(b)))
            if limit and len(outs) >= limit:
                return outs
        if ver == CONTAINER_VER:
            b = bytearray(buf)
            struct.pack_into("<H", b, off, (0x0001) | (rt & 0) | ((inst & 0xFFF) << 4))  # atom-ise (ver=1)
            outs.append(("rec%04x_d%d_atomize_off%x" % (rt, depth, off), bytes(b)))
            b2 = bytearray(buf)
            struct.pack_into("<H", b2, off, ((0xF) | ((inst & 0xFFF) << 4)))             # container-ise an atom
            outs.append(("rec%04x_d%d_containerize_off%x" % (rt, depth, off), bytes(b2)))
    return outs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("seed")
    ap.add_argument("outdir")
    ap.add_argument("--types", default="", help="comma list of decimal recType to aim at (empty = all)")
    ap.add_argument("--depth", default="", help="comma list of depths (empty = all)")
    ap.add_argument("--kinds", default="plus8,plus1,ffff,maxi,minus1,half,zero")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    ole = olefile.OleFileIO(a.seed)
    if not ole.exists(STREAM):
        sys.exit("seed has no %r stream (is it a PowerPoint 97-2003 .ppt?)" % STREAM)
    data = ole.openstream(STREAM).read()
    allh = walk(data)
    types = {int(t) for t in a.types.split(",") if t.strip()} if a.types else None
    depths = {int(d) for d in a.depth.split(",") if d.strip()} if a.depth else None
    hits = [h for h in allh
            if (types is None or h[1] in types) and (depths is None or h[5] in depths)]
    print("stream_bytes=%d headers=%d aimed=%d types=%s depths=%s"
          % (len(data), len(allh), len(hits), sorted(types or {h[1] for h in hits})[:12],
             sorted(depths or {h[5] for h in hits})))
    for h in hits[:20]:
        print("   off=0x%x type=%d ver=%X inst=%d len=%d depth=%d" % (h[0], h[1], h[2], h[3], h[4], h[5]))
    outs = mutate(data, hits, [k for k in a.kinds.split(",") if k], a.limit)
    print("variants=%d" % len(outs))

    os.makedirs(a.outdir, exist_ok=True)
    seed = open(a.seed, "rb").read()
    for name, body in outs:
        patched = bytearray(seed)
        # locate the original stream bytes inside the CFB image and replace in place (sector-aligned,
        # same length) so the directory/minifat stays valid
        idx = patched.find(data)
        if idx < 0:
            print("cannot locate stream in container, skipping", name)
            continue
        patched[idx:idx + len(data)] = body
        with open(os.path.join(a.outdir, "m_" + name[:70].replace("/", "_") + ".ppt"), "wb") as fh:
            fh.write(bytes(patched))
    print("written -> %s" % a.outdir)


if __name__ == "__main__":
    main()
