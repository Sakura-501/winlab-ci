#!/usr/bin/env python3
"""Runtime generators for EMF record-walk test carriers (no binary assets in repo).

gen_emf.py good.emf      -> record a genuine small EMF via GDI (Windows only)
gen_emf.py patch <in> <out>  -> neutralize the IconOnly comment data and enlarge
                                the last GDICOMMENT DataSize to a stress value
"""
import struct, sys

def record_emf(path):
    import ctypes
    from ctypes import wintypes
    gdi32 = ctypes.windll.gdi32
    user32 = ctypes.windll.user32
    hdc = user32.GetDC(0)
    class RECT(ctypes.Structure):
        _fields_ = [("l", wintypes.LONG), ("t", wintypes.LONG), ("r", wintypes.LONG), ("b", wintypes.LONG)]
    rc = RECT(0, 0, 200, 200)
    # CreateEnhMetaFileA(hdc, None, byref(rc), None)
    gdi32.CreateEnhMetaFileA.restype = ctypes.c_void_p
    mdc = gdi32.CreateEnhMetaFileA(hdc, None, ctypes.byref(rc), None)
    gdi32.Rectangle(ctypes.c_void_p(mdc), 10, 10, 190, 190)
    gdi32.Ellipse(ctypes.c_void_p(mdc), 20, 20, 180, 180)
    gdi32.TextOutA(ctypes.c_void_p(mdc), 30, 90, b"EMF", 3)
    hemf = gdi32.CloseEnhMetaFile(ctypes.c_void_p(mdc))
    n = gdi32.GetEnhMetaFileBits(ctypes.c_void_p(hemf), 0, None)
    buf = ctypes.create_string_buffer(n)
    gdi32.GetEnhMetaFileBits(ctypes.c_void_p(hemf), n, buf)
    open(path, 'wb').write(buf.raw[:n])
    gdi32.DeleteEnhMetaFile(ctypes.c_void_p(hemf))
    user32.ReleaseDC(0, hdc)
    print(f"recorded {path} {n} bytes")

def walk(d):
    it, ns = struct.unpack_from('<II', d, 0)
    off = ns; recs = []
    while off + 8 <= len(d):
        rt, rl = struct.unpack_from('<II', d, off)
        if rl < 8 or off + rl > len(d): break
        recs.append((off, rt, rl))
        off += rl
    return recs, off

def patch(path_in, path_out, stress=0x7FFF0000):
    d = bytearray(open(path_in, 'rb').read())
    recs, end = walk(d)
    comments = [r for r in recs if r[1] == 0x46]
    for (o, rt, rl) in comments:
        dsz = struct.unpack_from('<I', d, o + 8)[0]
        n = min(dsz, rl - 12)
        # neutralize any marker text inside comment data
        d[o + 12:o + 12 + n] = b'\x00' * n
    if comments:
        o = comments[-1][0]
        struct.pack_into('<I', d, o + 8, stress)
    open(path_out, 'wb').write(bytes(d))
    print(f"patched {path_out} comments={len(comments)} lastDataSize={hex(stress)}")

if __name__ == '__main__':
    if sys.argv[1] == 'good':
        record_emf(sys.argv[2])
    elif sys.argv[1] == 'patch':
        patch(sys.argv[2], sys.argv[3])
