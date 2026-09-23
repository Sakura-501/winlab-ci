#!/usr/bin/env python3
"""Dense count/size sweep over MS-OXTNEF attributes for the tail-guard harness.

The earlier corpus (../olmapi32-tnef-20260922/tools/mk_tnef_corpus.py) disagrees two fields in a
handful of fixed offsets (-1, -2, -8, 8, 1024, 1<<20). A copy loop that overshoots only for certain
remainders - "copy 8 bytes at a time then write the tail with one wide store" overshoots only when
len%8 is small - is not caught by a handful of offsets. Here each axis is walked over a dense run of
values with the record otherwise *self-consistent* (declared lengths match the bytes present), so the
only thing varying is the count that the consumer allocates against and the tail it writes.

Record format consumed by crtfbench mode 11: "<len>\\n<bytes>\\n".
"""
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "tnefdense"
SIG = 0x223E9F78
ATT_PROPS, ATT_RECIPTABLE, ATT_MSGFIELD = 16, 18, 17
ATT_ATTACHATTR = 20
ATT_ATTACHDATA, ATT_OLE10NATIVE = 19, 2000
ATT_SUBJECT, ATT_BYTEBUF, ATT_MBCS = 0x8000 | 9, 14, 13
ATT_BEGINOBJ, ATT_ENDOBJ = 10001, 10002
PT_LONG, PT_STRING8 = 3, 30
PT_UNICODE, PT_BINARY, PT_MV_UNICODE, PT_MV_BINARY, PT_MV_LONG = 31, 253, 0x101F, 0x1100, 0x1003

DENSE = list(range(1, 161))
EDGE = [191, 192, 193, 255, 256, 257, 383, 384, 511, 512, 513, 767, 768,
        1023, 1024, 1025, 2047, 2048, 4095, 4096, 4097, 8191, 8192, 8193]


def checksum(attid, data):
    c = 0
    for w in (attid & 0xFFFF, (attid >> 16) & 0xFFFF):
        c = (c + w) & 0xFFFFFFFF
    for i in range(0, len(data) - 1, 2):
        c = (c + struct.unpack_from("<H", data, i)[0]) & 0xFFFFFFFF
    if len(data) & 1:
        c = (c + data[-1]) & 0xFFFFFFFF
    c = (c & 0xFFFF) + ((c >> 16) & 0xFFFF)
    return c & 0xFFFF


def attr(attid, data, bad_len=None, bad_trailer=None, bad_ck=False):
    ck = checksum(attid, data)
    if bad_ck:
        ck = (ck ^ 0x5A5A) & 0xFFFF
    cb = len(data) if bad_len is None else bad_len
    tr = len(data) if bad_trailer is None else bad_trailer
    return struct.pack("<IHH", cb & 0xFFFFFFFF, attid & 0xFFFF, ck) + data + struct.pack("<I", tr & 0xFFFFFFFF)


def level(obj_type=1, name=b"tnof"):
    return struct.pack("<IHH", SIG, obj_type, 0) + name[:4].ljust(4, b"\0")[:4]


def props(entries, c_count=None):
    out = struct.pack("<I", len(entries) if c_count is None else c_count)
    for pid, ptype, raw in entries:
        if ptype in (PT_UNICODE, PT_STRING8, PT_BINARY):
            out += struct.pack("<II", pid, ptype) + struct.pack("<I", len(raw)) + raw
        elif ptype in (PT_MV_UNICODE, PT_MV_BINARY, PT_MV_LONG):
            n, items = raw
            out += struct.pack("<II", pid, ptype) + struct.pack("<I", n)
            for it in items:
                if ptype == PT_MV_LONG:
                    out += struct.pack("<I", it)
                elif ptype == PT_MV_UNICODE:
                    out += struct.pack("<I", len(it) * 2) + it.encode("utf-16-le")
                else:
                    out += struct.pack("<I", len(it)) + it
        else:
            out += struct.pack("<II", pid, ptype) + raw
    return out


def tbl(cRecip, cNames, names, rows=b""):
    b = struct.pack("<II", cRecip, cNames)
    for i in range(min(cNames, len(names))):
        b += struct.pack("<I", len(names[i]) * 2) + names[i].encode("utf-16-le")
    return b + rows


recs = []


def add(name, blob):
    recs.append((name, blob))


sub = "subject-hello\0".encode("utf-16-le")
add("ok_flat", level(1) + attr(ATT_SUBJECT, sub)
    + attr(ATT_PROPS, props([(0x0C04, PT_UNICODE, sub)]))
    + attr(ATT_RECIPTABLE, tbl(1, 1, ["001e001f"]))
    + attr(ATT_OLE10NATIVE, struct.pack("<I", 10) + b"attach.bin\0\0" + struct.pack("<HHI", 1, 2, 4) + b"xxxx"))

# 1. N fixed-size (PT_LONG) properties, all bytes present
for n in DENSE + EDGE:
    add("pl%u" % n, level(1) + attr(ATT_PROPS, props([(0x1234, PT_LONG, struct.pack("<I", 7))] * n)))
# 2. N variable-size (PT_UNICODE, 1 char) properties: entry stride 14 bytes, so the running offset
#    cycles mod 4 and mod 8 - a tail store that assumes alignment overshoots at particular N only.
for n in DENSE:
    add("pu%u" % n, level(1) + attr(ATT_PROPS, props([(0x1234, PT_UNICODE, b"a\0")] * n)))
for n in DENSE:
    add("ps8_%u" % n, level(1) + attr(ATT_PROPS, props([(0x1234, PT_STRING8, b"a")] * n)))
# 3. multi-value properties, N elements of each kind
for n in DENSE + EDGE:
    add("mvl%u" % n, level(1) + attr(ATT_PROPS, props([(0x6720, PT_MV_LONG, (n, [3] * n))])))
for n in DENSE:
    add("mvu%u" % n, level(1) + attr(ATT_PROPS, props([(0x6720, PT_MV_UNICODE, (n, ["a"] * n))])))
for n in DENSE:
    add("mvb%u" % n, level(1) + attr(ATT_PROPS, props([(0x6721, PT_MV_BINARY, (n, [b"x"] * n))])))
for n in DENSE:
    add("mvu2_%u" % n, level(1) + attr(ATT_PROPS, props([(0x6720, PT_MV_UNICODE, (n, ["ab"] * n))])))
# 4. recipient / attachment tables: cNames == number of name entries present
for n in DENSE:
    add("tbR%u" % n, level(1) + attr(ATT_RECIPTABLE, tbl(n, n, ["3001001f"] * n)))
for n in DENSE:
    add("tbA%u" % n, level(1) + attr(ATT_ATTACHATTR, tbl(n, n, ["3701001f"] * n)))
for n in DENSE:
    add("tbM%u" % n, level(1) + attr(ATT_MSGFIELD, tbl(1, n, ["001e001f"] * n)))
# 5. string / binary attribute payloads, dense length (wide-char conversion, memcpy tails)
for L in DENSE + EDGE:
    add("uni%u" % L, level(1) + attr(ATT_SUBJECT, b"B" * L))
for L in DENSE:
    add("bb%u" % L, level(1) + attr(ATT_BYTEBUF, b"\x5a" * L))
for L in DENSE:
    add("mbcs%u" % L, level(1) + attr(ATT_MBCS, b"m" * L))
# 6. attAttachData: declared length == present bytes
for L in DENSE:
    add("fbd%u" % L, level(1) + attr(ATT_ATTACHDATA, struct.pack("<I", L) + b"f" * L))
# 7. OLE10Native: label/filename/path each length-prefixed, then flags/position/size + data.
#    Every length field is made to agree with the bytes, for a dense range of sizes.
for L in DENSE:
    lab = b"L" * L + b"\0"
    fn = b"F" * max(1, L // 3) + b"\0"
    fp = b"P" * max(1, L // 5) + b"\0"
    payload = b"D" * max(1, L // 7)
    body = struct.pack("<I", len(lab)) + lab + struct.pack("<I", len(fn)) + fn \
        + struct.pack("<I", len(fp)) + fp + struct.pack("<HHI", 1, 2, len(payload)) + payload
    add("ole%u" % L, level(1) + attr(ATT_OLE10NATIVE, body))
# 8. OLE10Native with the *total* field disagreeing by one over a dense base size
for L in DENSE:
    lab = b"L" * 8 + b"\0"
    payload = b"D" * L
    body = struct.pack("<I", len(lab)) + lab + struct.pack("<I", 1) + b"f\0" \
        + struct.pack("<I", 1) + b"p\0" + struct.pack("<HHI", 1, 2, len(payload)) + payload
    add("ole_t%u" % L, level(1) + attr(ATT_OLE10NATIVE, body))
    add("ole_m%u" % L, level(1) + attr(ATT_OLE10NATIVE,
        struct.pack("<I", len(lab)) + lab + struct.pack("<I", 1) + b"f\0"
        + struct.pack("<I", 1) + b"p\0" + struct.pack("<HHI", 1, 2, len(payload) + 1) + payload))
# 9. two disagreeing fields at once: declared attribute length short by 4 while the inner counts stay
for n in DENSE:
    add("pair%u" % n, level(1) + attr(ATT_PROPS, props([(0x6720, PT_MV_LONG, (n, [3] * n))]), bad_len=-4))

# 10. nesting with a dense count inside the object
for n in DENSE:
    add("in%u" % n, level(1) + attr(ATT_BEGINOBJ, struct.pack("<I", 1))
        + attr(ATT_PROPS, props([(0x1234, PT_LONG, struct.pack("<I", 7))] * n))
        + attr(ATT_ENDOBJ, struct.pack("<I", 1)))

with open(OUT, "wb") as f:
    for name, blob in recs:
        f.write(b"%d\n" % len(blob))
        f.write(blob)
        f.write(b"\n")
with open(OUT + ".names.txt", "w") as f:
    for i, (name, blob) in enumerate(recs):
        f.write("%d\t%s\t%d\n" % (i, name, len(blob)))
print("records=%d bytes=%d -> %s" % (len(recs), sum(len(b) for _, b in recs), OUT))
for n, b in recs[:3]:
    print("  %-14s %6d %s" % (n, len(b), b[:24].hex()))
