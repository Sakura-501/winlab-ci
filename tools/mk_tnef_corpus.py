#!/usr/bin/env python3
"""MS-OXTNEF (winmail.dat) corpus for the in-process OLMAPI32 TNEF driver.

TNEF framing (MS-OXTNEF 2.1):
    level header : signature(4)=0x223E9F78 | type(2) | name(4 OEM chars)
    attribute    : cbData(4) | attid(2) | checksum(2) | data[cbData] | cbDataCopy(4)

Every record here is emitted through one of the mutation dimensions below, all of which
disagree with something else in the same record: the declared length, the trailer copy,
the checksum, the element counts that the typed attributes carry (cValues for PT_MV_*,
cNames/cRecip for the table attributes), and the "root object" nesting level.
Record format consumed by crtfbench mode 11: "<len>\\n<bytes>\\n".
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "tnefcorpus"
SIG = 0x223E9F78

ATT_OWNER, ATT_SENDER, ATT_EXECTIME, ATT_FILETYPE, ATT_FILENAME = 1, 2, 3, 4, 5
ATT_FILEBODY, ATT_INT32, ATT_STRING, ATT_JUNK, ATT_DATE = 6, 8, 9, 10, 11
ATT_INT16, ATT_MBCS, ATT_BYTEBUF, ATT_ATTRTNF, ATT_PROPS = 12, 13, 14, 15, 16
ATT_MSGFIELD, ATT_RECIPTABLE, ATT_ATTACHDATA, ATT_ATTACHATTR, ATT_RECIPIATTR = 17, 18, 19, 20, 21
ATT_AUX, ATT_OLE10NATIVE, ATT_STARTNAME, ATT_ENDNAME = 22, 2000, 2001, 2002
ATT_NEXTOBJ, ATT_BEGINOBJ, ATT_ENDOBJ = 10000, 10001, 10002
ATT_SUBJECT = 0x8004  # attSubject: class bit 0x8000 | id 4 (MS-OXTNEF 2.4)

PT_SHORT, PT_LONG, PT_DOUBLE, PT_CURRENCY = 2, 3, 5, 8
PT_APPTIME, PT_STRING8, PT_BINARY, PT_UNICODE = 10, 30, 253, 31
PT_MV_UNICODE = 0x101F
PT_MV_BINARY = 0x1100
PT_MV_LONG = 0x1003


def checksum(attid, data):
    """MS-OXTNEF 2.2.2: running sum of the 16-bit words of the attribute id and data."""
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
    return struct.pack("<IHH", cb, attid & 0xFFFF, ck) + data + struct.pack("<I", tr & 0xFFFFFFFF)


def level(obj_type=1, name=b"tnof"):
    return struct.pack("<IHH", SIG, obj_type, 0) + name[:4].ljust(4, b"\0")[:4]


def props_blob(entries, c_count=None):
    """attprops: cValues(4) then per-property {id(4) type(4) [len(4)] value}."""
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


def recip_table(cRecip, cNames, names, rows=b"", pad_limit=8):
    """attrecip / attattach / attmsgfield share: cValues(4) cNames(4) rgNames[2](4 each).

    The declared cNames/cRecip is what the consumer trusts, so the interesting shapes are
    declared >> present: emit at most pad_limit real entries and leave the rest undeclared-by-bytes."""
    n = min(cNames, len(names) + pad_limit)
    b = struct.pack("<II", cRecip, cNames)
    for i in range(n):
        nm = names[i] if i < len(names) else "fill"
        b += struct.pack("<I", len(nm) * 2) + nm.encode("utf-16-le")
    return b + rows


recs = []


def add(name, blob):
    recs.append((name, blob))


# ---- well-formed baseline controls (a wave that opens none of these is void) ----
sub = "subject-hello\0".encode("utf-16-le")
props_ok = props_blob([(0x0C04, PT_UNICODE, sub), (0x0037, PT_UNICODE, "body text\0".encode("utf-16-le"))])
tnef_ok = level(1) + attr(0x8000 | ATT_SUBJECT, sub) + attr(ATT_PROPS, props_ok) \
    + attr(ATT_MSGFIELD, recip_table(1, 2, ["001e001f", "1009001f"])) \
    + attr(ATT_RECIPTABLE, recip_table(1, 1, ["001e001f"])) \
    + attr(0x8000 | ATT_ATTACHDATA, struct.pack("<I", 4) + b"data") \
    + attr(ATT_OLE10NATIVE, struct.pack("<I", 10) + b"attach.bin\0\0" + struct.pack("<HHI", 1, 2, 4) + b"xxxx")
add("ok_flat", tnef_ok)
add("ok_rooted", level(2) + attr(ATT_BEGINOBJ, struct.pack("<I", 0)) + attr(0x8000 | ATT_SUBJECT, sub)
    + attr(ATT_ENDOBJ, struct.pack("<I", 0)) + level(1) + attr(ATT_ATTRTNF, struct.pack("<I", 1)))

# ---- declared length vs real data (each mismatch direction, both fields) ----
for delta in (-1, -2, -8, 8, 1024, 1 << 20, 0x7FFFFFFF, -1 << 31):
    good = attr(ATT_PROPS, props_ok)
    body = struct.pack("<IHH", (len(props_ok) + delta) & 0xFFFFFFFF, ATT_PROPS, checksum(ATT_PROPS, props_ok))
    add("len_props%+d" % delta, level(1) + body + props_ok + struct.pack("<I", len(props_ok)))
    body = struct.pack("<IHH", len(props_ok), ATT_PROPS, checksum(ATT_PROPS, props_ok))
    add("trailer%+d" % delta, level(1) + body + props_ok + struct.pack("<I", (len(props_ok) + delta) & 0xFFFFFFFF))
add("len_max", level(1) + struct.pack("<IHH", 0xFFFFFFFF, ATT_PROPS, checksum(ATT_PROPS, props_ok))
    + props_ok + struct.pack("<I", 0xFFFFFFFF))
add("trailer_max", level(1) + struct.pack("<IHH", len(props_ok), ATT_PROPS, checksum(ATT_PROPS, props_ok))
    + props_ok + struct.pack("<I", 0xFFFFFFFF))

# ---- checksum failures (does the parser trust the record anyway?) ----
for k in range(6):
    add("ck_bad%d" % k, level(1) + attr(ATT_PROPS, props_ok, bad_ck=True))
add("ck_bad_then_ok", level(1) + attr(ATT_PROPS, props_ok, bad_ck=True) + attr(ATT_PROPS, props_ok))

# ---- cValues of the property array vs the bytes actually present ----
for n in (0, 1, 2, 3, 16, 255, 4096, 1 << 20, 0x7FFFFFFF):
    add("props_count%u" % n, level(1) + attr(ATT_PROPS, props_blob([(0x0C04, PT_UNICODE, sub)], c_count=n)))
for n in (2, 8, 64, 1024):
    add("props_c%u_mv" % n, level(1) + attr(ATT_PROPS, props_blob(
        [(0x0C04, PT_UNICODE, sub), (0x6720, PT_MV_LONG, (n, [7] * n))])))

# ---- multi-value properties: cValues vs element bytes ----
for n in (0, 1, 4, 63, 64, 4096, 1 << 24):
    items = ["v%03d" % i for i in range(min(n, 4096))]
    add("mv_uni%u" % n, level(1) + attr(ATT_PROPS, props_blob(
        [(0x6720, PT_MV_UNICODE, (n, items))])))
for n in (1, 4, 100, 1 << 20):
    add("mv_bin%u" % n, level(1) + attr(ATT_PROPS, props_blob(
        [(0x6721, PT_MV_BINARY, (n, [b"B" * 4 for _ in range(min(n, 100))]))])))

# ---- recipient/attachment tables: cRecip / cNames vs row bytes ----
for cr in (0, 1, 2, 64, 4096, 1 << 20):
    for cn in (0, 1, 2, 8, 1000):
        add("tbl_r%u_n%u" % (cr, cn), level(1) + attr(ATT_RECIPTABLE, recip_table(cr, cn, ["001e001f", "1009001f"])))
add("msgfield_names_big", level(1) + attr(ATT_MSGFIELD, recip_table(1, 0x7FFFFFF, ["a"])))
add("attach_attrs_zero", level(1) + attr(ATT_ATTACHATTR, struct.pack("<II", 0, 0xFFFFFFFF)))
add("recip_attrs_neg", level(1) + attr(ATT_RECIPIATTR, struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)))

# ---- string/binary attributes without terminators, and oversized ----
for cb in (0, 1, 2, 3, 255, 256, 65535, 65536, 1 << 20):
    add("str_noend%u" % cb, level(1) + attr(0x8000 | ATT_SUBJECT, b"A" * cb))
    add("uni_odd%u" % (cb | 1), level(1) + attr(0x8000 | ATT_SUBJECT, b"A" * (cb | 1)))
for cb in (0, 1, 4, 4096, 1 << 20):
    add("bytebuf%u" % cb, level(1) + attr(ATT_BYTEBUF, b"\x00" * cb))
    add("mbcs%u" % cb, level(1) + attr(ATT_MBCS, b"x" * cb))
add("ole10_declared_big", level(1) + attr(ATT_OLE10NATIVE,
    struct.pack("<I", 0x7FFFFFFF) + b"name.bin\0\0" + struct.pack("<HHI", 1, 2, 4) + b"tiny"))
add("ole10_declared_small", level(1) + attr(ATT_OLE10NATIVE,
    struct.pack("<I", 1) + b"name.bin\0\0" + struct.pack("<HHI", 1, 2, 4) + b"tiny"))
add("filebody_huge", level(1) + attr(ATT_ATTACHDATA, struct.pack("<I", 0x7FFFFFFF) + b"z" * 64))

# ---- nesting / object-level confusion ----
add("nested_level_hdr", level(1) + attr(ATT_FILEBODY, level(2) + attr(ATT_PROPS, props_ok)))
add("double_root", level(2) + level(2) + attr(0x8000 | ATT_SUBJECT, sub))
add("begin_no_end", level(1) + attr(ATT_BEGINOBJ, struct.pack("<I", 0)) + attr(0x8000 | ATT_SUBJECT, sub))
add("end_no_begin", level(1) + attr(ATT_ENDOBJ, struct.pack("<I", 0)) + attr(0x8000 | ATT_SUBJECT, sub))
add("objid_mismatch", level(1) + attr(ATT_BEGINOBJ, struct.pack("<I", 7))
    + attr(ATT_ENDOBJ, struct.pack("<I", 9)) + attr(0x8000 | ATT_SUBJECT, sub))
add("nextobj", level(1) + attr(ATT_NEXTOBJ, b"\x01" * 8) + attr(0x8000 | ATT_SUBJECT, sub))
add("bad_signature", struct.pack("<IHH", 0xDEADBEEF, 1, 0) + b"tnof" + attr(0x8000 | ATT_SUBJECT, sub))
add("truncated_half", tnef_ok[: len(tnef_ok) // 2])
add("truncated_1", tnef_ok[:1])
add("empty", b"")
add("junk_lead", b"\xff" * 8 + tnef_ok)
add("attid_unknown", level(1) + attr(0x7FFF, b"junkjunk"))
add("attid_huge", level(1) + attr(0xFFFF, b"junkjunk"))


# --- nested objects: props inside attBeginObject/attEndObject and inside the
# --- attAttachAttributes / attRecipAttributes sub-blocks (how real winmail.dat
# --- carries per-attachment properties; the flat corpus above only exercises top level)
inner = attr(ATT_PROPS, props_blob([(0x0C04, PT_UNICODE, sub), (0x6720, PT_MV_UNICODE, (4, ["a", "bb", "ccc", "dddd"]))]))
big_inner = attr(ATT_PROPS, props_blob([(0x0C04, PT_UNICODE, sub)], c_count=99))
for depth in (1, 2, 3):
    blob = b""
    for _ in range(depth):
        blob += attr(ATT_BEGINOBJ, struct.pack("<I", 1)) + attr(0x8000 | ATT_SUBJECT, sub)
    blob += inner
    for _ in range(depth):
        blob += attr(ATT_ENDOBJ, struct.pack("<I", 1))
    add("nest_d%u" % depth, level(1) + attr(0x8000 | ATT_SUBJECT, sub) + blob)
add("nest_unclosed", level(1) + attr(ATT_BEGINOBJ, struct.pack("<I", 3)) + inner)
add("nest_extra_close", level(1) + attr(ATT_ENDOBJ, struct.pack("<I", 0)) + inner)
for aid in (ATT_ATTACHATTR, ATT_RECIPIATTR):
    add("sub_%u_ok" % aid, level(1) + attr(aid, recip_table(1, 1, ["3001001f"])) + inner)
    add("sub_%u_count_hi" % aid, level(1) + attr(aid, recip_table(0x7FFFFFFF, 0x7FFFFFFF, ["3001001f"])) + inner)
    add("sub_%u_zero" % aid, level(1) + attr(aid, recip_table(0, 0, [])) + inner)
add("attach_then_props_big", level(1) + attr(ATT_ATTACHATTR, recip_table(1, 1, ["3701001f"]))
    + attr(ATT_ATTACHDATA, struct.pack("<I", 8) + b"12345678") + big_inner)
add("mv_in_object_mismatch", level(1) + attr(ATT_BEGINOBJ, struct.pack("<I", 1))
    + attr(ATT_PROPS, props_blob([(0x6720, PT_MV_UNICODE, (1000, ["x", "yy"]))]))
    + attr(ATT_ENDOBJ, struct.pack("<I", 1)))
add("ole10_in_object", level(1) + attr(ATT_BEGINOBJ, struct.pack("<I", 1))
    + attr(ATT_OLE10NATIVE, struct.pack("<I", 300) + b"n.bin\0\0" + struct.pack("<HHI", 1, 2, 4) + b"y" * 8)
    + attr(ATT_ENDOBJ, struct.pack("<I", 1)))

os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "attr.txt"), "wb") as f:
    for name, blob in recs:
        f.write(b"%d\n" % len(blob))
        f.write(blob)
        f.write(b"\n")
with open(os.path.join(OUT, "attr_names.txt"), "w") as f:
    for i, (name, blob) in enumerate(recs):
        f.write("%d\t%s\t%d\n" % (i, name, len(blob)))
print("records=%d bytes=%d -> %s/attr.txt" % (len(recs), sum(len(b) for _, b in recs), OUT))
for n, b in recs[:3]:
    print("  %-18s %6d %s" % (n, len(b), b[:28].hex()))
