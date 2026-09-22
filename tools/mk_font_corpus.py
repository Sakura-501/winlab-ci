#!/usr/bin/env python3
"""Embedded-font .docx corpus: sfnt directory/table mutations inside a real package.

Word parses a document's embedded fonts at open (word/fonts/fontN.odttf, declared by
word/fontTable.xml + its relationships). The sfnt header's numTables, each directory
entry's (tag, offset, length), and the per-table counts (cmap segCount/nGroups,
head.indexToLocFormat, name count, maxp numGlyphs, hhea numberOfHMetrics) are all
"declared count" values whose consumers index buffers sized by the file, so each is
swept against the others from a known-valid base font.

usage: mk_font_corpus.py <outdir> [basefont.ttf]
"""
import io
import os
import random
import struct
import sys
import zipfile

OUT = sys.argv[1]
BASE = sys.argv[2] if len(sys.argv) > 2 else None
rng = random.Random(20260922)

CANDIDATES = [
    r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\times.ttf", r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\calibri.ttf", r"C:\Windows\Fonts\consola.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf", "/System/Library/Fonts/Helvetica.ttc",
    "/Library/Fonts/Arial.ttf",
]


def load_base():
    if BASE and os.path.exists(BASE):
        return open(BASE, 'rb').read()
    for c in CANDIDATES:
        if os.path.exists(c):
            try:
                d = open(c, 'rb').read()
            except OSError:
                continue
            if d[:4] in (b'\x00\x01\x00\x00', b'OTTO', b'true', b'ttcf'):
                if d[:4] == b'ttcf':          # unpack first face of a collection
                    n = struct.unpack_from('>I', d, 8)[0]
                    off = struct.unpack_from('>I', d, 12 + 4 * min(n - 1, 0))[0]
                    d = d[off:]
                if d[:4] != b'ttcf':
                    return d
    return None


def parse_sfnt(d):
    tag, version, num, sr, es, rs = struct.unpack_from('>4sIHhhh', d, 0) if False else (None,) * 6
    ver = d[:4]
    num = struct.unpack_from('>H', d, 4)[0]
    entries = []
    for i in range(num):
        o = 12 + 16 * i
        t = d[o:o + 4]
        cs, off, ln = struct.unpack_from('>III', d, o + 4)
        entries.append([t, cs, off, ln])
    return ver, num, sr_es_rs_placeholder(d), entries


def sr_es_rs_placeholder(d):
    return struct.unpack_from('>HHH', d, 6)


def rebuild(d, entries, num=None, header=None):
    """rebuild a font whose tables are placed contiguously in file order"""
    ver = d[:4]
    n = len(entries) if num is None else num
    ds = 16
    esz = max(1, int(ds ** 0.5)) if False else 1
    # searchRange/entrySelector/rangeShift per spec
    es = 0
    t = n
    while t > 1:
        t //= 2
        es += 1
    sr = (2 ** es) * 16
    out = bytearray()
    out += ver
    out += struct.pack('>Hhhh', n, sr, es, n * 16 - sr)
    body = bytearray()
    dir_off = 12 + 16 * n
    pos = dir_off + len(body)
    placed = []
    for e in entries:
        tag, cs, off, ln = e
        blob = d[off:off + ln]
        pad = (4 - len(blob) % 4) % 4
        placed.append([tag, cs, dir_off + len(body), ln])
        body += blob + b'\x00' * pad
    out += b''.join(struct.pack('>4sIII', p[0], p[1], p[2], p[3]) for p in placed)
    out += body
    return bytes(out)


def mutate_dir(d, kind, val):
    ver, n, hdr, entries = parse_sfnt(d)
    e = [list(x) for x in entries]
    if kind == 'numtables_gt':
        return _hdr_only(d, min(0xFFFF, n + val), keep=n)
    if kind == 'numtables_lt':
        return _hdr_only(d, max(0, n - val), keep=n)
    if kind == 'numtables_zero':
        return _hdr_only(d, 0, keep=n)
    if kind == 'numtables_max':
        return _hdr_only(d, 0xFFFF, keep=n)
    if kind == 'drop_table':
        idx = val % max(1, len(e))
        del e[idx]
        return rebuild(d, e)
    if kind == 'dup_table':
        idx = val % max(1, len(e))
        e.insert(idx, list(e[idx]))
        return rebuild(d, e)
    if kind == 'len_beyond_eof':
        e[val % len(e)][3] = 0xFFFFFFFF
        return _entries_only(d, e)
    if kind == 'len_zero':
        e[val % len(e)][3] = 0
        return _entries_only(d, e)
    if kind == 'offset_huge':
        e[val % len(e)][2] = 0xFFFFFFF0
        return _entries_only(d, e)
    if kind == 'offset_before_dir':
        e[val % len(e)][2] = 12
        return _entries_only(d, e)
    if kind == 'offset_unaligned':
        e[val % len(e)][2] = e[val % len(e)][2] + 1
        return _entries_only(d, e)
    if kind == 'overlap_pairs':
        for i in range(1, len(e)):
            e[i][2] = e[i - 1][2]
        return _entries_only(d, e)
    if kind == 'bad_tag':
        e[val % len(e)][0] = b'\x00\x01\x02\x03'
        return _entries_only(d, e)
    if kind == 'checksum_garbage':
        for x in e:
            x[1] = rng.randrange(1 << 32)
        return _entries_only(d, e)
    return None


def _entries_only(d, entries):
    """keep original table bytes/positions, rewrite only the directory"""
    out = bytearray(d)
    n = len(entries)
    struct.pack_into('>H', out, 4, n)
    for i, (tag, cs, off, ln) in enumerate(entries):
        o = 12 + 16 * i
        if o + 16 > len(out):
            break
        out[o:o + 4] = tag
        struct.pack_into('>III', out, o + 4, cs, off, ln)
    return bytes(out)


def _hdr_only(d, newnum, keep):
    out = bytearray(d[:12 + 16 * max(keep, newnum)] )
    struct.pack_into('>H', out, 4, newnum)
    if len(out) < 12 + 16 * newnum:
        out += b'\x00' * (12 + 16 * newnum - len(out))
    return bytes(out)


TABLE_PATCHES = [
    ('head', 50, 'h', [0, 1, 2, -1, -2, 0x7FFF, -0x8000]),          # indexToLocFormat
    ('maxp', 4, 'H', [0, 1, 2, 0xFFFF, 0x8000, 0x0100]),            # numGlyphs
    ('hhea', 34, 'H', [0, 1, 2, 0xFFFF, 0x8000]),                   # numberOfHMetrics
    ('name', 2, 'H', [0, 1, 2, 0xFFFF, 0x0100]),                    # nameRecordCount
    ('name', 6, 'H', [0, 0xFFFF, 0x4000]),                          # stringOffset
    ('OS/2', 0, 'H', [0, 1, 2, 3, 4, 5, 0xFFFF]),                   # version
    ('OS/2', 66, 'h', [0, -1, 0x7FFF, -0x8000]),                    # sTypoAscender
    ('post', 32, 'I', [0, 1, 0xFFFFFFFF, 0x40000000]),              # numberOfGlyphs
    ('hmtx', 0, 'I', [0, 1, 0xFFFFFFFF]),                           # advanceWidthArray bound
    ('cmap', 2, 'H', [0, 1, 2, 0xFFFF, 0x0100]),                    # numTables (subtable records)
]


def patch_table(d, tag, off, fmt, vals):
    ver, n, hdr, entries = parse_sfnt(d)
    for t, cs, o, ln in entries:
        if t.rstrip(b'\x00') == tag and o + off + struct.calcsize(fmt) <= o + ln:
            out = bytearray(d)
            for v in vals:
                struct.pack_into(fmt, out, o + off, v)
                break
            return bytes(out)
    return None


def obfuscate(b):
    key = bytes([0xB2, 0x34, 0xE1, 0x15, 0x05, 0xE1, 0x19, 0x7F, 0x84, 0x29, 0x01, 0xFC,
                 0xB9, 0x03, 0x32, 0x26, 0xA3, 0x0C, 0x41, 0x9A, 0x37, 0x2C, 0x01, 0x0F,
                 0x03, 0x01, 0x15, 0x35, 0xE6, 0x2A, 0x0E, 0xA3])
    b = bytearray(b)
    for i in range(min(32, len(b))):
        b[i] ^= key[i]
    return bytes(b)


def _patch_cmap(d, which, delta):
    """format 4: segCount / length / searchRange decoupled from the array;
       subtable record: offset+length beyond the table"""
    ver, n, hdr, entries = parse_sfnt(d)
    for t, cs, o, ln in entries:
        if t.rstrip(b'\x00') != b'cmap':
            continue
        m = bytearray(d)
        nsub = struct.unpack_from('>H', m, o + 2)[0]
        for i in range(nsub):
            ro = o + 4 + 8 * i
            if ro + 8 > o + ln:
                break
            plat, enc, soff = struct.unpack_from('>HHI', m, ro)
            so = o + soff
            if so + 4 > len(m):
                continue
            fmt = struct.unpack_from('>H', m, so)[0]
            if which == 'subtable':
                struct.pack_into('>I', m, ro + 4, (ln - 4) & 0xFFFFFFFF)   # subtable offset beyond table
                return bytes(m)
            if fmt == 4 and which in ('f4', 'f4len'):
                seg = struct.unpack_from('>H', m, so + 6)[0]
                if which == 'f4':
                    struct.pack_into('>H', m, so + 6, min(0xFFFF, seg + delta))
                    struct.pack_into('>H', m, so + 10, min(0xFFFF, max(0, (seg + delta) // 2) * 2))
                else:
                    struct.pack_into('>H', m, so + 8, min(0xFFFF, struct.unpack_from('>H', m, so + 8)[0] + delta))
                return bytes(m)
            if fmt == 12 and which == 'f4':
                ng = struct.unpack_from('>I', m, so + 12)[0]
                struct.pack_into('>I', m, so + 12, min(0xFFFFFFFF, ng + delta))
                struct.pack_into('>I', m, so + 8, min(0xFFFFFFFF, (ng + delta) * 12 + 16))
                return bytes(m)
    return None


def docx(font_bytes, rid='rIdF', embed=True):
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Default Extension="odttf" ContentType="application/vnd.openxmlformats-officedocument.obfuscatedFont"/>'
          '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
          '<Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/>'
          '</Types>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>')
    wrels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/>'
             '</Relationships>')
    # the embedded-font relationship hangs off fontTable.xml, not document.xml.rels,
    # and its type is .../relationships/font (verified against a Word-produced package)
    ftrels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              + ('<Relationship Id="%s" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/font" Target="fonts/font1.odttf"/>' % rid if embed else '')
              + '</Relationships>')
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
           'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
           '<w:body><w:p><w:pPr><w:rPr><w:rFonts w:ascii="ProbeFont" w:hAnsi="ProbeFont"/></w:rPr></w:pPr>'
           '<w:r><w:rPr><w:rFonts w:ascii="ProbeFont" w:hAnsi="ProbeFont"/></w:rPr><w:t>hello</w:t></w:r></w:p>'
           '</w:body></w:document>')
    fnt = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:fonts xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
           'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
           'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:font w:name="ProbeFont">'
           '<w:panose1 w:val="020B0604020202020204"/>'
           '<w:charset w:val="00"/><w:family w:val="auto"/><w:pitch w:val="variable"/>'
           '<w:sig w:usb0="E0002AFF" w:usb1="C0007841" w:usb2="00000009" w:usb3="00000000" '
           'w:csb0="000001FF" w:csb1="00000000"/>'
           + ('<w:embedRegular r:id="%s" w:fontKey="{00000000-0000-0000-0000-000000000001}"/>' % rid if embed else '')
           + '</w:font></w:fonts>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', ct)
        z.writestr('_rels/.rels', rels)
        z.writestr('word/_rels/document.xml.rels', wrels)
        z.writestr('word/document.xml', doc)
        z.writestr('word/fontTable.xml', fnt)
        if embed:
            z.writestr('word/_rels/fontTable.xml.rels', ftrels)
            z.writestr('word/fonts/font1.odttf', obfuscate(font_bytes))
    return buf.getvalue()


def main():
    base = load_base()
    if not base:
        print('no base font found; pass a ttf path')
        return
    print('base font %d bytes, numTables=%d' % (len(base), struct.unpack_from('>H', base, 4)[0]))
    os.makedirs(OUT, exist_ok=True)
    made = 0
    kinds = ['numtables_gt', 'numtables_lt', 'numtables_zero', 'numtables_max', 'drop_table',
             'dup_table', 'len_beyond_eof', 'len_zero', 'offset_huge', 'offset_before_dir',
             'offset_unaligned', 'overlap_pairs', 'bad_tag', 'checksum_garbage']
    for k in kinds:
        for v in (0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987):
            m = mutate_dir(base, k, v)
            if not m:
                continue
            open(os.path.join(OUT, 'f_%s_%04d.docx' % (k, v)), 'wb').write(docx(m))
            made += 1
    for tag, off, fmt, vals in TABLE_PATCHES:
        for v in vals:
            m = patch_table(base, tag.encode(), off, fmt, [v])
            if m:
                open(os.path.join(OUT, 't_%s_%s.docx' % (tag.replace('/',''), str(v).replace('-','m'))), 'wb').write(docx(m))
                made += 1
    # cmap format-4 / format-12 count-vs-length decoupling (the classic font-engine family)
    for delta in (0, 1, 2, 8, 64, 512, 4096, 0x7FFF):
        for which in ('f4', 'f4len', 'subtable'):
            m = _patch_cmap(base, which, delta)
            if m:
                open(os.path.join(OUT, 'cm_%s_%05d.docx' % (which, delta)), 'wb').write(docx(m))
                made += 1
    # truncated / oversized / empty embedded font
    for name, blob in [('trunc_quarter', base[:len(base) // 4]), ('trunc_hdr', base[:12]),
                       ('empty', b''), ('just_hdr', base[:16 + 16 * 2]),
                       ('huge_pad', base + b'\x00' * 200000), ('prepend_garbage', b'GARB' + base[4:]),
                       ('sfnt_ver_bogus', b'AAAA' + base[4:])]:
        open(os.path.join(OUT, 'e_%s.docx' % name), 'wb').write(docx(blob))
        made += 1
    # benign controls: untouched font, and a document with no embedded font
    open(os.path.join(OUT, 'xctrl_font_ok.docx'), 'wb').write(docx(base))
    open(os.path.join(OUT, 'xctrl_nofont.docx'), 'wb').write(docx(base, embed=False))
    print('made=%d dir=%s' % (made, OUT))


if __name__ == '__main__':
    main()
