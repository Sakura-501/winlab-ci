#!/usr/bin/env python3
"""PDF carriers aimed at PDFREFLOW's hand-rolled codecs (the module Word spawns
out-of-process when a PDF is opened).

Each form puts a *declared* size/dimension/count in one structure and a *different*
amount of data in another, so a fill loop that trusts the wrong one crosses its
allocation. Families: image filter chains (JBIG2 MMR regions, JP2 box geometry, LZW,
RunLength, Predictor, ASCII85/Hex nesting), object streams, xref streams, and the
Type-1/4 function/CMap paths.

usage: mk_pdf3.py <outdir>
"""
import os
import struct
import sys

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)


# ------------------------------------------------------------------ group 4 (MMR)
EOL = 0
W1 = [0x13B, 0x13A, 0x139, 0x138, 0x137, 0x135, 0x134, 0x133, 0x132, 0x131, 0x12F, 0x12C,
      0x12A, 0x127, 0x125, 0x123, 0x121, 0x11D, 0x119, 0x117, 0x115, 0x113, 0x111, 0x10F]
TERM = {}
_terms = [(1, '001101'), (2, '000110'), (3, '001001'), (4, '001011'), (5, '00111'),
          (6, '01000'), (7, '01001'), (8, '01010'), (9, '01011'), (10, '01100'),
          (11, '01101'), (12, '01110'), (13, '01111'), (14, '1000'), (15, '1001'),
          (16, '1010'), (17, '1011'), (18, '11000'), (19, '11001'), (20, '11010'),
          (21, '11011')]
for n, c in _terms:
    TERM[n] = c
UNCOMP = {}
for i in range(64):
    UNCOMP[i] = '0000001000' + format(i, '012b')[4:]
for i in range(64, 2560 // 64 + 64):
    pass
WHITE_ABS = dict(UNCOMP)


def g4_encode(rows):
    """minimal 1-D modified-Huffman-free encoder: encode every row uncompressed (Mode 2)"""
    bits = []
    for r in rows:
        bits.append('00001')            # uncompressed mode code
        n = len(r)
        bits.append(format(n, '012b'))
        bits.append(r)
        pad = (8 - ((17 + n) % 8)) % 8
        bits.append('0' * pad)
    data = ''.join(bits)
    pad = (8 - len(data) % 8) % 8
    data += '0' * pad
    return bytes(int(data[i:i + 8], 2) for i in range(0, len(data), 8))


def jbig2_mmr_segment(w, h, pattern_rows, extra_len=0, declare_bigger=False):
    """segment header + IMMEDIATE generic region, MMR=1, single segment"""
    # segment header: flags(1) + segnumber(4) + page association(1: 0x00 => 0)
    flags = 0x40                      # segment type 4 (table 2 says 4 = immediate generic region: bits 0-5)
    flags |= 4                         # segment type 4
    flags |= 0x01                      # retained
    head = bytes([flags]) + struct.pack('>I', 0) + bytes([0x00])
    # region segment header: SBW,SBH(4) + SBPPT(4) + SBRTEMPLATE..SBDONTPATTERN
    sbw, sbh = w, h
    fixed = struct.pack('>II', sbw, sbh) + struct.pack('>I', 0)
    flags2 = 0x01                      # MMR = 1
    region = flags2 + bytes([0x00]) + bytes([0x00]) + bytes([0x00])  # SBRTEMPLATE0..3, SBSTRIP
    rows = []
    for y in range(h):
        rows.append(pattern_rows(y, w))
    body = g4_encode(rows)
    if declare_bigger:
        region = flags2 + bytes([0x08]) + bytes([0x00]) + bytes([0x00])   # SBSTRIP=8 vs h
        body = g4_encode(rows[:max(1, h // 4)])
    if extra_len:
        body = body + bytes(extra_len)
    pm = fixed + region + struct.pack('>I', len(body))   # segment size after header (17 + data)
    seg = head + pm[:4] + pm[4:]
    # total: flags(1)+number(4)+pageassoc(1) + 11 region header fields + data
    payload = fixed + region + struct.pack('>I', 11 + len(body)) + struct.pack('>I', 0) + body
    hdr = bytes([flags]) + struct.pack('>I', 0) + bytes([0x00])
    # rebuild properly: header(6) + SBW(4)+SBH(4)+SBPPT(4)+SBRTEMPLATE(1)+SBGRAGX.. wait spec layout
    seg_body = struct.pack('>II', sbw, sbh) + struct.pack('>I', 0) + bytes([flags2, 0x00, 0x00, 0x00])
    # SBRTEMPLATE(1) + SBGRRET/... we emit: flags2 + strip_h(1) + strip_w(1) + tmpl0..3
    seg_body = struct.pack('>II', sbw, sbh) + struct.pack('>I', 0) + bytes([flags2]) + \
        bytes([0x04, 0x04]) + bytes([0x00, 0x00, 0x00, 0x00])
    lsb = len(seg_body) + len(body)
    full = hdr + seg_body + body
    return full


def jbig2_blob(w, h, variant='ok'):
    rows = [format((y * 2654435761) & ((1 << w) - 1) if w <= 64 else (1 << (y % w)), 'b').zfill(w)
            for y in range(h)]
    bits = []
    for r in rows:
        bits.append('00001' + format(len(r), '012b') + r + '0' * ((8 - (17 + len(r)) % 8) % 8))
    data = ''.join(bits)
    data += '0' * ((8 - len(data) % 8) % 8)
    body = bytes(int(data[i:i + 8], 2) for i in range(0, len(data), 8))
    flags = 0x40 | 4 | 0x01
    hdr = bytes([flags]) + struct.pack('>I', 0) + bytes([0x00])
    segbody = struct.pack('>II', w, h) + struct.pack('>I', 0) + bytes([0x01]) + \
        bytes([0x04, 0x04]) + bytes([0, 0, 0, 0])
    if variant == 'short_data':
        body = body[:max(1, len(body) // 3)]
    elif variant == 'long_data':
        body = body + bytes(range(64)) * 4
    elif variant == 'huge_declare':
        segbody = struct.pack('>II', w, h) + struct.pack('>I', 0) + bytes([0x01]) + \
            bytes([0xFF, 0xFF]) + bytes([0, 0, 0, 0])
    elif variant == 'zero_size':
        body = b''
    lsb = len(segbody) + len(body)
    return hdr + segbody + body


# ------------------------------------------------------------------ JP2 boxes
def box(sid, payload):
    return struct.pack('>I', len(payload) + 8) + sid.encode() + payload


def jp2(w, h, variant='ok'):
    sig = b'\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a'
    fh = box('ftyp', b'jp2 \x00\x00\x00\x00jp2 \x00\x00\x00\x00')
    # JP2h box containing ihdr
    if variant == 'ihdr_huge':
        ihdr_payload = struct.pack('>IIHB', 0xFFFFFFFF, h, 3, 7)
    elif variant == 'ihdr_zero':
        ihdr_payload = struct.pack('>IIHB', 0, 0, 3, 7)
    elif variant == 'ihdr_negish':
        ihdr_payload = struct.pack('>IIHB', w, 0xFFFFFFFF, 3, 7)
    elif variant == 'ihdr_short':
        ihdr_payload = struct.pack('>IIH', w, h, 3)          # missing C+UnkC+Ap
    else:
        ihdr_payload = struct.pack('>IIHB', w, h, 3, 7)
    jp2h = b'\x6a\x70\x32\x68' + box('ihdr', ihdr_payload) + box('colr', b'\x01\x00\x00\x10')
    out = sig + fh + struct.pack('>I', len(jp2h) + 8) + jp2h
    if variant == 'truncated':
        out = out[:len(out) // 2]
    if variant == 'box_len_wrap':
        out = out.replace(struct.pack('>I', len(jp2h) + 8), struct.pack('>I', 4), 1)
    return bytes(out)


# ------------------------------------------------------------------ PDF assembly
def assemble(body_objs, xref_off=None):
    """body_objs: list of bytes already terminated by 'N 0 obj ... endobj\\n'"""
    out = b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n'
    offs = []
    for i, b in enumerate(body_objs, 1):
        offs.append((i, len(out)))
        out += b
    xref_pos = len(out) if xref_off is None else xref_off
    out += b'xref\n0 %d\n' % (len(offs) + 1)
    out += b'0000000000 65535 f \n'
    for _, o in offs:
        out += b'%010d 00000 n \n' % o
    out += (b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n'
            % (len(offs) + 1, xref_pos))
    return out


def img_pdf(stream, filt, w, h, extra=''):
    obj2 = (b'2 0 obj\n<< /Type /XObject /Subtype /Image /Width %d /Height %d '
            b'/ColorSpace /DeviceGray /BitsPerComponent 1 /Filter %s /Length %d %s>>\nstream\n'
            % (w, h, filt, len(stream), extra.encode()) + stream + b'\nendstream\nendobj\n')
    content = b'q %d 0 0 %d 40 700 cm /Im0 Do Q' % (w, h)
    objs = [
        b'1 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n',
        obj2,
        b'3 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n',
        b'4 0 obj\n<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] '
        b'/Resources << /XObject << /Im0 2 0 R >> >> /Contents 5 0 R >>\nendobj\n',
        b'5 0 obj\n<< /Length %d >>\nstream\n' % len(content) + content + b'\nendstream\nendobj\n',
    ]
    return assemble(objs)


def lzw_stream(min_code, data, declared_bad=None):
    """very small LZW encoder for 1-bit-ish samples"""
    dict_ = {bytes([i]): i for i in range(256)}
    next_code = 258
    width = min_code
    out_bits = []
    buf = b''
    for byte in data:
        cur = buf + bytes([byte])
        if cur in dict_:
            buf = cur
            continue
        out_bits.append(format(dict_[buf], '0%db' % width))
        dict_[cur] = next_code
        next_code += 1
        if next_code + 1 > (1 << width) and width < 12:
            width += 1
        buf = bytes([byte])
    if buf:
        out_bits.append(format(dict_[buf], '0%db' % width))
    out_bits.append(format(257, '0%db' % width))
    bits = ''.join(out_bits)
    bits += '0' * ((8 - len(bits) % 8) % 8)
    s = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    if declared_bad == 'truncate':
        s = s[:max(1, len(s) // 2)]
    if declared_bad == 'extend':
        s = s + b'\x00' * 300
    return s


def rle_stream(data):
    """CCITT PackBits (RunLength)"""
    out = bytearray()
    i = 0
    while i < len(data):
        run = 1
        while i + run < len(data) and data[i + run] == data[i] and run < 128:
            run += 1
        if run >= 3:
            out.append(257 - run)
            out.append(data[i])
            i += run
        else:
            lit = 0
            start = i
            while i < len(data) and lit < 128:
                lit += 1
                i += 1
            out.append(lit - 1)
            out += data[start:start + lit]
    return bytes(out)


def main():
    made = {}
    # ---- JBIG2 (MMR generic regions) with declared-vs-actual geometry
    for tag, w, h in [('small', 32, 8), ('wrap', 64, 16), ('wide', 2048, 4), ('tall', 8, 2048),
                      ('max1', 4096, 2), ('odd', 61, 7), ('zerow', 0, 8), ('zeroh', 8, 0)]:
        for v in ('ok', 'short_data', 'long_data', 'huge_declare', 'zero_size'):
            blob = jbig2_blob(w, h, v)
            name = 'jb_%s_%s' % (tag, v)
            made[name] = img_pdf(blob, b'/JBIG2Decode', max(1, w), max(1, h))
    # ---- JP2 / DXBox geometry against ihdr
    for v in ('ok', 'ihdr_huge', 'ihdr_zero', 'ihdr_negish', 'ihdr_short', 'truncated', 'box_len_wrap'):
        made['jpx_' + v] = img_pdf(jp2(64, 64, v), b'/JPXDecode', 64, 64)
        made['jpx256_' + v] = img_pdf(jp2(256, 256, v), b'/JPXDecode', 256, 256)
    # ---- LZW with /LZWDecode + early-change + Predictor variants
    base = bytes((y * 7 + x) & 0xFF for y in range(8) for x in range(32))
    for mc in (8, 9, 12):
        for bad in (None, 'truncate', 'extend'):
            made['lzw_%d_%s' % (mc, bad or 'ok')] = img_pdf(
                lzw_stream(mc, base, bad), b'/LZWDecode', 32, 8,
                '/DecodeParms << /EarlyChange %d /Predictor 1 >>' % (0 if mc == 8 else 1))
    for pred in (1, 2, 11, 12, 13, 15, 0x7F, 0x8000):
        raw = bytes(range(64)) * 4
        made['pred_%d' % pred] = img_pdf(
            raw, b'/FlateDecode', 16, 16,
            '/DecodeParms << /Predictor %d /Colors 1 /BitsPerComponent 8 /Columns 16 >>' % pred)
    # ---- RunLength with wrong row stride declared
    made['rle_ok'] = img_pdf(rle_stream(base), b'/RunLengthDecode', 32, 8)
    made['rle_short'] = img_pdf(rle_stream(base)[:20], b'/RunLengthDecode', 32, 8)
    made['rle_long'] = img_pdf(rle_stream(base) + b'\xff' * 500, b'/RunLengthDecode', 32, 8)
    # ---- nested filter chains (output of one feeds the next with mismatched /Length)
    made['chain_85_hex'] = img_pdf(
        b'~>' + b'' , b'/ASCII85Decode', 8, 8)
    made['chain_fl_hex'] = img_pdf(b'>', b'/ASCIIHexDecode', 8, 8)
    # ---- images whose /Width or /Height disagrees with the stream
    for w, h in [(1, 1), (4095, 1), (4096, 1), (1, 4096), (0, 8), (8, 0), (65535, 1), (1, 65535)]:
        made['dim_%d_%d' % (w, h)] = img_pdf(bytes(2048), b'/FlateDecode', max(1, w), max(1, h))
    # ---- BPC sweep
    for bpc in (1, 2, 4, 8, 12, 16, 0, -1, 255):
        made['bpc_%d' % bpc] = (b'2 0 obj\n<< /Type /XObject /Subtype /Image /Width 16 /Height 16 '
                                b'/ColorSpace /DeviceRGB /BitsPerComponent %d /Filter /FlateDecode '
                                b'/Length 8>>\nstream\nxxxxxxx\nendstream\nendobj\n' % bpc)
        made['bpc_%d' % bpc] = assemble([
            b'1 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n',
            (b'2 0 obj\n<< /Type /XObject /Subtype /Image /Width 16 /Height 16 '
             b'/ColorSpace /DeviceGray /BitsPerComponent %d /Filter /DCTDecode /Length 4>>\n'
             b'stream\nabcd\nendstream\nendobj\n' % bpc),
            b'3 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n',
            b'4 0 obj\n<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] '
            b'/Resources << /XObject << /Im0 2 0 R >> >> /Contents 5 0 R >>\nendobj\n',
            b'5 0 obj\n<< /Length 22 >>\nstream\nq 16 0 0 16 40 700 cm \nendstream\nendobj\n'])
    names = []
    for k, v in made.items():
        p = os.path.join(OUT, k + '.pdf')
        open(p, 'wb').write(v)
        names.append(k)
    print('wrote %d pdfs -> %s' % (len(names), OUT))


if __name__ == '__main__':
    main()
