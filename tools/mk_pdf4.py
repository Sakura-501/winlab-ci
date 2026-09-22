#!/usr/bin/env python3
"""PDF image carriers that decouple the /Decode array from the colour space.

ApplyDecodeGeneralCase / ApplyDecodeArray take the per-row sample count and the LUT
table from the caller's colour description, while the destination bitmap is sized from
/Width, /Height, /BitsPerComponent and the colour space's component count. Putting a
different number of ranges in /Decode (and ranges whose span is wider than the sample
domain) is the direct test of "count from one field, bound from another".

Sizes are deliberately tiny (4x2 .. 16x16) so a single extra component per sample walks
off the allocation on the first row under an armed page heap.

usage: mk_pdf4.py <outdir>
"""
import os
import sys

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)

CS = {
    'gray': (b'/DeviceGray', 1),
    'rgb': (b'/DeviceRGB', 3),
    'cmyk': (b'/DeviceCMYK', 4),
}
DECODE_LEN = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 24, 32, 64, 128, 255]
RANGES = [
    '0 1', '0 255', '0 65535', '255 0', '-1 1', '0 1e30', '1e-30 1', '0 -1',
    '2147483647 -2147483648', '0 0', '1 1',
]


def stream(n):
    return bytes((i * 37 + 11) & 0xFF for i in range(n))


def obj_image(num, w, h, bpc, csname, filt, decodetxt, extra=b'', data=None):
    cs, ncol = CS[csname]
    body = data if data is not None else stream(max(1, (w * h * ncol * bpc + 7) // 8))
    d = (b'%d 0 obj\n<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace %s '
         b'/BitsPerComponent %d /Filter %s /Length %d %s%s>>\nstream\n'
         % (num, w, h, cs, bpc, filt, len(body), decodetxt, extra))
    return d + body + b'\nendstream\nendobj\n'


def build(imgs):
    """objs: 1 catalog, 2 pages, then per image i: page 3+3i, content 4+3i, image 5+3i"""
    n = len(imgs)
    objs = [None] * (2 + 3 * n)
    objs[0] = b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
    kids = b' '.join(b'%d 0 R' % (3 + 3 * i) for i in range(n))
    objs[1] = b'2 0 obj\n<< /Type /Pages /Kids [%s] /Count %d >>\nendobj\n' % (kids, n)
    for i, im in enumerate(imgs):
        pg, co, imn = 3 + 3 * i, 4 + 3 * i, 5 + 3 * i
        objs[pg - 1] = (b'%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] '
                        b'/Resources << /XObject << /Im0 %d 0 R >> >> /Contents %d 0 R >>\nendobj\n'
                        % (pg, imn, co))
        content = b'q 64 0 0 64 30 700 cm /Im0 Do Q'
        objs[co - 1] = b'%d 0 obj\n<< /Length %d >>\nstream\n' % (co, len(content)) + content + b'\nendstream\nendobj\n'
        objs[imn - 1] = im
    out = b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n'
    offs = []
    for i, b in enumerate(objs, 1):
        offs.append((i, len(out)))
        out += b
    xr = len(out)
    out += b'xref\n0 %d\n' % (len(objs) + 1)
    out += b'0000000000 65535 f \n'
    for _, o in offs:
        out += b'%010d 00000 n \n' % o
    out += b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(objs) + 1, xr)
    return out


def main():
    made = 0
    cases = []
    # 1) /Decode entry count decoupled from the colour space, per bpc and filter
    for cs in ('gray', 'rgb', 'cmyk'):
        for bpc in (1, 2, 4, 8, 12, 16):
            for dl in DECODE_LEN:
                dec = b'/Decode [' + b' '.join(b'0 1' for _ in range(dl // 2)) + b']' if dl >= 2 else b''
                if dl in (1, 3, 5):        # odd trailing entry
                    dec = b'/Decode [' + b' '.join(b'0 1' for _ in range(dl)) + b']'
                cases.append(('dc_%s_b%02d_n%03d' % (cs, bpc, dl),
                              obj_image(5, 8, 4, bpc, cs, b'/DCTDecode', dec, data=b'\xff\xd8\xff\xdb' + bytes(40))))
            for filt in (b'/FlateDecode', b'/LZWDecode', b'/RunLengthDecode', b'/ASCIIHexDecode'):
                cases.append(('dc_%s_%s' % (cs, filt[1:-7].decode()),
                              obj_image(5, 16, 16, 8, cs, filt, b'/Decode [0 255 0 255 0 255 0 255 0 255 0 255]',
                                        data=stream(4096))))
    # 2) /Decode range values that widen the LUT index beyond the sample domain
    for cs in ('gray', 'rgb'):
        for bpc in (1, 2, 4, 8):
            for r in RANGES:
                cases.append(('dr_%s_b%02d_%s' % (cs, bpc, abs(hash(r)) % 9999),
                              obj_image(5, 8, 8, bpc, cs, b'/FlateDecode',
                                         b'/Decode [' + r.encode() + b']', data=stream(2048))))
    # 3) DecodeParms /Colors and /BitsPerComponent decoupled from the image dictionary
    for colors in (1, 3, 4, 6, 0, 255):
        for bpc in (1, 4, 8, 16):
            cases.append(('dp_c%d_b%02d' % (colors, bpc),
                          obj_image(5, 16, 16, bpc, 'rgb', b'/FlateDecode', b'',
                                    extra=b'/DecodeParms << /Colors %d /BitsPerComponent %d /Columns 16 /Predictor 10 >>'
                                          % (colors, bpc), data=stream(8192))))
    # 4) /Height vs stream rows (destination sized by the dict, source longer), and /SMask
    for h in (1, 2, 8, 16, 64):
        cases.append(('ht_%03d' % h,
                      obj_image(5, 16, h, 8, 'gray', b'/FlateDecode', b'/Decode [0 1 0 1 0 1]',
                                data=stream(20000))))
        cases.append(('sm_%03d' % h,
                      obj_image(5, 16, h, 8, 'gray', b'/FlateDecode', b'',
                                extra=b'/SMask 99 0 R', data=stream(20000))))
    for name, body in cases:
        open(os.path.join(OUT, name + '.pdf'), 'wb').write(build([body]))
        made += 1
    print('wrote %d decode-array pdfs -> %s' % (made, OUT))


if __name__ == '__main__':
    main()
