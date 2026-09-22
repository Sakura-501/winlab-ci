#!/usr/bin/env python3
"""mk_pdf.py - build real-structure PDFs (and structural mutations) for the
PDFREFLOW.EXE (Word out-of-process PDF->OOXML converter) line.

usage:  python3 tools/mk_pdf.py <outdir>
Writes N .pdf files plus manifest.txt (name / bytes / mutation note).
"""
import os
import sys
import zlib


def build(mut=None, npages=2, text_reps=1):
    """Return PDF bytes. `mut` selects a structural mutation."""
    mut = mut or 'clean'
    objs = {}          # num -> bytes body (without "N 0 obj" wrapper)

    # 1 = Catalog, 2 = Pages, 3 = Font, 4..= Page, then content streams
    page_ids = [10 + i for i in range(npages)]
    cont_ids = [20 + i for i in range(npages)]
    kids = ' '.join('%d 0 R' % p for p in page_ids)
    objs[1] = b'<< /Type /Catalog /Pages 2 0 R >>'
    objs[2] = ('<< /Type /Pages /Kids [%s] /Count %d >>' % (kids, npages)).encode()
    objs[3] = b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'

    for i, pid in enumerate(page_ids):
        objs[pid] = ('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] '
                     '/Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>'
                     % cont_ids[i]).encode()
        body = b'BT /F1 12 Tf 72 720 Td ('
        body += (b'PDFREFLOW-PROBE page %d text run. ' % i) * text_reps
        body += b') Tj ET'
        if mut == 'length_big' and i == 0:
            real = len(body)
            objs[cont_ids[i]] = (b'<< /Length %d >>\nstream\n' % (real + 40000)) + body + b'\nendstream'
        elif mut == 'length_negative' and i == 0:
            objs[cont_ids[i]] = (b'<< /Length -1 >>\nstream\n') + body + b'\nendstream'
        elif mut == 'no_length' and i == 0:
            objs[cont_ids[i]] = b'stream\n' + body + b'\nendstream'
        else:
            objs[cont_ids[i]] = (b'<< /Length %d >>\nstream\n' % len(body)) + body + b'\nendstream'

    # a ToUnicode CMap object + an image XObject for the parser paths
    if mut in ('cmap_long', 'image', 'clean', 'objstm_bad', 'hex_unterminated'):
        cmap = (b'/CMapName /Adobe-Identity-UCS def /CMapType 2 def\n'
                b'1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n')
        if mut == 'cmap_long':
            cmap += b'100 beginbfchar\n'
            for k in range(100):
                cmap += b'<%04X> <%04X>\n' % (k, 0x4E00 + k)
            cmap += b'endbfchar\n'
        elif mut == 'hex_unterminated':
            cmap += b'1 beginbfchar\n<0041> <004\nendbfchar\n'
        else:
            cmap += b'1 beginbfchar\n<0041> <4F60>\nendbfchar\n'
        objs[40] = (b'<< /Length %d >>\nstream\n' % len(cmap)) + cmap + b'\nendstream'
        objs[41] = (b'<< /Type /XObject /Subtype /Image /Width 4 /Height 4 /ColorSpace /DeviceRGB '
                    b'/BitsPerComponent 8 /Length 48 >>\nstream\n' + bytes(range(48)) + b'\nendstream')
        objs[42] = (b'<< /Type /Font /Subtype /Type0 /BaseFont /Probe0 '
                    b'/Encoding /Identity-H /DescendantFonts [43 0 R] /ToUnicode 40 0 R >>')
        objs[43] = (b'<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Probe0 /CIDSystemInfo '
                    b'<< /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 44 0 R '
                    b'/DW 1000 /CIDToGIDMap /Identity >>')
        objs[44] = (b'<< /Type /FontDescriptor /FontName /Probe0 /Flags 4 /FontBBox [-100 -300 1100 900] '
                    b'/ItalicAngle 0 /Ascent 800 /Descent -200 /CapHeight 700 /StemV 80 >>')
        if mut == 'image':
            objs[page_ids[0]] = (objs[page_ids[0]].replace(
                b'/Resources << /Font << /F1 3 0 R >>',
                b'/Resources << /XObject << /Im0 41 0 R >> /Font << /F1 3 0 R /F2 42 0 R >>'))
            objs[20] = objs[20] + b'\nq 24 0 0 24 72 700 cm /Im0 Do Q'

    if mut == 'annot_huge':
        objs[50] = (b'<< /Type /Annot /Subtype /Widget /FT 51 0 R /T (x) /Rect [0 0 1 1] '
                    b'/V (hello) /P %d 0 R >>' % page_ids[0])
        objs[51] = b'<< /FT /Sig /DA () >>'
        objs[page_ids[0]] = objs[page_ids[0]].replace(b'>>\n', b'/Annots [50 0 R] >>\n', 1)

    nums = sorted(objs)
    out = bytearray(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')
    off = {}
    for n in nums:
        off[n] = len(out)
        out += b'%d 0 obj\n' % n + objs[n] + b'\nendobj\n'
    xr = len(out)
    cnt = len(nums) + 1
    declared = cnt
    if mut == 'size_wrong':
        declared = cnt + 50
    out += b'xref\n0 %d\n' % declared
    out += b'0000000000 65535 f \n'
    for n in nums:
        o = off[n]
        if mut == 'off_shift' and n == nums[1]:
            o += 3
        out += b'%010d 00000 n \n' % o
    if mut == 'size_wrong':
        for k in range(50):
            out += b'%010d 00000 n \n' % (10 + k)
    out += b'trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R /ID [<0102> <0304>] >>\nstartxref\n%d\n%%%%EOF\n' % (declared, xr)
    if mut == 'objstm_bad':
        out = out.replace(b'/Size %d' % declared, b'/Size 1 /Prev 9999999')
    return bytes(out)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else 'work/pdfs'
    os.makedirs(outdir, exist_ok=True)
    forms = [
        ('clean', None, 2, 1),
        ('big_text', None, 3, 40),
        ('image', 'image', 2, 4),
        ('cmap_long', 'cmap_long', 2, 2),
        ('hex_unterminated', 'hex_unterminated', 2, 2),
        ('length_big', 'length_big', 2, 6),
        ('length_negative', 'length_negative', 2, 2),
        ('no_length', 'no_length', 2, 2),
        ('size_wrong', 'size_wrong', 2, 2),
        ('off_shift', 'off_shift', 2, 2),
        ('annot_huge', 'annot_huge', 2, 2),
        ('objstm_bad', 'objstm_bad', 2, 2),
    ]
    man = []
    for name, mut, np, reps in forms:
        data = build(mut=mut, npages=np, text_reps=reps)
        p = os.path.join(outdir, name + '.pdf')
        open(p, 'wb').write(data)
        man.append('%s\t%d\tmut=%s pages=%d reps=%d' % (name + '.pdf', len(data), mut, np, reps))
    open(os.path.join(outdir, 'manifest.txt'), 'w').write('\n'.join(man) + '\n')
    print('\n'.join(man))
    print("wrote %d pdfs -> %s" % (len(forms), outdir))


if __name__ == '__main__':
    main()
