#!/usr/bin/env python3
"""mk_pdf2.py - a second, "real-world-shaped" PDF corpus for the PDFREFLOW /
mip_pdf_sdk line: each form is built to exercise one named parser cluster that
exists in PDFREFLOW's symbol set (xref streams, ObjStm, Type-4 functions,
ToUnicode CMaps, CID fonts, JPX/CCITT images, AcroForm/XFA, encryption, outlines).

usage: python3 tools/mk_pdf2.py [outdir]
"""
import os
import sys
import zlib


def stream_obj(d, extra=b''):
    return b'<< /Length ' + str(len(d)).encode() + b' >>' + extra + b'\nstream\n' + d + b'\nendstream'


def deflate(x):
    return zlib.compress(x, 9)


def assemble(objs, trailer_extra=b'', xref_stream=False):
    """objs: dict num -> bytes. Returns the whole file."""
    nums = sorted(objs)
    out = bytearray(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')
    off = {}
    for n in nums:
        off[n] = len(out)
        out += b'%d 0 obj\n' % n + objs[n] + b'\nendobj\n'
    if not xref_stream:
        xr = len(out)
        out += b'xref\n0 %d\n' % (len(nums) + 1) + b'0000000000 65535 f \n'
        for n in nums:
            out += b'%010d 00000 n \n' % off[n]
        out += b'trailer\n<< /Size %d %s >>\nstartxref\n%d\n%%%%EOF\n' % (len(nums) + 1, trailer_extra, xr)
        return bytes(out)
    # classic xref + appended xref stream (so both paths run)
    xr = len(out)
    out += b'xref\n0 %d\n' % (len(nums) + 1) + b'0000000000 65535 f \n'
    for n in nums:
        out += b'%010d 00000 n \n' % off[n]
    out += b'trailer\n<< /Size %d %s /XRefStm %d >>\nstartxref\n%d\n%%%%EOF\n' % (
        len(nums) + 1, trailer_extra, 0, xr)
    return bytes(out)


def content(text=b'Hello PDFREFLOW corpus two.', tj=0, qq=0):
    c = bytearray(b'BT /F1 12 Tf 72 720 Td (')
    c += text + b') Tj ET\n'
    if tj:
        c += b'BT /F1 10 Tf 72 700 Td ['
        for k in range(tj):
            c += b'(x%d) -%d ' % (k, k % 97)
        c += b'] TJ ET\n'
    if qq:
        c += b'q' * qq + b'Q' * qq + b'\n'
    return bytes(c)


def base_doc(mut, npages=3):
    objs = {}
    page_ids = [10 + i for i in range(npages)]
    cont_ids = [20 + i for i in range(npages)]
    objs[1] = b'<< /Type /Catalog /Pages 2 0 R >>'
    objs[2] = ('<< /Type /Pages /Kids [%s] /Count %d >>' % (
        ' '.join('%d 0 R' % p for p in page_ids), npages)).encode()
    objs[3] = b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'
    for i, pid in enumerate(page_ids):
        objs[pid] = ('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources '
                     '<< /Font << /F1 3 0 R >> >> /Contents %d 0 R >>' % cont_ids[i]).encode()
        objs[cont_ids[i]] = stream_obj(content(tj=200 if mut == 'tj_big' else 0,
                                               qq=600 if mut == 'qq_deep' else 0))
    objs[5] = b'<< /Title (Corpus two) /Author (probe) /Producer (mk_pdf2) >>'

    if mut in ('objstm', 'objstm_n_mismatch', 'objstm_first_bad'):
        # /Type /ObjStm with N entries; the payload is "num offset num offset ... <objects>"
        inner = b''
        payload = b''
        entries = [(60, b'<< /Type /Annot /Subtype /Text /Contents (note) /P 10 0 R >>'),
                   (61, b'<< /Foo (bar) >>')]
        for num, body in entries:
            inner += b'%d %d ' % (num, len(payload))
            payload += body
        n = 5 if mut == 'objstm_n_mismatch' else len(entries)
        first = 0 if mut == 'objstm_first_bad' else len(inner)
        objs[62] = (b'<< /Type /ObjStm /N %d /First %d ' % (n, first)) + stream_obj(inner + payload)
        objs[1] = b'<< /Type /Catalog /Pages 2 0 R /Test 62 0 R >>'
        for k, (num, _) in enumerate(entries):
            objs[num] = b'<< /Free true >>' if False else objs.get(num, b'<< /Stub true >>')

    if mut in ('cmap_bfchar_big', 'cmap_bfrange_bad'):
        cm = b'/CMapName /Adobe-Identity-UCS def /CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n'
        if mut == 'cmap_bfchar_big':
            cm += b'200 beginbfchar\n'
            for k in range(200):
                cm += b'<%04X> <%04X>\n' % (k, 0x4E00 + k)
            cm += b'endbfchar\n'
        else:
            cm += b'1 beginbfrange\n<0020> <FFFF> <0020>\nendbfrange\n'
        objs[70] = stream_obj(cm)
        objs[71] = (b'<< /Type /Font /Subtype /Type0 /BaseFont /CidProbe /Encoding /Identity-H '
                    b'/DescendantFonts [72 0 R] /ToUnicode 70 0 R >>')
        objs[72] = (b'<< /Type /Font /Subtype /CIDFontType2 /BaseFont /CidProbe /CIDSystemInfo '
                    b'<< /Registry (Adobe) /Ordering (GB1) /Supplement 2 >> /FontDescriptor 73 0 R '
                    b'/DW 1000 /W [ 1 [500 500 500] ] /CIDToGIDMap 74 0 R >>')
        objs[73] = (b'<< /Type /FontDescriptor /FontName /CidProbe /Flags 4 /FontBBox [-100 -300 1100 900] '
                    b'/ItalicAngle 0 /Ascent 800 /Descent -200 /CapHeight 700 /StemV 80 /FontFile2 75 0 R >>')
        gid = bytes(range(256)) * 8                       # 2048 bytes of "CIDToGIDMap"
        objs[74] = stream_obj(gid)
        objs[75] = stream_obj(b'\x00\x01\x00\x00' + bytes(511))   # a stub TrueType collection
        objs[page_ids[0]] = objs[page_ids[0]].replace(b'/F1 3 0 R', b'/F1 3 0 R /F2 71 0 R')

    if mut in ('func_type4', 'func_type4_deep', 'func_type2_bad'):
        if mut == 'func_type4':
            prog = b'{ 1 add dup mul exch pop } bind'
        elif mut == 'func_type4_deep':
            prog = b'{ ' + b'1 add ' * 4000 + b'} bind'
        else:
            prog = b''
        objs[80] = stream_obj(prog)
        objs[81] = (b'<< /FunctionType %s /Domain [0 1] /Range [0 1] %s >>' % (
            (b'4' if 'type4' in mut else b'2'), (b'/Filters [/Identity]' if 'type2' in mut else b'')))
        if 'type2' in mut:
            objs[81] = b'<< /FunctionType 2 /Domain [0 1] /Range [0 1] /C0 [0] /C1 [1] /N 65535 >>'
        objs[82] = b'<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] /Resources << /Font << /F1 3 0 R >> >> /Matrix [1 0 0 1 0 0] /Length 0 >>\nstream\n\nendstream'
        objs[page_ids[0]] = objs[page_ids[0]].replace(
            b'/Contents', b'/Annots [83 0 R] /Contents') if False else objs[page_ids[0]]
        objs[83] = b'<< /Type /Annot /Subtype /Widget /FT 84 0 R /Rect [10 10 40 40] /T (f1) /AA << /E << /S /JavaScript /JS (x) >> >> >>'
        objs[84] = b'<< /DA () >>'
        objs[1] = b'<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [83 0 R] /DR << /Font << /F1 3 0 R >> >> >>'

    if mut in ('image_jpx', 'image_ccitt', 'image_dims_bad'):
        if mut == 'image_jpx':
            body = b'\x00\x00\x00\x0CJP2 \x00\x01\x00\x00JP2H' + bytes(64)
            objs[90] = (b'<< /Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceRGB '
                        b'/BitsPerComponent 8 /Filter /JPXDecode ') + stream_obj(body)
        elif mut == 'image_ccitt':
            objs[90] = (b'<< /Type /XObject /Subtype /Image /Width 1728 /Height 200 /BitsPerComponent 1 '
                        b'/Filter /CCITTFaxDecode /Decode [1 0] /DecodeParms << /K -1 /Columns 1728 >> ') + stream_obj(bytes(64))
        else:
            objs[90] = (b'<< /Type /XObject /Subtype /Image /Width -8 /Height 2147483647 /ColorSpace /DeviceGray '
                        b'/BitsPerComponent 16 /Length 8 >>\nstream\n\x00\x01\x02\x03\x04\x05\x06\x07\nendstream')
        objs[91] = b'<< /Type /Pattern /PatternType 2 /PatternType 1 >>'
        objs[page_ids[0]] = objs[page_ids[0]].replace(b'/Font << /F1 3 0 R >>',
                                                      b'/Font << /F1 3 0 R >> /XObject << /Im0 90 0 R >>')
        objs[cont_ids[0]] = stream_obj(content() + b'\nq 100 0 0 100 200 200 cm /Im0 Do Q\n')

    if mut in ('outline_struct', 'meta_xml'):
        objs[100] = b'<< /Type /Outlines /First 101 0 R /Last 101 0 R /Count 1 >>'
        objs[101] = b'<< /Title (t) /Parent 100 0 R /Dest [10 0 R /Fit] /A << /S /GoTo /D [10 0 R /Fit] >> >>'
        objs[102] = stream_obj(b'<?xpacket begin="\xef\xbb\xbf"?><x:xmpmeta xmlns:x="adobe:ns:meta/">'
                               + b'<ragged>' * 40 + b'</x:xmpmeta><?xpacket end="w"?>')
        objs[1] = b'<< /Type /Catalog /Pages 2 0 R /Outlines 100 0 R /MarkInfo << /Marked true >> /StructTreeRoot 103 0 R /Metadata 102 0 R >>'
        objs[103] = b'<< /Type /StructTreeRoot /ParentTree 104 0 R /K [105 0 R] >>'
        objs[104] = b'<< /Type /ParentTree /Nums [0 105 0 R 1 105 0 R] >>'
        objs[105] = b'<< /Type /StructElem /S /Document /P 103 0 R /K 106 0 R >>'
        objs[106] = b'<< /Type /StructElem /S /P /P 105 0 R /Pg 10 0 R >>'

    if mut in ('xref_stream', 'prev_broken'):
        body = deflate(b'\x00' + b'\x00\x00\x00\x00\xff\xff' + b'\x01' + b'\x00\x00\x10\x00\x00\x00' * 3)
        objs[110] = (b'<< /Type /XRef /Size 120 /W [1 4 2] /Root 1 0 R /Index [0 4 4 116] /Filter /FlateDecode /Length %d >>'
                     % len(body)) + b'\nstream\n' + body + b'\nendstream'
    return objs


def build(mut):
    objs = base_doc(mut)
    tr = b'/Root 1 0 R /Info 5 0 R /ID [<0A0B> <0C0D>]'
    if mut in ('encrypted',):
        objs[120] = (b'<< /Filter /Standard /V 2 /R 3 /Length 128 /O <' + b'00' * 32 +
                     b'> /U <' + b'00' * 32 + b'> /P -44 >>')
        tr += b' /Encrypt 120 0 R'
    if mut == 'prev_broken':
        tr += b' /Prev 9999999'
    return assemble(objs, trailer_extra=tr, xref_stream=False)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else 'work/pdfs2'
    os.makedirs(outdir, exist_ok=True)
    forms = ['clean3p', 'tj_big', 'qq_deep', 'objstm', 'objstm_n_mismatch', 'objstm_first_bad',
             'cmap_bfchar_big', 'cmap_bfrange_bad', 'func_type4', 'func_type4_deep', 'func_type2_bad',
             'image_jpx', 'image_ccitt', 'image_dims_bad', 'outline_struct', 'meta_xml',
             'encrypted', 'prev_broken', 'xref_stream']
    man = []
    for f in forms:
        data = build(f if f != 'clean3p' else None)
        open(os.path.join(outdir, f + '.pdf'), 'wb').write(data)
        man.append('%s.pdf\t%d' % (f, len(data)))
    open(os.path.join(outdir, 'manifest.txt'), 'w').write('\n'.join(man) + '\n')
    print('\n'.join(man))
    print("wrote %d pdfs -> %s" % (len(forms), outdir))


if __name__ == '__main__':
    main()
