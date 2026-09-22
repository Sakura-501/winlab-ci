#!/usr/bin/env python3
"""Targeted corpus for the Excel text-carrier DDE / name-record path.

Field boundaries come from the static reading of the record writer/reader:
  MdParseBaxcel  : *(_WORD*)(a1+5) = v26 ; BltB(src, a1+7, 2*v26)   (v26 <= 8192 from a 16386-byte / 8193-WCHAR buffer)
  HrNewDdeVal    : case 23 -> v16 = min(*(u16*)(a1+1), 255); alloc 2*v16+2; BltBBuf(a1+3, 2*v16, buf+1, 2*v16)
  DIF record     : buf[0]=23, *(u16*)(buf+1)=min(cch,255), BltB(src, buf+3, 2*cch) into a 32793-element stack buffer
So the interesting axes are the 255 clamp, the 8192/16384 char boundary, byte-vs-WCHAR units,
embedded terminators, and repeated-name merges (HrMergeLbls / FNukeLinkName).

usage: mk_dde_corpus.py <outdir>
"""
import os
import sys

B = chr(92)
QUOT = "'"


def cell(topic, item='A0'):
    return '=%s|%s%s%s!%s' % ('notepad', QUOT, topic, QUOT, item)


def csv_text(rows, bom=''):
    head = 'k,v'
    out = [head]
    for r in rows:
        out.append('%d,"%s"' % (r[0], r[1].replace('"', '""')))
    txt = '\r\n'.join(out) + '\r\n'
    return bom + txt


def write(d, name, data):
    p = os.path.join(d, name)
    if isinstance(data, str):
        open(p, 'w', encoding='utf-8', newline='') .write(data)
    else:
        open(p, 'wb').write(data)
    return p


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    made = []

    lens = [1, 2, 3, 31, 32, 63, 64, 127, 128, 129, 200, 253, 254, 255, 256, 257,
            300, 400, 509, 510, 511, 512, 600, 1000, 1023, 1024, 2047, 2048, 4000,
            4094, 4095, 4096, 4097, 8000, 8190, 8191, 8192, 8193, 8194, 12000,
            16382, 16383, 16384, 16385, 16386, 20000, 32000]
    for L in lens:
        made.append(write(out, 't%05d.csv' % L, csv_text([(1, cell('A' * L))])))
    for L in [1, 8, 100, 255, 256, 1000, 4096, 8192, 16384]:
        made.append(write(out, 'i%05d.csv' % L, csv_text([(1, cell('AAAA', 'B' + 'Z' * L))])))

    # quoting / separator / escape shapes around the | and quoted-topic grammar
    odd = {
        'q_empty': cell(''),
        'q_doubled': cell("it''s"),
        'q_bar': cell('a|b'),
        'q_bang': cell('a!b!c'),
        'q_bslash': cell('a' + B * 2 + 'x'),
        'q_slash': cell('a//b'),
        'q_brack': cell('[1]a'),
        'q_brace': cell('{a}'),
        'q_pct': cell('%a%'),
        'q_dollar': cell('a$b$c'),
        'q_nopipe': '=notepad' + cell('abc')[8:],
        'q_twopipe': '=a||b!A0',
        'q_pipefirst': '=|abc!A0',
        'q_semi': cell('a;b'),
        'q_comma': cell('a,b'),
        'q_utf_hi': cell('中文' * 200),
        'q_rtl': cell('אב' * 300),
        'q combining': cell('a' + chr(0x0301) * 900),
        'q_zyzz': cell('a' + chr(0x2028) * 500),
    }
    for k, v in odd.items():
        made.append(write(out, 'e_%s.csv' % k.replace(' ', '_'), csv_text([(1, v)])))

    # embedded terminators / control bytes (UTF-16 LE carrier so U+0000 can be written)
    for tag, payload in [('surr', 'a' + ''.join(chr(c) for c in range(0xD800, 0xDC00, 4)) + 'b' * 300),
                         ('nul_mid', 'AB' + chr(0) + 'CD' * 200),
                         ('nul_end', 'AB' + chr(0)),
                         ('ctrl_lo', ''.join(chr(c) for c in range(1, 32))),
                         ('nul_255', 'A' * 254 + chr(0) + 'B' * 20),
                         ('nul_8192', 'A' * 8192 + chr(0))]:
        txt = csv_text([(1, cell(payload))])
        made.append(write(out, 'u_%s.csv' % tag, ('\ufeff'.encode('utf-16-le','surrogatepass') + txt.encode('utf-16-le','surrogatepass'))))

    # name-table pressure: many distinct links, and repeated links (merge path)
    made.append(write(out, 'm_distinct200.csv', csv_text([(i, cell('T%04d' % i)) for i in range(1, 201)])))
    made.append(write(out, 'm_same400.csv', csv_text([(i, cell('SAME' * 60)) for i in range(1, 401)])))
    made.append(write(out, 'm_grow_mix.csv', csv_text(
        [(i, cell('A' * (i * 37 % 9000))) for i in range(1, 121)] +
        [(200 + i, cell('B' * 255, 'C%d' % i)) for i in range(1, 41)])))
    made.append(write(out, 'm_mixed_plain.csv', csv_text(
        [(1, cell('A' * 250)), (2, '=1+1'), (3, '="x"&"y"'), (4, cell('B' * 4000)),
         (5, '=SUM(1,2)'), (6, cell('C' * 8192))])))

    # SYLK E-record carriers (same formula text, different loader)
    def slk(rows_note, tokens):
        lines = ['ID;PW XL 2000 4', 'F;P0;DG0G8;M150', 'C;Y1;X1;K"note"']
        for i, tok in enumerate(tokens):
            lines.append('E;Y%d;X1;%s' % (i + 2, tok))
            lines.append('C;Y%d;X1;E' % (i + 2))
        lines += ['B;1;1;8;8', 'W;N', 'P;M8', 'O;N', 'E']
        return '\r\n'.join(lines) + '\r\n'

    def stok(text):
        return 'S"' + text.replace('"', '""') + '"'

    for L in [1, 60, 127, 128, 255, 256, 300, 1000, 4096, 8192, 16384]:
        f = '=notepad|' + QUOT + ('A' * L) + QUOT + '!A0'
        made.append(write(out, 's%05d.slk' % L, slk(None, [stok('x'), 'N1', 'O+'])))
        p = os.path.join(out, 'sK%05d.slk' % L)
        open(p, 'w', encoding='utf-8', newline='').write(
            'ID;PW XL 2000 4\r\nF;P0;DG0G8;M150\r\n' +
            '\r\n'.join('C;Y%d;X1;K"%s"' % (i + 1, f.replace('"', '""')) for i in range(1)) +
            '\r\nC;Y2;X1;K"%s"\r\nB;1;1;8;8\r\nW;N\r\nP;M8\r\nO;N\r\nE\r\n' % f.replace('"', '""'))
        made.append(p)

    # DIF / PRN carriers with the same text
    for L in [60, 255, 256, 1000, 4096, 8192]:
        f = cell('A' * L)
        dif = ('TABLE,xx,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;2;1\r\n'
               'D;1\r\nN;%s\r\nE;\r\n' % f.replace(';', ','))
        made.append(write(out, 'd%05d.dif' % L, dif))
        made.append(write(out, 'p%05d.prn' % L, f.ljust(200) + '\r\n'))
    print('cases=%d dir=%s' % (len(made), out))


if __name__ == '__main__':
    main()
