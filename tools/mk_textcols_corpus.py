#!/usr/bin/env python3
"""Column-count ladder corpus for Excel's text import (ASPPTEXTIMPORT).

Sink under test (findings/MSRC/M365-Insider/excel-formula-compiler-20260920/STATE.md, last section):
HrFinishDataRow / HrPushValue write a 24-byte-stride SXOPER array at obj+80 and a DWORD array at
obj+88, both bounded by the count at obj+96; the allocation site and the setter of obj+96 are not in
the local decompile slice, so the capacity question is settled dynamically.

Each carrier varies "columns seen by the first row" against "columns reached by a later row", which is
the only way obj+96 can disagree with whatever sized obj+80/obj+88.
"""
import os, sys

OUT = sys.argv[2] if len(sys.argv) > 2 else 'corpus_tc'
NS = [1, 2, 3, 5, 8, 16, 24, 31, 32, 33, 48, 63, 64, 65, 96, 100, 127, 128, 129, 160, 200, 255, 256,
      257, 300, 380, 512, 700, 1024, 1600]
DELIMS = {'csv': ',', 'tsv': '\t'}


def cell(i):
    return 'c%d' % i


def csv_body(ncols_first, ncols_row, rows=3, delim=',', quote=False):
    def line(n):
        out = []
        for i in range(n):
            v = cell(i)
            if quote and i % 3 == 0:
                v = '"%s,x"' % v
            out.append(v)
        return delim.join(out)
    parts = [line(ncols_first)]
    for _ in range(rows):
        parts.append(line(ncols_row))
    return '\r\n'.join(parts) + '\r\n'


def dif_body(ncols_first, ncols_row, rows=3):
    # DIF per the published grammar: TABLE, the virtual/column tuple headers, then data as
    # "<count>\n<value>\n<type>\n..." tuples, terminated by E.  Excel refused the earlier
    # SYLK-flavoured file (28/28 .dif opened=0 in run 35919455035).
    maxc = max(ncols_first, ncols_row)
    out = ['TABLE', '1,V,%d' % maxc, 'N', '1,C,%d' % maxc, 'R%dC%d' % (rows + 1, maxc), '0,0',
           '%d,%d' % (maxc, maxc), 'R,D', '0,0']

    def tuplin(vals):
        out.append(str(len(vals)))
        for v in vals:
            out.append('"%s"' % v)
            out.append('1')

    tuplin(['c%d' % i for i in range(ncols_first)])
    for k in range(rows):
        tuplin(['r%dc%d' % (k, i) for i in range(ncols_row)])
    out.append('E')
    return '\r\n'.join(out) + '\r\n'


def slk_body(ncols_first, ncols_row, rows=3):
    # Shape copied from a file Excel itself writes for FileFormat:=2 (out.slk on the VM):
    #   ID;PWXL;N;E / P;PGeneral / F;... / B;Y<rows>;X<cols>;D0 0 <r-1> <c-1>
    #   C;Y<row>;X1;K"..."   then, for the rest of that row,   C;X<n>;K"..."
    #   E
    # 28/28 .slk carriers reported opened=0 in run 35919455035 because my earlier records
    # carried no Y and repeated X1, so Excel refused the file before the parser ever ran.
    maxc = max(ncols_first, ncols_row)
    nrow = rows + 1
    out = ['ID;PWXL;N;E', 'P;PGeneral', 'F;P0;DG0G8;M285',
           'B;Y%d;X%d;D0 0 %d %d' % (nrow, maxc, nrow - 1, maxc - 1)]

    def emit(r, n):
        for i in range(n):
            if i == 0:
                out.append('C;Y%d;X1;K"c%d"' % (r, i))
            else:
                out.append('C;X%d;K"c%d"' % (i + 1, i))

    emit(1, ncols_first)
    for k in range(rows):
        emit(2 + k, ncols_row)
    out.append('E')
    return '\r\n'.join(out) + '\r\n'


def prn_body(ncols_first, ncols_row, rows=3):
    w = 6
    def line(n):
        return ''.join(('%-*s' % (w, cell(i))) for i in range(n))
    return '\r\n'.join([line(ncols_first)] + [line(ncols_row) for _ in range(rows)]) + '\r\n'


def build():
    os.makedirs(OUT, exist_ok=True)
    n = 0
    for ext, fn, kwlist in (('csv', csv_body, [{}]), ('tsv', csv_body, [{'delim': '\t'}]),
                            ('dif', dif_body, [{}]), ('slk', slk_body, [{}]),
                            ('prn', prn_body, [{}])):
        for kw in kwlist:
            for first in (1, 2, 8, 32, 64, 128, 256):
                for delta in (1, 8, 64, 1024):
                    later = first + delta
                    if later > 17000:
                        continue
                    name = 'tc_%s_%d_%d.%s' % (ext, first, later, ext)
                    with open(os.path.join(OUT, name), 'w', newline='') as f:
                        f.write(fn(first, later, **kw))
                    n += 1
    # ragged/quoted and long-cell variants on csv (the shape that reaches HrPushValue's text path)
    for first, later in ((3, 300), (1, 1024), (1600, 5), (255, 256), (256, 257), (1024, 1025)):
        with open(os.path.join(OUT, 'tc_csvq_%d_%d.csv' % (first, later)), 'w', newline='') as f:
            f.write(csv_body(first, later, rows=4, quote=True))
        n += 1
    # single very long cell after a wide header
    for ncols in (2, 64, 256):
        body = ','.join(cell(i) for i in range(ncols)) + '\r\n' + ('z' * 32767) + ',short\r\n'
        with open(os.path.join(OUT, 'tc_long_%d.csv' % ncols), 'w', newline='') as f:
            f.write(body)
        n += 1
    # formula-bearing cells (text carriers evaluate formulas without a security dialog)
    for ncols in (2, 32, 256):
        head = ','.join(cell(i) for i in range(ncols))
        body = head + '\r\n' + ','.join(['=1+1'] * ncols) + '\r\n' + head + '\r\n'
        with open(os.path.join(OUT, 'tc_form_%d.csv' % ncols), 'w', newline='') as f:
            f.write(body)
        n += 1
    print('carriers=%d dir=%s' % (n, OUT))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'corpus':
        build()
    else:
        print('usage: mk_textcols_corpus.py corpus [outdir]')
