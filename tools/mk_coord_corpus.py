#!/usr/bin/env python3
"""Wave 2: text carriers whose declared dimensions disagree with actual content.

Axes not covered by mk_dde_corpus.py (which only varied text length):
  * DIF  V;<rows>;<cols> header vs. number/width of D;/N; records actually written
  * DIF  rows/cols past the declared count, duplicated D; row ids, out-of-order rows
  * SYLK C;Y<row>;X<col> coordinates past 16384 / past 1048576, reversed order, duplicates
  * SYLK B;/F; dimension records that disagree with the cells present
  * truncated stream right after a partial cell record
  * .prn fixed-width lines whose field count exceeds the declared format width

usage: mk_coord_corpus.py <outdir>
"""
import os
import sys

MAXROW = 1048576
MAXCOL = 16384


def w(d, name, text):
    p = os.path.join(d, name)
    open(p, 'w', encoding='utf-8', newline='').write(text)
    return p


def dif(rows, cols, body_rows):
    head = 'TABLE,dimensionprobe,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;%d;%d\r\n' % (rows, cols)
    return head + body_rows + 'E;E\r\n'


def dif_row(ridx, values):
    out = ['D;%d' % ridx]
    for v in values:
        out.append('N;%s' % v)
    return '\r\n'.join(out) + '\r\n'


def slk(lines_cells, dims='B;1;1;8;8', tail=None, fline='F;P0;DG0G8;M150'):
    head = ['ID;PW XL 2000 4', fline]
    body = []
    for rec in lines_cells:
        body.append(rec)
    tail_recs = tail if tail is not None else ['W;N', 'P;M8', 'O;N', 'E']
    return '\r\n'.join(head + body + [dims] + tail_recs) + '\r\n'


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    made = []

    # --- DIF: declared vs actual row/col counts
    for dec_r, act_r, dec_c, act_c, tag in [
        (1, 40, 1, 3, 'less_rows'),
        (50, 5, 5, 2, 'more_rows'),
        (3, 3, 1, 12, 'more_cols'),
        (3, 3, 12, 1, 'less_cols'),
        (0, 6, 0, 4, 'zero_decl'),
        (1, 6, 2, 2, 'one_decl'),
        (MAXROW, 3, MAXCOL, 2, 'huge_decl'),
        (MAXROW + 5, 3, MAXCOL + 5, 2, 'over_decl'),
    ]:
        body = ''.join(dif_row(i + 1, ['v%d_%d' % (i, j) for j in range(act_c)]) for i in range(act_r))
        made.append(w(out, 'dif_%s.csv' % tag, dif(dec_r, dec_c, body)))

    # duplicated / out-of-order / negative row ids
    for tag, ids in [('dup', [1, 1, 2, 2, 2, 3]), ('rev', [9, 7, 5, 3, 1]),
                     ('zero', [0, 1, 2]), ('neg', [-1, 1, -5, 2]),
                     ('huge', [1, MAXROW, 2, MAXROW + 100, 3]),
                     ('skip', [1, 500, 5000, 100000])]:
        body = ''.join(dif_row(i, ['x' * 4] * 2) for i in ids)
        made.append(w(out, 'difid_%s.csv' % tag, dif(10, 4, body)))

    # ragged rows: differing value counts inside one file
    body = dif_row(1, ['a'] * 12) + dif_row(2, ['b']) + dif_row(3, ['c'] * 30) + dif_row(4, ['d'] * 3)
    made.append(w(out, 'difrag.csv', dif(4, 8, body)))

    # long values inside a declared-small grid + formula cells
    body = dif_row(1, ['=SUM(1,2)', 'A' * 500]) + dif_row(2, ['=1+1', 'B' * 4000])
    made.append(w(out, 'difmix.csv', dif(2, 2, body)))

    # truncated right after a partial record
    full = dif(4, 4, dif_row(1, ['a', 'b']) + dif_row(2, ['c', 'd']))
    for cut in (0.5, 0.8, 0.95):
        made.append(w(out, 'difcut_%d.csv' % int(cut * 100), full[:int(len(full) * cut)]))

    # --- SYLK: coordinates and dimension disagreement
    cells = []
    for i, (y, x) in enumerate([(1, 1), (1, MAXCOL), (2, MAXCOL + 1), (MAXROW, 1),
                                (MAXROW + 1, 3), (3, 70000), (5, 2), (5, 2)]):
        cells.append('C;Y%d;X%d;K"s%d"' % (y, x, i))
    made.append(w(out, 'slkcoord.csv', slk(cells)))
    made.append(w(out, 'slkbounds.csv', slk(cells, dims='B;1;1;2;2')))
    made.append(w(out, 'slkbbig.csv', slk(cells, dims='B;1;1;16384;1048576')))
    made.append(w(out, 'slkdim.csv', slk(cells, fline='F;P0;DG0G8;M150;W8')))
    made.append(w(out, 'slktail0.csv', slk(cells, tail=['W;N'])))
    made.append(w(out, 'slknotrail.csv', '\r\n'.join(['ID;PW XL 2000 4', 'F;P0;DG0G8;M150'] + cells) + '\r\n'))
    made.append(w(out, 'slkhalf.csv', '\r\n'.join(['ID;PW XL 2000 4', 'C;Y2;X3;K'] ) + '\r\nC;Y3;X'))
    made.append(w(out, 'slkmany.csv', slk(['C;Y%d;X1;K"c%d"' % (i, i) for i in range(1, 900)])))
    made.append(w(out, 'slkwide.csv', slk(['C;Y1;X%d;K"w%d"' % (i, i) for i in range(1, 400)])))
    dde_cell = 'C;Y3;X3;K"=notepad|' + chr(39) + 'TOPIC' + chr(39) + '!A0"'
    made.append(w(out, 'slkformula.csv', slk(['C;Y1;X1;K"=SUM(1,2)"',
                                             'C;Y2;X2;K"=%s"' % ('A' * 300),
                                             dde_cell])))

    # --- PRN: field counts past the declared width, overlong lines
    for tag, line in [('long', 'A' * 9000), ('tabs', '\t'.join('f%d' % i for i in range(500))),
                      ('commas', ','.join('c%d' % i for i in range(500))),
                      ('quotes', '"' + 'x' * 4000 + '"'),
                      ('mixed', '1,"a,b",2,' + 'z' * 2000)]:
        made.append(w(out, 'prn_%s.prn' % tag, line + '\r\n' + 'tail,2,3\r\n'))

    # --- CSV: row/col shape extremes and per-line field-count churn
    rows = ['a,b,c,d']
    for i in range(1, 300):
        rows.append(','.join(str(i) * ((i % 40) + 1) for _ in range((i % 120) + 1)))
    made.append(w(out, 'csv_churn.csv', '\r\n'.join(rows) + '\r\n'))
    made.append(w(out, 'csv_maxcol.csv', ','.join('c%d' % i for i in range(1, MAXCOL + 1)) + '\r\n'))
    made.append(w(out, 'csv_overcol.csv', ','.join('c%d' % i for i in range(1, MAXCOL + 400)) + '\r\n'))
    made.append(w(out, 'csv_maxrow.csv', '\r\n'.join('r%d,1' % i for i in range(1, 60000)) + '\r\n'))
    print('cases=%d dir=%s' % (len(made), out))


if __name__ == '__main__':
    main()
