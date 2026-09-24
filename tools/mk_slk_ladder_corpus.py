#!/usr/bin/env python3
"""Dense SYLK ladders for Excel's `.slk` loader (`HrLoadSylk@0x140705fb8` -> `sub_140706080`).

`.slk` is the text-format carrier that the armed page-heap sweep actually let Excel parse
(`.dif` carriers all reported opened=0 in run 35933599710, so nothing was concluded from them).
The SYLK record grammar declares geometry in the file itself, so every one of these numbers is
attacker-chosen:

  B;Y<rows>;X<cols>;D<r1> <c1> <r2> <c2>   sheet rectangle + display rectangle
  C;Y<row>;X<col>;K"value"                  first cell of a row carries Y, later cells carry only X
  C;X<col>;K"value"                         column index only (row inherited)
  W;N<width> / P;P<fmt> / F;P0;DG0G8;M285   widths / number format
  E                                         end of file

Ladders: column index across 0/1/16383/16384/16385/32768/65536/2^31/2^32-1, row index across the
1048576-row limit and beyond, D-rectangle larger than the declared rectangle, missing `E`,
repeated identical (Y,X) cells, negative and non-numeric indices, and `K` records whose quoted value
is longer than any row buffer the loader could have sized from the declared `X`.
"""
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else 'corpus_sk'
HEAD = ['ID;PWXL;N;E', 'P;PGeneral', 'F;P0;DG0G8;M285']


def doc(records, declared_rows=3, declared_cols=8, rect=None, tail_E=True, extra=None):
    out = list(HEAD)
    if rect is None:
        out.append('B;Y%d;X%d;D0 0 %d %d' % (declared_rows, declared_cols, declared_rows - 1, declared_cols - 1))
    else:
        out.append(rect)
    out.extend(records)
    if extra:
        out.extend(extra)
    if tail_E:
        out.append('E')
    return '\r\n'.join(out) + '\r\n'


def row(r, cols):
    recs = []
    for c in cols:
        recs.append('C;Y%d;X%d;K"c%d"' % (r, c, c) if c == cols[0] else 'C;X%d;K"c%d"' % (c, c))
    return recs


def build():
    os.makedirs(OUT, exist_ok=True)
    n = 0

    def emit(name, text):
        nonlocal n
        with open(os.path.join(OUT, name), 'w', newline='') as f:
            f.write(text)
        n += 1

    # 1) column index ladder, declared rectangle stays small
    for c in (0, 1, 2, 100, 255, 256, 257, 1024, 4095, 4096, 16382, 16383, 16384, 16385,
              20000, 32767, 32768, 65535, 65536, 262144, 1048576, 2147483647):
        emit('sk_col_%d.slk' % c, doc(row(1, [c]) + row(2, [1, 2]), declared_cols=8))
    # 2) row index ladder across the sheet row limit
    for r in (0, 1, 2, 3, 1000, 65536, 1048575, 1048576, 1048577, 2147483646, 2147483647):
        emit('sk_row_%d.slk' % r, doc(row(r, [1, 2, 3]) + row(2, [1]), declared_rows=4))
    # 3) declared X small but a long run of columns in one row (per-row growth)
    for ncols in (16, 64, 256, 1024, 2048, 4096, 8192, 16384):
        emit('sk_wide_%d.slk' % ncols, doc(row(1, list(range(1, ncols + 1))), declared_cols=4))
    # 4) many rows for a declared B;Y of 1..2
    for nrows in (64, 512, 4096, 20000):
        recs = []
        for r in range(1, nrows + 1):
            recs.extend(row(r, [1, 2, 3]))
        emit('sk_deep_%d.slk' % nrows, doc(recs, declared_rows=1, declared_cols=3))
    # 5) D rectangle beyond the declared one
    emit('sk_drect_big.slk', doc(row(1, [1, 2]), rect='B;Y2;X2;D0 0 100000 100000'))
    emit('sk_drect_neg.slk', doc(row(1, [1, 2]), rect='B;Y2;X2;D-1 -1 -2 -2'))
    emit('sk_drect_huge.slk', doc(row(1, [1, 2]), rect='B;Y2;X2;D0 0 2147483647 2147483647'))
    # 6) malformed / edge index spellings
    emit('sk_noe.slk', doc(row(1, [1, 2, 3]), tail_E=False))
    emit('sk_dup_cell.slk', doc(row(1, [1, 2]) + row(1, [1, 2]) * 400, declared_cols=2))
    emit('sk_noX.slk', '\r\n'.join(HEAD + ['B;Y3;X3;D0 0 2 2', 'C;Y1;K"a"', 'C;K"b"', 'E']) + '\r\n')
    emit('sk_neg_idx.slk', doc(row(1, [1]) + ['C;X-1;K"n1"', 'C;Y-1;X1;K"n2"'], declared_cols=2))
    emit('sk_nonnum_idx.slk', doc(row(1, [1]) + ['C;Xabc;K"s1"', 'C;Y9.9;X2;K"s2"'], declared_cols=2))
    emit('sk_semi_in_k.slk', doc(row(1, [1]) + ['C;X2;K"a;b;c;d;e;f;g;h"'], declared_cols=2))
    # 7) long K values against a 1-column declared rectangle
    for ln in (1024, 16383, 16384, 32768, 65536, 262144):
        emit('sk_longk_%d.slk' % ln, doc(['C;Y1;X1;K"%s"' % ('z' * ln), 'C;X2;K"tail"'], declared_cols=1))
    # 8) W/P/F record ladders (width and format tables are sized from the header column count)
    for ncols in (2, 8, 256, 4096):
        emit('sk_wide_w_%d.slk' % ncols, doc(row(1, list(range(1, ncols + 1))),
                                            declared_cols=2,
                                            extra=['W;N' + ';'.join(['80'] * ncols)]))
    emit('sk_p_long.slk', doc(row(1, [1, 2]), extra=['P;P' + 'G' * 4000]))
    print('carriers=%d dir=%s' % (n, OUT))


if __name__ == '__main__':
    build()
