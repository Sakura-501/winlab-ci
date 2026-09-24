#!/usr/bin/env python3
"""Count-vs-content mismatch carriers for Excel's text loaders (`.dif` / `.slk` / `.csv` / `.tsv`).

Why this file exists: `mk_textcols_corpus.py` varies *how many columns* the first row reports
against how many a later row reaches, which is the obj+96 (column count) vs obj+80/obj+88 (the two
arrays) question.  The other way a text loader's bookkeeping can disagree with its buffers is the
**declared** count inside the format itself:

  .dif  every data record is `<n>` followed by n `"value"\ntype` pairs.  Declaring n larger than the
        pairs that actually follow makes the reader keep pulling past the end of the record; declaring
        it smaller leaves tuples in the queue while the next record header is read as a count.
  .slk  `B;Y<rows>;X<cols>;D...` declares the sheet rectangle; `C;Y<r>;X<c>` addresses a cell inside
        it.  Cells outside the declared rectangle, or more rows than `Y`, are the dimension-vs-data
        mismatch.
  .csv  the column limit (16384) and the "first row says 1 column, next row says 16k" shape, which
        the ladder's deltas never crossed.

All carriers are written with CRLF and ASCII, the same shape Excel itself emits.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mk_textcols_corpus import csv_body, dif_body, slk_body, cell   # reuse the verified bodies

OUT = sys.argv[1] if len(sys.argv) > 1 else 'corpus_mm'


def dif_raw(lines):
    return '\r\n'.join(lines) + '\r\n'


def dif_tuples(vals):
    out = [str(len(vals))]
    for v in vals:
        out.append('"%s"' % v)
        out.append('1')
    return out


def dif_declared_count(rows_cols, declared_delta, tail_rows=3):
    """Header says `1,V,n`/`1,C,n` and `RxCy`; the data records then carry a count that is
    `declared_delta` larger (or smaller) than the tuples actually written."""
    ncols = rows_cols
    head = ['TABLE', '1,V,%d' % ncols, 'N', '1,C,%d' % ncols, 'R%dC%d' % (tail_rows + 1, ncols),
            '0,0', '%d,%d' % (ncols, ncols), 'R,D', '0,0']
    body = []
    for k in range(tail_rows):
        vals = ['r%dc%d' % (k, i) for i in range(ncols)]
        declared = max(1, ncols + declared_delta)
        body.append(str(declared))
        for v in vals:
            body.append('"%s"' % v)
            body.append('1')
    return dif_raw(head + body + ['E'])


def dif_short_trailing_tuple(delta):
    """Count is right but the last tuple's type line is missing (truncated record)."""
    ncols = 8
    lines = ['TABLE', '1,V,%d' % ncols, 'N', '1,C,%d' % ncols, 'R3C%d' % ncols, '0,0',
             '%d,%d' % (ncols, ncols), 'R,D', '0,0']
    vals = ['c%d' % i for i in range(ncols)]
    lines.append(str(ncols))
    for i, v in enumerate(vals):
        lines.append('"%s"' % v)
        if i < ncols - max(1, delta):
            lines.append('1')
    lines.append('E')
    return dif_raw(lines)


def slk_rect_mismatch(declared_rows, declared_cols, actual_rows, actual_cols, first_row_cols=None):
    """`B;Y..;X..` rectangle smaller than the cells actually emitted (and the reverse)."""
    out = ['ID;PWXL;N;E', 'P;PGeneral', 'F;P0;DG0G8;M285',
           'B;Y%d;X%d;D0 0 %d %d' % (declared_rows, declared_cols, declared_rows - 1, declared_cols - 1)]
    fc = first_row_cols if first_row_cols is not None else actual_cols
    for r in range(1, actual_rows + 1):
        n = fc if r == 1 else actual_cols
        for c in range(1, n + 1):
            if c == 1:
                out.append('C;Y%d;X1;K"c%d"' % (r, c))
            else:
                out.append('C;X%d;K"c%d"' % (c, c))
    out.append('E')
    return '\r\n'.join(out) + '\r\n'


def slk_row_index_beyond(row_index, cols=4):
    out = ['ID;PWXL;N;E', 'P;PGeneral', 'F;P0;DG0G8;M285', 'B;Y4;X%d;D0 0 3 %d' % (cols, cols - 1)]
    for r in (1, row_index):
        for c in range(1, cols + 1):
            out.append(('C;Y%d;X1;K"r%dc1"' % (r, c)) if c == 1 else ('C;X%d;K"r%dc%d"' % (c, r, c)))
    out.append('E')
    return '\r\n'.join(out) + '\r\n'


def build():
    os.makedirs(OUT, exist_ok=True)
    n = 0

    def emit(name, text):
        nonlocal n
        with open(os.path.join(OUT, name), 'w', newline='') as f:
            f.write(text)
        n += 1

    # ---- .dif : declared tuple count vs tuples actually written -------------------------------
    for ncols in (1, 2, 8, 32, 128, 256, 1024):
        for delta in (1, 2, 8, 64, 1024, 16384):
            emit('mm_dif_over_%d_%d.dif' % (ncols, delta), dif_declared_count(ncols, delta))
        for delta in (-1, -2, -8, -64):
            if ncols + delta >= 1:
                emit('mm_dif_under_%d_%d.dif' % (ncols, delta), dif_declared_count(ncols, delta))
    for delta in (1, 2, 3):
        emit('mm_dif_trunc_%d.dif' % delta, dif_short_trailing_tuple(delta))
    # the header column count itself disagrees with the data
    for hdr, real in ((8, 64), (64, 8), (1, 512), (255, 256), (256, 255), (16384, 16), (16, 16384)):
        lines = dif_body(hdr, real, rows=3).split('\r\n')
        emit('mm_dif_hdr_%d_%d.dif' % (hdr, real), '\r\n'.join(lines) + '\r\n' if not lines[-1] else '\r\n'.join(lines) + '\r\n')
    # ---- .slk : declared rectangle vs emitted cells ------------------------------------------
    for dr, dc, ar, ac in ((2, 4, 40, 4), (2, 4, 2, 200), (1, 1, 300, 1), (4, 4, 4, 3000),
                           (8, 8, 8, 16384), (1, 1, 1, 16385), (3, 3, 3, 64), (1, 2, 6, 2)):
        emit('mm_slk_rect_%d_%d_%d_%d.slk' % (dr, dc, ar, ac), slk_rect_mismatch(dr, dc, ar, ac))
    for r in (5, 8, 64, 1024, 65536, 1048576):
        emit('mm_slk_rowidx_%d.slk' % r, slk_row_index_beyond(r))
    for fc, ac in ((1, 4096), (2, 16384), (4096, 1)):
        emit('mm_slk_widewrap_%d_%d.slk' % (fc, ac), slk_rect_mismatch(2, 16, 3, ac, first_row_cols=fc))
    # ---- .csv : cross the 16384 column limit from a 1-column first row ------------------------
    for first, later in ((1, 4096), (1, 16383), (1, 16384), (1, 16385), (1, 20000),
                         (16384, 1), (2, 16384), (1, 32768)):
        emit('mm_csv_%d_%d.csv' % (first, later), csv_body(first, later, rows=2))
        emit('mm_tsv_%d_%d.tsv' % (first, later), csv_body(first, later, rows=2, delim='\t'))
    print('carriers=%d dir=%s' % (n, OUT))


if __name__ == '__main__':
    build()
