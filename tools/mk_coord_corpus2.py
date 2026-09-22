#!/usr/bin/env python3
"""Declared-dimension vs actually-supplied-record grid for the Excel text importers.

For each dimension field, sweep the declared value over a boundary list and, for each
declared value, sweep the real record count/coordinate around it (dec-2 .. dec+100, 0, 1).
That is the shape that turns "allocate from header" vs "fill from stream" into an
observable difference.

usage: mk_coord_corpus2.py <outdir> [max_cases]
"""
import os
import sys

MAXROW = 1048576
MAXCOL = 16384

BOUNDS = [0, 1, 2, 3, 8, 15, 16, 17, 32, 33, 63, 64, 65, 128, 129, 255, 256, 257,
          1024, 4095, 4096, 16383, 16384, 16385, 32767, 65535, 65536, 1048575,
          1048576, 1048577, 2147483646, 2147483647]

DELTAS = [-2, -1, 0, 1, 2, 5, 17, 100]


def w(d, name, text):
    p = os.path.join(d, name)
    open(p, 'w', encoding='utf-8', newline='').write(text)
    return p


def clamp(n, hi=2000):
    if n < 0:
        return 0
    return int(min(n, hi))


# ---------------------------------------------------------------- DIF
def dif(dec_r, dec_c, act_r, per_row):
    """V;<rows>;<cols> header, then act_r D; records each holding per_row[i] N; values."""
    head = 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;%d;%d\r\n' % (dec_r, dec_c)
    body = []
    for i in range(act_r):
        vals = ['N;%d' % (i * 7 + j) for j in range(max(0, per_row(i)))]
        body.append('D;%d\r\n' % i + '\r\n'.join(vals) + ('\r\n' if vals else ''))
    return head + ''.join(body) + 'E;E\r\n'


def dif_grid_rows():
    out = []
    for dec in BOUNDS:
        for dl in DELTAS + [0, 1]:
            act = clamp(dec + dl) if dl else dec
            if dl == 0 and dec not in (0, 3, 64, 16384, 1048577):
                continue
            name = 'dif_rows_d%06d_%+04d.dif' % (dec, dl)
            out.append((name, dif(dec, 4, act, lambda i: 4)))
    return out


def dif_grid_cols():
    out = []
    for dec in BOUNDS:
        for dl in DELTAS:
            act = clamp(dec + dl, 400)
            name = 'dif_cols_d%06d_%+04d.dif' % (dec, dl)
            # declared cols = dec, each row actually carries `act` values
            out.append((name, dif(6, dec, 6, (lambda k: (lambda i: k))(act))))
    return out


def dif_struct():
    out = []
    # D; row-id anomalies (declared 8 rows, 8 records, ids replaced)
    ids = {0: ['D;-1'], 1: ['D;999999999'], 2: ['D;0', 'D;0'], 3: ['D;5', 'D;4', 'D;3', 'D;2', 'D;1'],
           4: ['D;2147483647'], 5: ['D;0x10'], 6: ['D;'], 7: ['D;1e5'], 8: ['D; 3 ']}
    for k, repl in ids.items():
        body = []
        for i in range(8):
            rid = repl[min(i, len(repl) - 1)] if i < len(repl) else 'D;%d' % i
            body.append('%s\r\nN;%d\r\nN;%d\r\n' % (rid, i, i * 2))
        out.append(('dif_did_%02d.dif' % k,
                    'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;8;2\r\n' + ''.join(body) + 'E;E\r\n'))
    # per-row value count churn with a fixed declaration
    for tag, per in [('all_zero', lambda i: 0), ('one_over', lambda i: 3 + (i % 2)),
                     ('ramp', lambda i: min(i, 9)), ('big_jump', lambda i: 3 if i else 400),
                     ('only_last_big', lambda i: 400 if i == 7 else 3)]:
        body = []
        for i in range(8):
            vals = '\r\n'.join('N;%d' % v for v in range(per(i)))
            body.append('D;%d\r\n%s\r\n' % (i, vals))
        out.append(('dif_percol_%s.dif' % tag,
                    'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;8;3\r\n' + ''.join(body) + 'E;E\r\n'))
    # header anomalies
    hdrs = {'none': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\n',
            'neg': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;-1;-1\r\n',
            'neg2': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;-2147483648;2\r\n',
            'huge': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;99999999999;99999999999\r\n',
            'overflow': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;2147483648;2\r\n',
            'mul_overflow': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;65536;65536\r\n',
            'nonnum': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;x;y\r\n',
            'empty': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;\r\n',
            'one_field': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;8\r\n',
            'three_field': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;8;2;9\r\n',
            'dup_v': 'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;8;2\r\nV;2;8\r\n',
            'lf_only': 'TABLE,t,1.00,V1.00,0\nMF;\nNE;\nAD;\nV;8;2\n'}
    body = ''.join('D;%d\r\nN;1\r\nN;2\r\n' % i for i in range(8))
    for tag, h in hdrs.items():
        out.append(('dif_hdr_%s.dif' % tag, h + body + 'E;E\r\n'))
    # missing / duplicated terminators
    for tag, tail in [('no_e', ''), ('single_e', 'E;\r\n'), ('double', 'E;E\r\nE;E\r\n'),
                      ('after_partial', 'E;E\r\nD;0\r\nN;1\r\n'), ('early_e', 'E;E\r\n' + body)]:
        out.append(('dif_tail_%s.dif' % tag,
                    'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;8;2\r\n' + body + tail))
    # value records: type letters and long text
    for tag, val in [('long', 'N;' + '9' * 9000), ('nonnum', 'N;zzz'), ('empty', 'N;'),
                     ('exp', 'N;1e400'), ('negzero', 'N;-0'), ('quote', 'N;"a,b"'),
                     ('a_type', 'A;' + 'x' * 5000), ('mixed_type', 'T;1;2'),
                     ('shortrec', 'N;1;2;3')]:
        out.append(('dif_val_%s.dif' % tag,
                    'TABLE,t,1.00,V1.00,0\r\nMF;\r\nNE;\r\nAD;\r\nV;2;2\r\n'
                    'D;0\r\n%s\r\nN;5\r\nD;1\r\nN;6\r\nN;7\r\nE;E\r\n' % val))
    return out


# ---------------------------------------------------------------- SYLK
def slk(cells, dec=None, dims='B;1;1;8;8', tail=('W;N', 'P;M8', 'O;N', 'E')):
    head = ['ID;PW XL 2000 4', 'F;P0;DG0G8;M150']
    if dec:
        head.append(dec)
    return '\r\n'.join(head + list(cells) + [dims] + list(tail)) + '\r\n'


def slk_grid_y():
    out = []
    for dec in BOUNDS:
        for dl in DELTAS:
            y = dec + dl
            if y < 1:
                y = 1
            out.append(('slk_y_d%06d_%+04d.slk' % (dec, dl),
                        slk(['C;Y%d;X2;K%d' % (y, y % 97)], dims='B;1;2;8;8')))
    return out


def slk_grid_x():
    out = []
    for dec in [1, 2, 3, 16, 17, 255, 256, 257, 1023, 1024, 4095, 4096, 16382, 16383, 16384,
                16385, 16386, 65535, 65536, 2147483647]:
        for dl in [-2, -1, 0, 1, 2, 5, 100]:
            x = dec + dl
            if x < 1:
                x = 1
            out.append(('slk_x_d%06d_%+04d.slk' % (dec, dl),
                        slk(['C;Y2;X%d;K123' % x], dims='B;1;2;8;8')))
    return out


def slk_struct():
    out = []
    # duplicate / reversed / sparse coordinates within a declared block
    out.append(('slk_dup20.slk', slk(['C;Y3;X3;K%d' % i for i in range(20)], dims='B;1;3;8;8')))
    out.append(('slk_rev.slk', slk(['C;Y%d;X%d;K1' % (y, x) for y in range(30, 0, -1)
                                   for x in range(10, 0, -1)], dims='B;1;1;8;8')))
    out.append(('slk_sparse.slk', slk(['C;Y1;X1;K1', 'C;Y100000;X16384;K2',
                                       'C;Y1048576;X1;K3'], dims='B;1;1;8;8')))
    out.append(('slk_grid60.slk', slk(['C;Y%d;X%d;K%d' % (y, x, y * x)
                                       for y in range(1, 9) for x in range(1, 9)])))
    # B; declared dims vs present cells
    for tag, dims, cells in [
        ('b_zero', 'B;0;0;8;8', ['C;Y1;X1;K1']),
        ('b_small', 'B;1;1;8;8', ['C;Y%d;X%d;K1' % (y, x) for y in range(1, 6) for x in range(1, 6)]),
        ('b_big', 'B;100000;20000;8;8', ['C;Y1;X1;K1']),
        ('b_over', 'B;2;2;8;8', ['C;Y3;X3;K1']),
        ('b_neg', 'B;-1;-1;8;8', ['C;Y1;X1;K1']),
        ('b_huge', 'B;2147483647;2147483647;8;8', ['C;Y1;X1;K1']),
        ('b_nonnum', 'B;x;y;8;8', ['C;Y1;X1;K1']),
        ('b_missing', None, ['C;Y1;X1;K1']),
        ('b_only', 'B;4;4;8;8', []),
    ]:
        head = ['ID;PW XL 2000 4', 'F;P0;DG0G8;M150'] + (['C;%s' % c[2:] for c in []])
        body = cells
        s = '\r\n'.join(head + body + ([dims] if dims else []) + ['W;N', 'P;M8', 'O;N', 'E']) + '\r\n'
        out.append(('slk_%s.slk' % tag, s))
    # cell content extremes
    for tag, k in [('longstr', 'K"' + 's' * 32767 + '"'), ('overlong', 'K"' + 't' * 65600 + '"'),
                   ('unterm', 'K"abc'), ('huge_num', 'K9' * 400), ('neg', 'K-1'),
                   ('empty', 'K'), ('formula', 'K=1+1'), ('quoted_semi', 'K"a;b"'),
                   ('brackets', 'K[3]1'), ('multisemi', 'K;1;2;3')]:
        out.append(('slk_val_%s.slk' % tag,
                    slk(['C;Y1;X1;123', 'C;Y2;X2;%s' % k, 'C;Y3;X3;K7'], dims='B;1;1;8;8')))
    # record shape anomalies
    for tag, cells in [('no_k', ['C;Y1;X1']), ('x_before_y', ['C;X1;Y1;K5']),
                       ('bare_c', ['C;']), ('bad_letter', ['X;Y1;X1;K5']),
                       ('lower', ['c;y1;x1;k5']), ('extra_f', ['F;P0;DG0G8;M150'] * 30),
                       ('nul_in_rec', ['C;Y1;X1;K1\x002'])]:
        out.append(('slk_shape_%s.slk' % tag, slk(cells, dims='B;1;1;8;8')))
    # missing/odd stream terminators
    for tag, tail in [('no_e', ('W;N', 'P;M8', 'O;N')), ('early_e', ('E', 'C;Y1;X1;K1')),
                      ('double_e', ('E', 'E')), ('trunc_mid', ('E;C;Y1;X'))]:
        out.append(('slk_tail_%s.slk' % tag,
                    '\r\n'.join(['ID;PW XL 2000 4', 'F;P0;DG0G8;M150', 'C;Y1;X1;K1',
                                 'B;1;1;8;8'] + list(tail)) + '\r\n'))
    return out


# ---------------------------------------------------------------- PRN / CSV
def prn_csv():
    out = []
    for n in [1, 2, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 1000, 1024, 16383, 16384, 16385]:
        out.append(('prn_cols_%06d.prn' % n,
                    ','.join('c%d' % i for i in range(n)) + '\r\n1,2,3\r\n'))
    for n in [1, 3, 16, 17, 255, 256, 8192, 65535, 65536, 1048575, 1048576, 1048577]:
        out.append(('prn_wide_%08d.prn' % n, 'A' * n + ',1\r\n'))
    # CSV ragged rows around column boundaries
    for cols in [1, 2, 16, 17, 255, 256, 1024]:
        rows = ['r%d,%s' % (i, ','.join(str((i + j) % 10) for j in range((i % (cols + 1)))))
                for i in range(40)]
        out.append(('csv_ragged_%05d.csv' % cols, '\r\n'.join(rows) + '\r\n'))
    return out


def main():
    out = sys.argv[1]
    cap = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    os.makedirs(out, exist_ok=True)
    groups = [('rows', dif_grid_rows()), ('cols', dif_grid_cols()), ('struct', dif_struct()),
              ('sy', slk_grid_y()), ('sx', slk_grid_x()), ('ss', slk_struct()),
              ('pc', prn_csv())]
    # round-robin across groups so truncating with cap still covers every axis
    flat = []
    depth = max(len(i) for _, i in groups)
    for k in range(depth):
        for gname, items in groups:
            if k < len(items):
                flat.append((gname, items[k]))
    made = []
    for gname, (name, text) in flat:
        if cap and len(made) >= cap:
            break
        made.append(w(out, name, text))
    print('groups=%s per-group=%s' % ([g for g, _ in groups], [len(i) for _, i in groups]))
    # per-axis benign controls (must open clean; if a control does not open, that axis is invalid)
    w(out, 'xctrl_dif_ok.dif', dif(8, 3, 8, lambda i: 3))
    w(out, 'xctrl_slk_ok.slk', slk(['C;Y%d;X%d;K%d' % (y, x, y * x)
                                   for y in range(1, 9) for x in range(1, 9)]))
    # canonical minimal SYLK / DIF forms (the shape a working carrier is known to have)
    w(out, 'xctrl_slk_min.slk', 'ID;P\r\nC;Y1;X1;K1\r\nC;Y2;X2;K2\r\nE\r\n')
    w(out, 'xctrl_dif_min.dif', 'TABLE,t\r\nV;2;1\r\nD;0\r\nN;5\r\nD;1\r\nN;6\r\nE;E\r\n')
    w(out, 'xctrl_prn_ok.prn', 'a,b,c\r\n1,2,3\r\n')
    w(out, 'xctrl_csv_ok.csv', 'a,b,c\r\n1,2,3\r\n')
    print('cases=%d dir=%s' % (len(made), out))


if __name__ == '__main__':
    main()
