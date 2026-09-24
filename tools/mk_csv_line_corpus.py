#!/usr/bin/env python3
"""`.csv`/`.txt` carriers whose *record line* length sits on the two fixed windows.

The SYLK loader body (`sub_140706080`, STATE office-mem-lifetime-20260922 §27.2) sizes its line
buffer with compile-time constants 0x40CE=16,590 (usable to +16,588) and 0x81A2=33,186, and the
record scanner that walks it (`sub_141C04C70`, §31) lives on a shared `0x141C0xxxx` page rather
than inside the SYLK-specific `0x140705xxx-0x140712xxx` block - so the same window shape is worth
probing on the carrier that has never failed to open zero-click in this lab (`.csv`/`.txt`, 2 s to a
document window with MOTW, STATE §27.1/§29.2).

Earlier Excel corpora walked the *number of columns* (`mk_textcols_corpus.py`, `mk_textcount_mismatch_corpus.py`)
which the loader caps at 16,384 by refusing the whole file (run 35943689154 `unopened` list), so the
per-line byte dimension is unprobed.

Families (one carrier per file; every other record identical):
  cl<N>      `a,b,c` + one row whose *single unquoted field* is N bytes long (line = N)
  cq<N>      same but the long field is quoted (`"aaa..."`) - exercises the quote/escape copy path
  cn<N>      N rows of `1,2,3` (aggregate-line dimension: the buffer that holds many records)
  cd<N>      a delimiter-dense line: `1,1,1,...` with N commas (line = 2N-1)
  ct<N>      `.txt` tab-separated twin of cl<N>
  ctl_*      a tiny valid file and a 4,000-byte field (inside both windows)
Ladder values centre on 16,588/16,590 and 33,186 with single-byte steps, plus the 65,536/131,072/
262,144 rungs and the 16,384/16,385 column-cap boundary.
"""
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else 'corpus_cl'
ANSI = 16590
ANSI_USE = 16588
WIDE = 33186

ladder = (list(range(ANSI - 10, ANSI + 11)) + list(range(ANSI_USE - 5, ANSI_USE + 6))
          + list(range(WIDE - 8, WIDE + 9, 2)) + [WIDE - 1, WIDE + 1]
          + [255, 256, 257, 1023, 1024, 1025, 4095, 4096, 8191, 8192,
             16383, 16384, 16385, 32767, 32768, 65536, 131072, 262144])
ladder = sorted(set(ladder))

HEAD = ['alpha,beta,gamma']


def one_line(n, quote=False, sep=','):
    """A header line plus one data line whose single field is padded so the data line is n bytes."""
    field = 'a' * max(0, n)
    if quote:
        field = '"' + 'a' * max(0, n - 2) + '"'
    return '\r\n'.join(HEAD + [field]) + '\r\n'


def delim(n):
    return '\r\n'.join(HEAD + ['1' + ',1' * (n - 1)]) + '\r\n'


def many(n):
    return '\r\n'.join(HEAD + ['1,2,3'] * n) + '\r\n'


def main():
    os.makedirs(OUT, exist_ok=True)
    made = 0
    for n in ladder:
        write('cl_%06d.csv' % n, one_line(n)); made += 1
    for n in ladder:
        write('cq_%06d.csv' % n, one_line(n, quote=True)); made += 1
    for n in [x for x in ladder if x <= 70000]:
        write('cd_%06d.csv' % n, delim(n)); made += 1
    for n in [x for x in ladder if x <= 70000]:
        write('cn_%06d.csv' % n, many(n)); made += 1
    for n in [x for x in ladder if x % 3 == 0]:
        write('ct_%06d.txt' % n, one_line(n, sep='\t').replace(',', '\t')); made += 1
    write('ctl_small.csv', one_line(6)); made += 1
    write('ctl_4000.csv', one_line(4000)); made += 1
    tot = sum(os.path.getsize(os.path.join(OUT, f)) for f in os.listdir(OUT))
    print('carriers=%d bytes=%d windows ansi=%d use=%d wide=%d out=%s'
          % (made, tot, ANSI, ANSI_USE, WIDE, OUT))
    for probe in (ANSI - 1, ANSI, ANSI_USE, WIDE, 16384, 16385):
        fn = os.path.join(OUT, 'cl_%06d.csv' % probe)
        if os.path.exists(fn):
            b = open(fn, 'rb').read()
            line = b.split(b'\r\n')[1]
            print('probe %d -> data-line bytes=%d file=%d' % (probe, len(line), len(b)))
        else:
            print('probe %d MISSING' % probe)


def write(name, text):
    with open(os.path.join(OUT, name), 'w', newline='') as fh:
        fh.write(text)


if __name__ == '__main__':
    main()
