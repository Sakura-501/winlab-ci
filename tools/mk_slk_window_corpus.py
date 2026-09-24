#!/usr/bin/env python3
"""SYLK carriers sized against the two buffers `HrLoadSylk`'s body allocates.

Measured in `findings/MSRC/M365-Insider/excel-formula-compiler-20260920/work/
excel_a64_dif_textloaders_decomp.txt` (STATE office-mem-lifetime-20260922 §27.2): the body at
`sub_140706080` does

    _FHpAllocCore(&v9 , 0x40CE)   -> 16,590 bytes, cursor v9+1, three sentinels at v9+16588
    _FHpAllocCore(&v10, 0x81A2)   -> 33,186 bytes  (= 2 x 16,590 + 6, i.e. a wide mirror)

Both sizes are compile-time constants while the record lengths come from the file, so the
interesting region is the few bytes around 16,588 and 33,186 - which the power-of-two ladder in
`mk_slk_ladder_corpus.py` brackets (16,384 / 65,536) without ever landing in it.

Ladders (one carrier per file, everything else a byte-identical valid document):
  k<N>   `C;Y1;X1;K"<payload>"` whose record line is exactly N bytes (no CRLF counted)
  kc<N>  same, but N counts the CRLF terminator too
  f<N>   `C;Y1;X1;K=<payload>` unquoted formula text, line = N bytes
  p<N>   `P;P<format text>` number-format record, line = N bytes
  w<N>   `W;N<payload>` column-width record, line = N bytes
  u<N>   UTF-16LE (BOM + `ID;PWXL;N;E`) variant, record line = N *characters*
  m<N>   payload bytes 0x80..0xFF (ANSI->OEM/locale expansion of the 1:1 copy assumption)
  ctl_*  one tiny valid document and one 4,000-byte document (well inside both windows)
"""
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else 'corpus_sw'

# the two windows as the loader sizes them
ANSI = 16590
ANSI_USE = 16588
WIDE = 33186

ladder_ansi = list(range(ANSI - 12, ANSI + 12)) + list(range(ANSI_USE - 6, ANSI_USE + 7))
ladder_wide = list(range(WIDE - 10, WIDE + 11, 2)) + [WIDE - 1, WIDE + 1]
ladder_coarse = [ANSI // 2, ANSI + 64, ANSI + 4096, WIDE, WIDE + 8192, 65536, 131072]

HEAD = ['ID;PWXL;N;E', 'P;PGeneral', 'F;P0;DG0G8;M285']
TAIL = ['E']


def body(records):
    return '\r\n'.join(HEAD + [
        'B;Y3;X8;D0 0 2 7'] + records + TAIL) + '\r\n'


def line_len(prefix, suffix):
    return len(prefix) + len(suffix)


def mk_k(n, pad='A'):
    pre = 'C;Y1;X1;K"'
    pay = pad * max(0, n - len(pre) - 1)
    return body([pre + pay + '"'])


def mk_kc(n, pad='A'):
    pre = 'C;Y1;X1;K"'
    pay = pad * max(0, n - len(pre) - 1 - 2)
    return body([pre + pay + '"'])


def mk_f(n):
    pre = 'C;Y1;X1;K='
    pay = '+' * (n - len(pre) - 1) + '1'
    return body([pre + pay])


def mk_p(n):
    pre = 'P;P'
    pay = '#' * (n - len(pre))
    return body([pre + pay, 'C;Y1;X1;K"1"'])


def mk_w(n):
    pre = 'W;N'
    pay = ' ' * (n - len(pre) - 1) + '8'
    return body([pre + pay, 'C;Y1;X1;K"1"'])


def mk_m(n):
    pre = 'C;Y1;X1;K"'
    pay = ''.join(chr(0x80 + (i % 0x40)) for i in range(max(0, n - len(pre) - 1)))
    return body([pre + pay + '"']).encode('latin-1')


def mk_u(n):
    txt = body(['C;Y1;X1;K"' + 'A' * max(0, n - 11) + '"'])
    return ('﻿' + txt).encode('utf-16-le')


def mk_wi(n, entry='8'):
    """`W;N` with ';'-separated numeric entries so the *record line* is exactly n bytes and the
    record stays syntactically valid at lengths where `K`/`P` are refused by the loader."""
    pre = 'W;N'
    unit = len(entry) + 1          # '8;'
    k = max(1, (n - len(pre) + 1) // unit)
    line = pre + ';'.join([entry] * k)
    while len(line) < n:
        k += 1
        line = pre + ';'.join([entry] * k)
        if len(line) > n:
            break
    if len(line) > n:              # trim by shortening the last entry's padding
        line = line[:n] if line[n - 1] == ';' else line[:n].rstrip(';')
    return body([line, 'C;Y1;X1;K"1"'])


def mk_wic(k, entry='8'):
    """`W;N` with exactly k ';'-separated width entries - the count that reaches the +0x88 list
    whose consumer shifts it by 6 bits (STATE \u00a731: lsl w1, w8, #6)."""
    return body(['W;N' + ';'.join([entry] * k), 'C;Y1;X1;K"1"'])


def write(name, data):
    p = os.path.join(OUT, name)
    if isinstance(data, (bytes, bytearray)):
        with open(p, 'wb') as fh:
            fh.write(data)
    else:
        with open(p, 'w', newline='') as fh:
            fh.write(data)
    return p


def main():
    os.makedirs(OUT, exist_ok=True)
    made = 0
    for n in sorted(set(ladder_ansi + ladder_coarse)):
        write('sw_k_%06d.slk' % n, mk_k(n)); made += 1
    for n in sorted(set(ladder_ansi)):
        write('sw_kc_%06d.slk' % n, mk_kc(n)); made += 1
    for n in sorted(set(ladder_ansi[::3] + ladder_wide)):
        write('sw_f_%06d.slk' % n, mk_f(n)); made += 1
    for n in sorted(set(ladder_ansi[::3] + ladder_wide)):
        write('sw_p_%06d.slk' % n, mk_p(n)); made += 1
    for n in sorted(set(ladder_ansi[::4] + ladder_wide)):
        write('sw_w_%06d.slk' % n, mk_w(n)); made += 1
    for n in sorted(set(ladder_ansi[::2])):
        write('sw_m_%06d.slk' % n, mk_m(n)); made += 1
    for n in sorted(set(ladder_ansi + ladder_wide)):
        write('sw_u_%06d.slk' % n, mk_u(n)); made += 1
    for n in sorted(set(ladder_ansi + ladder_wide + ladder_coarse)):
        write('sw_wi_%06d.slk' % n, mk_wi(n)); made += 1
    for k in (2, 100, 1000, 4095, 4096, 4097, 8191, 8192, 16382, 16383, 16384, 16385, 32767,
              32768, 65535, 65536, 131072):
        write('sw_wic_%06d.slk' % k, mk_wic(k)); made += 1
    write('sw_ctl_small.slk', mk_k(40)); made += 1
    write('sw_ctl_4000.slk', mk_k(4000)); made += 1
    tot = sum(os.path.getsize(os.path.join(OUT, f)) for f in os.listdir(OUT))
    print('carriers=%d bytes=%d windows ansi=%d use=%d wide=%d out=%s'
          % (made, tot, ANSI, ANSI_USE, WIDE, OUT))
    for probe in (ANSI - 1, ANSI, ANSI + 1, ANSI_USE, WIDE):
        print('ladder_has_%d=%s' % (probe, probe in set(ladder_ansi + ladder_wide)))


if __name__ == '__main__':
    main()
