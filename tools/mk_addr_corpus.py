r"""RFC822 address-string corpus for OUTLMIME's exported MimeOleParseRfc822Address.

Output file format (one record per case):  "<len>\n<bytes>\n"  (bytes may contain any value
except the record reader stops at the first '\n' after len bytes, so embedded newlines are fine).

The shapes here target what the parser's fixed stack objects can absorb: a 128-entry
array plus terminator and three 256-byte inline CByteBuffer seeds, so counts and token
lengths sit exactly on 63/64/127/128/129/255/256/257 boundaries, with group syntax,
nested comments, quoted-pair runs, encoded words, and unbalanced terminators.
"""
import os, sys, base64, random


def rec(s):
    b = s if isinstance(s, bytes) else s.encode('utf-8', 'surrogateescape')
    return f"{len(b)}\n".encode() + b + b"\n"


def build(seed=11, extra=0):
    rnd = random.Random(seed)
    out = []
    at = lambda i: f"u{i}@example.com"
    # address-count boundaries (the 128+terminator array)
    for n in [1, 2, 3, 15, 16, 31, 32, 63, 64, 65, 95, 96, 100, 127, 128, 129, 130, 200, 512, 1000]:
        out.append(rec(','.join(at(i) for i in range(n))))
        out.append(rec(';'.join(at(i) for i in range(n))))
        out.append(rec(', '.join(f'Name{i} <{at(i)}>' for i in range(n))))
    # token-length boundaries across the 256-byte inline buffers
    for L in [1, 2, 63, 64, 127, 128, 129, 250, 254, 255, 256, 257, 300, 511, 512, 1000, 4095, 4096, 8192]:
        out.append(rec('"' + 'a' * L + '"@example.com'))
        out.append(rec('user' + 'a' * L + '@example.com'))
        out.append(rec('a' + 'b' * L + '@' + 'c' * L + '.com'))
        out.append(rec('(' + 'x' * L + ') real@example.com'))
        out.append(rec('Friendly ' + 'y' * L + ' <z@example.com>'))
        out.append(rec('=?utf-8?B?' + base64.b64encode(b'x' * L).decode() + '?= <q@example.com>'))
    # structural abuse
    S = ['"' * 3 + 'a@b.c', 'a@b.c\\', '"unterminated@x', '(comment without end', 'a@(b@c)@d',
         ':;', ',', ',,', ';;;', '<>', '<a@b', 'a@b>', '<[1.2.3.4]>', 'grp:;<a@b>;', 'grp:a@b,(c@d);',
         'a@b (c (d (e (f))))', 'a\\@b@c', '"a\\\\\\\\\\\\"@b', 'x=' * 400, 'a%41b@c', 'a%00b@c',
         'from:sent:a@b', '<a@b>,<c@d>', 'a@b.c (', ' a@b.c ', '@', '@@', 'a@', '@b', '.@.',
         'x' * 100 + '@' + 'y' * 100 + '.' + 'z' * 100,
         '=?x-unknown?Q?=FF=FE?= <a@b>', '=?utf-8?q?=C3=28?= <a@b>', '=?ISO-8859-1?B?/w==?= <a@b>']
    for s in S:
        out.append(rec(s))
    # CRLF folding and control bytes inside phrases
    for pat in [b'a@b.c\r\n (folded)', b'"q\r\nuoted"@b.c', b'x\x01y\x02@b.c', b'\xc3\x28@b.c',
                b'\xff\xfe@b.c', b'a@b.c;(nested (a (b (c (d (e))))))', b'[' * 200 + b'a@b.c']:
        out.append(rec(pat))
    # random combinatorial fuzz over the alphabet the parser switches on
    alpha = b'ab.@"()<>:,;\\ \x09=\xc3-/[]%0123456789:;<>@.[]()"'
    for i in range(1400 + extra):
        n = rnd.randint(1, 400)
        out.append(rec(bytes(rnd.choice(alpha) for _ in range(n))))
    return b''.join(out), len(out)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '/tmp/addr.txt'
    extra = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    blob, n = build(extra=extra)
    open(out, 'wb').write(blob)
    print('records', n, 'bytes', len(blob), '->', out)
