#!/usr/bin/env python3
"""`.eml` carriers for the real OUTLOOK.EXE parse pipeline under armed page heap.

Why this corpus exists: every Outlook-side instrument in this lab has driven a *specific exported
function* in a harness (OLMAPI32's `\fromhtml1` RTF engine through its allocator slot pair, MIMEDIR's
iCal/vCard parsers, OUTLMIME's `Ess*DecodeEx`) or opened `.msg` files.  Double-clicking an `.eml`
runs the whole in-product stack - RFC822 header parsing, transport-decoding, MIME tree building, the
S/Mime wrapper, and the HTML body importer - inside OUTLOOK.EXE, and `.eml` has no Protected View
(AGENTS 62 (6) matrix), so a page-heaped Outlook is the only instrument that sees all of it with the
product's own allocations.

Families (each file is a syntactically ordinary message with exactly one dimension pushed):
  bd<D>       boundary repeated/`multipart` nesting depth D
  bdl<N>      boundary string length N
  cml<A,B>    `Content-Length: A` header while the body is really B bytes (declared-vs-actual)
  qp<N>       quoted-printable body with N soft line breaks / odd `=` placements
  b64<N>      base64 body, length N, missing/extra padding, whitespace every 1..5 chars
  enc<N>      RFC2047 encoded-word in Subject with malformed padding of length N
  hdr<N>      one header whose value is N bytes (long `Content-Type` parameters, duplicates)
  rfc<N>      nested `message/rfc822` N deep
  tnef<N>     `application/ms-tnef` part whose declared length exceeds the supplied bytes
  smime<N>    `application/pkcs7-mime` wrapper around a small body
  html<N>     `text/html` body with `<img>`/`<table>`/attribute runs of length N
  ctl_*       a plain well-formed message (positive control the reader is alive)
"""
import os
import re
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else 'corpus_eml'
BOUND = "----=_NextPart_000_0000_01D8"


def wrap(parts, ctype='multipart/mixed', boundary=None, hdrs=None, mark='ctl'):
    # A unique Subject per carrier is the observer: Outlook keeps one process for many read windows,
    # so a window *title* containing the marker is the only per-file "this file parsed" signal.
    h = ['From: "Ann Example" <ann@example.invalid>', 'To: user@example.invalid',
         'Subject: GTMSG%sEND' % mark, 'Date: Tue, 23 Sep 2026 10:00:00 +0000',
         'MIME-Version: 1.0']
    for k, v in (hdrs or []):
        h.append('%s: %s' % (k, v))
    body = ''
    if boundary:
        h.append('Content-Type: %s; boundary="%s"' % (ctype, boundary))
        chunks = []
        for p in parts:
            chunks.append('--' + boundary + '\r\n' + p)
        chunks.append('--' + boundary + '--\r\n')
        body = '\r\n'.join(chunks)
    else:
        h.append('Content-Type: %s' % ctype)
        body = parts[0]
    return '\r\n'.join(h) + '\r\n\r\n' + body + '\r\n'


def leaf(text, ctype='text/plain', extra=None, encoding='7bit'):
    h = ['Content-Type: %s%s' % (ctype, ('; ' + extra) if extra else ''),
         'Content-Transfer-Encoding: %s' % encoding, '']
    return '\r\n'.join(h) + text


def nested(depth, inner):
    part = inner
    for _ in range(depth):
        part = leaf('', 'message/rfc822') + '\r\n' + wrap([part], boundary=BOUND + 'X')
    return wrap([part], boundary=BOUND)


def qp_body(n):
    lines = []
    for i in range(n):
        lines.append('a' * 70 + '=')
    return '\r\n'.join(lines) + '\r\n' + 'b' * 3


def b64_body(n, pad=True, ws=4):
    import base64
    raw = bytes((i * 7 + 3) & 0xFF for i in range(n))
    s = base64.b64encode(raw).decode()
    if not pad:
        s = s.rstrip('=')
    return '\r\n'.join(s[i:i + ws * 19] for i in range(0, len(s), ws * 19))


def main():
    os.makedirs(OUT, exist_ok=True)
    made = 0

    def emit(name, text):
        nonlocal made
        text = text.replace('GTMSGctlEND', 'GTMSG%sEND' % re.sub(r'[^A-Za-z0-9]', '', name.split('.')[0])[:24])
        with open(os.path.join(OUT, name), 'w', newline='') as fh:
            fh.write(text)
        made += 1

    emit('ctl_plain.eml', wrap([leaf('Hello.\r\n')], boundary=BOUND))
    for d in (1, 2, 3, 8, 20, 32, 40, 64, 100, 200):
        emit('bd_%04d.eml' % d, nested(d, leaf('deep\r\n')))
    for n in (8, 70, 75, 150, 500, 1000, 4000, 8192, 16384, 65536, 131072):
        emit('bdl_%06d.eml' % n, wrap([leaf('x\r\n')], boundary='B' * n))
    for a, b in ((100, 10), (10, 100), (0, 50), (50, 0), (76, 75), (76, 77),
                 (1000, 10), (10, 1000), (65536, 8), (8, 65536), (3, 3), (7, 1)):
        emit('cml_%06d_%06d.eml' % (a, b),
             wrap([leaf('y' * b), leaf('z' * b)], hdrs=[('Content-Length', str(a))], boundary=BOUND))
    for n in (1, 2, 3, 8, 64, 500, 4000, 20000):
        emit('qp_%06d.eml' % n, wrap([leaf(qp_body(n), encoding='quoted-printable')], boundary=BOUND))
    for n in (1, 2, 3, 60, 300, 3000, 30000):
        emit('b64_%06d_p.eml' % n, wrap([leaf(b64_body(n), encoding='base64')], boundary=BOUND))
        emit('b64_%06d_n.eml' % n, wrap([leaf(b64_body(n, pad=False), encoding='base64')], boundary=BOUND))
    for n in (4, 8, 75, 76, 77, 200, 1000, 5000):
        emit('enc_%06d.eml' % n, wrap([leaf('t\r\n')], boundary=BOUND,
                                      hdrs=[('X-Enc', '=?iso-8859-1?B?' + 'A' * n)]))
    for n in (100, 500, 1000, 4000, 16384, 65536, 131072, 262144):
        emit('hdr_%07d.eml' % n, wrap([leaf('t\r\n')], boundary=BOUND,
                                      hdrs=[('X-Long', 'v' * n), ('X-Long', 'w' * (n // 2))]))
    for n in (1, 2, 4, 8, 16, 24, 32, 64, 128):
        emit('rfc_%04d.eml' % n, nested(n, leaf('inner\r\n')))
    for n in (0, 1, 2, 8, 64, 512):
        emit('tnef_%05d.eml' % n, wrap(
            [leaf('q' * n, 'application/ms-tnef', 'name="winmail.dat"', 'base64')], boundary=BOUND))
    for n in (1, 2, 4, 16, 64, 512, 4096):
        emit('smime_%05d.eml' % n, wrap(
            [leaf(b64_body(n), 'application/pkcs7-mime', 'smime-type="signed-data"', 'base64')],
            boundary=BOUND))
    for n in (1, 2, 8, 64, 512, 4000, 20000, 100000):
        html = ('<html><body><table><tr>' + '<td>%s</td>' % ('d' * 20) * 4 + '</tr></table>'
                + '<img src="http://example.invalid/%s">' % ('p' * n)
                + '<div ' + ' '.join('a%d="%s"' % (i, 'v' * min(n, 64)) for i in range(min(n, 500))) + '>x</div>'
                + '</body></html>')
        emit('html_%06d.eml' % n, wrap([leaf(html, 'text/html')], boundary=BOUND))
    tot = sum(os.path.getsize(os.path.join(OUT, f)) for f in os.listdir(OUT))
    print('carriers=%d bytes=%d out=%s' % (made, tot, OUT))
    for probe in ('ctl_plain.eml', 'bdl_065536.eml', 'hdr_00262144.eml', 'html_0100000.eml'):
        p = os.path.join(OUT, probe)
        print('probe %s %s' % (probe, os.path.getsize(p) if os.path.exists(p) else 'MISSING'))


if __name__ == '__main__':
    main()
