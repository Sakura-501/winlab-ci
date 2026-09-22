#!/usr/bin/env python3
"""Wrap each TNEF record into an .eml so OUTLMIME's own importer (ImportTNEF) reaches
OLMAPI32's property-extraction loop the way receiving a winmail.dat message does.

Two shapes per record:
  T<name>.eml  - multipart with a base64 application/x-ms-tnef part named winmail.dat
  S<name>.eml  - the message itself declared as TNEF-encapsulated (single-part, base64 body)
Plus one benign control pair so a run where nothing imports is visible as such.
"""
import base64
import os
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "/tmp/tnefmix.txt"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/emlcorpus"

data = open(SRC, "rb").read()
recs = []
off = 0
while off < len(data):
    e = data.index(b"\n", off)
    ln = int(data[off:e])
    body = data[e + 1:e + 1 + ln]
    recs.append(body)
    off = e + 1 + ln
    if off < len(data) and data[off] == 10:
        off += 1

names = []
try:
    for line in open(SRC.replace(".txt", "_names.txt")):
        names.append(line.rstrip("\n").split("\t")[1])
except Exception:
    names = ["r%d" % i for i in range(len(recs))]

BND = "----=_NextPart_000_0001_TNEFEMU"


def hdr(ctype_extra=""):
    return ("From: =?utf-8?B?VGVzdCBTZW5kZXI=?= <sender@example.com>\r\n"
            "To: recipient@example.com\r\n"
            "Subject: tnef import probe\r\n"
            "Date: Tue, 22 Sep 2026 12:00:00 +0000\r\n"
            "Message-ID: <tnefprobe-%d@example.com>\r\n"
            "MIME-Version: 1.0\r\n" % (len(recs)))


def multipart(blob):
    b = base64.b64encode(blob).decode()
    b = "\r\n".join(b[i:i + 76] for i in range(0, len(b), 76))
    return (hdr() +
            'Content-Type: multipart/mixed; boundary="%s"\r\n\r\n' % BND +
            "--%s\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n"
            "plain body for the import probe\r\n" % BND +
            "--%s\r\n"
            "Content-Type: application/x-ms-tnef; name=\"winmail.dat\"\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "Content-Disposition: attachment; filename=\"winmail.dat\"\r\n\r\n" % BND +
            b + "\r\n--%s--\r\n" % BND)


def singlepart(blob):
    b = base64.b64encode(blob).decode()
    b = "\r\n".join(b[i:i + 76] for i in range(0, len(b), 76))
    return (hdr() +
            "Content-Type: application/x-ms-tnef; name=\"winmail.dat\"\r\n"
            "Content-Transfer-Encoding: base64\r\n"
            "Content-Disposition: attachment; filename=\"winmail.dat\"\r\n\r\n" +
            b + "\r\n")


os.makedirs(OUT, exist_ok=True)
n = 0
for i, (nm, blob) in enumerate(zip(names, recs)):
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in nm)[:60]
    for pfx, fn in (("T", multipart), ("S", singlepart)):
        p = os.path.join(OUT, "%s%s_%d.eml" % (pfx, safe, i))
        with open(p, "wb") as f:
            f.write(fn(blob).encode("latin-1", "replace"))
        n += 1

# benign controls: a plain mail and a well-formed TNEF (record 0 is the baseline in the corpus)
with open(os.path.join(OUT, "Zbenign_plain.eml"), "wb") as f:
    f.write((hdr() + "Content-Type: text/plain; charset=us-ascii\r\n\r\nnothing to import\r\n").encode())
n += 1
print("eml=%d -> %s" % (n, OUT))
