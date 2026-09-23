#!/usr/bin/env python3
"""Dense single-quantity MIME (.eml / .mht) corpus for the MIMEDIR parser channel.

mmv.exe mode 9 feeds a file to the CLSID_Parser object, whose extension list already includes .eml and
.mht, so the whole MIME structure parser (boundary scanning, per-part header decoding, transfer-encoding
decoders) runs in-process. The existing corpora for that channel were randomised; this one walks one
quantity at a time over a dense range with the rest of the document well-formed, which is what catches a
copy loop that overshoots only for particular remainders and what makes a fault attributable to one number.

Axes
  bnd_<L>    boundary token length
  par_<N>    number of parts in one multipart
  dep_<N>    nested multipart depth
  hd_<L>     header value length (unfolded, then folded at 74/75/76)
  prm_<L>    a single header parameter value length (filename=)
  qp_<L>     quoted-printable body length with soft line breaks
  b64_<L>    base64 body length
  ew_<L>     RFC 2047 encoded-word length in a header
  enc_<L>    uuencoded attachment payload length
  ct_<x>     Content-Type with an oversized / odd charset and boundary
"""
import base64
import os
import quopri
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "mimededense"
DENSE = list(range(1, 121))
EDGE = [127, 128, 129, 255, 256, 257, 511, 512, 1023, 1024, 4095, 4096]
os.makedirs(OUT, exist_ok=True)
made = 0


def put(name, text):
    global made
    open(os.path.join(OUT, name), "wb").write(text.replace("\n", "\r\n").encode("latin-1", "replace"))
    made += 1


def hdr(ctype, extra=""):
    return ("MIME-Version: 1.0\nFrom: dense@example.invalid\nTo: you@example.invalid\n"
            "Subject: dense case\nDate: Tue, 23 Sep 2026 00:00:00 +0000\n" + extra + ctype + "\n")


def multipart(boundary, parts, extra_hdr=""):
    b = ["--" + boundary]
    for p in parts:
        b.append("Content-Type: text/plain; charset=us-ascii" + extra_hdr)
        b.append("Content-Transfer-Encoding: 7bit")
        b.append("")
        b.append(p)
        b.append("")
    b.append("--" + boundary + "--")
    b.append("")
    return hdr('Content-Type: multipart/mixed; boundary="' + boundary + '"\n',
               "Content-Transfer-Encoding: binary\n") + "\n".join(b)


# 1. boundary length
for L in DENSE + EDGE[:8]:
    bd = "B" * L
    put("bnd_%05d.eml" % L, multipart(bd, ["hello", "world"]))
# 2. part count
for N in DENSE + [127, 128, 129, 255, 256]:
    put("par_%05d.eml" % N, multipart("===boundary===", ["part %d" % i for i in range(N)]))
# 3. nesting depth
for N in DENSE[:60] + [63, 64, 65, 127, 128]:
    def nest(k):
        if k == 0:
            return "Content-Type: text/plain\n\nleaf\n"
        inner = nest(k - 1)
        return ("Content-Type: multipart/mixed; boundary=\"L%d\"\n\n--L%d\n%s--L%d--\n"
                % (k, k, inner, k))
    body = nest(N)
    put("dep_%05d.mht" % N, ("MIME-Version: 1.0\nContent-Type: multipart/related; boundary=\"TOP\"\n\n"
                             "--TOP\n" + body + "--TOP--\n"))
# 4. header value length, plain and folded at boundary widths
for L in DENSE + EDGE[:8]:
    put("hd_%05d.eml" % L, hdr("Subject: " + ("s" * L) + "\nContent-Type: text/plain\n\nbody\n"))
for W in (73, 74, 75, 76):
    for L in DENSE[:60]:
        v = ("x" * L)
        folded = v[:W] + "\n " + v[W:W * 2] + ("\n " + v[W * 2:] if L > W * 2 else "")
        put("hfd%02d_%04d.eml" % (W, L),
            hdr("Subject: " + folded + "\nContent-Type: text/plain\n\nbody\n"))
# 5. parameter value length (filename)
for L in DENSE + [127, 128, 129, 255, 256, 257]:
    fn = "f" * L
    put("prm_%05d.eml" % L,
        hdr('Content-Type: multipart/mixed; boundary="ZZ"\n\n--ZZ\n'
            'Content-Type: application/octet-stream; name="' + fn + '"\n'
            'Content-Disposition: attachment; filename="' + fn + '"; size=' + str(L) + '\n'
            'Content-Transfer-Encoding: base64\n\n' + base64.b64encode(b"data").decode() +
            "\n--ZZ--\n"))
# 6. quoted-printable payload with soft line breaks
for L in DENSE + [255, 256, 512, 1024]:
    raw = ("~" * L).encode()
    enc = quopri.encodestring(raw).decode().replace("\r\n", "\n").rstrip("\n")
    put("qp_%05d.eml" % L, hdr("Content-Type: text/plain\nContent-Transfer-Encoding: quoted-printable\n\n"
                               + enc + "\n"))
# 7. base64 payload length (with and without line wrapping)
for L in DENSE + [255, 256, 1023, 1024]:
    enc = base64.b64encode(b"q" * L).decode()
    put("b64_%05d.eml" % L, hdr("Content-Type: application/octet-stream\n"
                                "Content-Transfer-Encoding: base64\n\n" + enc + "\n"))
    wrapped = "\n".join(enc[i:i + 76] for i in range(0, len(enc), 76))
    put("b64w_%05d.eml" % L, hdr("Content-Type: application/octet-stream\n"
                                 "Content-Transfer-Encoding: base64\n\n" + wrapped + "\n"))
# 8. RFC 2047 encoded words, dense length and count
for L in DENSE:
    ew = "=?utf-8?B?" + base64.b64encode(("e" * L).encode()).decode() + "?="
    put("ew_%05d.eml" % L, hdr("Subject: " + ew + "\nContent-Type: text/plain\n\nbody\n"))
for N in DENSE[:60]:
    ew = "=?utf-8?Q?ab?="
    put("ewc_%05d.eml" % N, hdr("Subject: " + " ".join([ew] * N) + "\nContent-Type: text/plain\n\nbody\n"))
# 9. uuencode attachment payload
for L in DENSE[:80]:
    lines = []
    for i in range(0, L, 45):
        chunk = ("u" * L)[i:i + 45]
        lines.append(chr(32 + len(chunk)) + base64.b64encode(chunk.encode()).decode()[:((len(chunk) + 2) // 3) * 4])
    put("uu_%05d.eml" % L, hdr("Content-Type: application/octet-stream\n"
                               "Content-Transfer-Encoding: x-uuencode\n\nbegin 644 file.bin\n"
                               + "\n".join(lines) + "\n`\nend\n"))
# 10. odd charset / boundary shapes
for cs in ("utf-8", "utf-7", "ISO-2022-JP", "x-mac-roman", "big5", "gb18030", "cp1251"):
    for L in (1, 2, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256):
        put("ct_%s_%04d.eml" % (cs.replace("-", ""), L),
            hdr("Content-Type: text/plain; charset=\"" + cs + "\"\n"
                "Content-Transfer-Encoding: 8bit\n\n" + ("n" * L) + "\n"))
print("made=%d dir=%s" % (made, OUT))
