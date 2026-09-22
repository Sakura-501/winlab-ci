#!/usr/bin/env python3
"""Corpus builder for OUTLMIME's Ess*DecodeEx family (seven exported flattener entry points).

The records are DER blobs for the RFC 2633/2634 ESS attribute shapes those exports decode:
ESSSecurityLabel (policy OID + the four optional sslf fields + cleared/ security categories),
MLExpansionHistory, ContentHint, Receipt, ReceiptRequest, SigningCertificate and
KeyExchangePreference. Every record is emitted as "<len>\\n<bytes>\\n", the record format the
corpus reader in tools/crtfbench.cpp mode 42 expects.

The axes chosen are the ones the decode callbacks actually consume: which optional fields are
present (the callbacks branch on bits 0x80 / 0x40 / 0x20 of the decoded header word), the number
of category elements (reserve is 24 bytes per element, the decoded array stride is 88), the number
of arcs in each category OID (the arcs are flattened into a decimal dotted string), and the length
of each ANY value (aligned to 8 bytes when copied).
"""
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "esscorpus"

recs = []


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, val):
    return bytes([tag]) + enc_len(len(val)) + val


def enc_arc(a):
    if a == 0:
        return b"\x00"
    out = bytearray()
    while a:
        out.append(a & 0x7F)
        a >>= 7
    out.reverse()
    for i in range(len(out) - 1):
        out[i] |= 0x80
    return bytes(out)


def oid(body_arcs):
    """body_arcs: list of integers, first two combined into the leading octet."""
    if len(body_arcs) < 2:
        body_arcs = list(body_arcs) + [0]
    b = bytearray([body_arcs[0] * 40 + body_arcs[1]])
    for a in body_arcs[2:]:
        b += enc_arc(a)
    return tlv(0x06, bytes(b))


POLICY = [1, 3, 6, 1, 4, 1, 311, 46, 1]
WIDE = [1, 2, 840, 113549, 1, 9, 16, 1000000007, 1000000013, 1000000029]


def integer(v):
    b = abs(v).to_bytes(max(1, (abs(v).bit_length() + 8) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    if v < 0:
        b = bytes([0xFF]) + b[:-1] if len(b) == 1 else bytes([0x80]) + b[1:]
    return tlv(0x02, b)


def any_blob(n, fill=0x42):
    return tlv(0x04, bytes([fill]) * n)


def category(idx, narcs, vlen):
    arcs = POLICY[:min(narcs, len(POLICY))]
    while len(arcs) < narcs:
        arcs.append(1000000000 + 7919 * len(arcs) + idx)
    inner = tlv(0xA0, oid(arcs)) + tlv(0xA1, any_blob(vlen))
    return tlv(0x30, inner)


def cat_seq(n, narcs, vlen, tag=0xA3):
    body = b"".join(category(i, narcs, vlen) for i in range(n))
    return tlv(0x30, body) if n else tlv(0x30, b"")


def label(present_bits, ncat, narcs, vlen, form=1):
    """ESSSecurityLabel with the optional fields selected by present_bits:
    0x80 = sslf-uniOrdinal, 0x40 = sslf-parsedAs (form selects INTEGER(1)/2 or IA5), 0x20 = clearance."""
    body = oid(POLICY)
    if present_bits & 0x80:
        body += tlv(0xA0, integer(7))
    if present_bits & 0x40:
        if form == 1:
            body += tlv(0xA2, bytes("label text " + "A" * 8, "ascii"))
        elif form == 2:
            body += tlv(0xA2, b"")
        else:
            body += tlv(0xA2, bytes("B" * 300, "ascii"))
    if present_bits & 0x20:
        body += tlv(0xA3, cat_seq(ncat, narcs, vlen, 0x30))
    return tlv(0x30, body)


def mlhistory(n, vlen):
    inner = b""
    for i in range(n):
        inner += tlv(0x30, tlv(0x80, integer(i)) + tlv(0x81, tlv(0x30, tlv(0x81, bytes("list%d@example.com" % i, "ascii")))))
    return tlv(0x30, inner) if inner else tlv(0x30, b"")


def content_hint(narcs, tnlen):
    arcs = POLICY[:min(narcs, len(POLICY))]
    while len(arcs) < narcs:
        arcs.append(1000000000 + 137 * len(arcs))
    body = tlv(0x80, oid(arcs))
    if tnlen:
        body += tlv(0x81, bytes("C" * tnlen, "ascii"))
    return tlv(0x30, body)


def signcert(n, dlen):
    inner = b""
    for i in range(n):
        issuer = tlv(0x30, tlv(0x30, tlv(0x0C, bytes("Issuer %d" % i, "ascii"))) + tlv(0x02, integer(i + 1)))
        inner += tlv(0x30, issuer + tlv(0x04, bytes([0x11]) * dlen))
    return tlv(0x30, inner)


def receipt(n_any):
    body = tlv(0x80, oid(POLICY)) + tlv(0x81, bytes([0x22]) * 20)
    if n_any:
        body += tlv(0x83, any_blob(n_any))
    return tlv(0x30, body)


def receipt_req(n_any):
    body = tlv(0x80, oid(POLICY)) + tlv(0x84, bytes("rcpt@example.com", "ascii"))
    if n_any:
        body += tlv(0x83, any_blob(n_any))
    return tlv(0x30, body)


def keyexch():
    return tlv(0x30, tlv(0x30, oid(POLICY)) + tlv(0x02, integer(2)))


def add(tag, blob):
    recs.append((tag, blob))


NC = [0, 1, 2, 16, 17, 64]
NA = [1, 3, 8, 16, 17, 24]
VL = [0, 1, 7, 8, 15, 16, 64, 512]

# the whole optional-field lattice crossed with the category/count/length ladders
for bits in range(8):
    for form in (1, 2, 3):
        for nc in NC:
            for na in NA:
                for vl in ([VL[0], VL[4], VL[7]] if nc <= 2 else [VL[1], VL[5]]):
                    add("label_b%d_f%d_c%d_a%d_v%d" % (bits, form, nc, na, vl),
                        label(bits, nc, na, vl, form))
for nc in NC:
    for na in NA:
        add("wide_c%d_a%d" % (nc, na),
            tlv(0x30, oid(WIDE) + tlv(0xA3, cat_seq(nc, na, 16, 0x30))))
for n in [0, 1, 2, 17, 64, 255]:
    add("ml_%d" % n, mlhistory(n, 8))
for na in NA:
    for tn in [0, 1, 64, 300]:
        add("hint_a%d_t%d" % (na, tn), content_hint(na, tn))
for n in [1, 2, 17, 64]:
    for dl in [1, 20, 64, 512]:
        add("cert_%d_%d" % (n, dl), signcert(n, dl))
for v in [0, 1, 16, 512]:
    add("rcpt_%d" % v, receipt(v))
    add("rcptrq_%d" % v, receipt_req(v))
add("kexch", keyexch())
# structural variants: constructed where primitive is expected, and truncated tails
base = label(0xE0, 2, 3, 16, 1)
add("trunc_half", base[: len(base) // 2])
add("trunc_1", base[:1])
add("extra_tail", base + b"\x00\x00")
add("indefinite", b"\x30\x80" + oid(POLICY)[2:] + b"\x00\x00")
add("seq_of_direct", tlv(0x30, oid(POLICY) + tlv(0xA3, b"".join(category(i, 3, 8) for i in range(17)))))

import os
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "ess.txt"), "wb") as fh:
    for name, blob in recs:
        fh.write(b"%d\n" % len(blob))
        fh.write(blob)
        fh.write(b"\n")
print("records=%d bytes=%d dir=%s" % (len(recs), sum(len(b) + len(str(len(b))) + 2 for _, b in recs), OUT))
