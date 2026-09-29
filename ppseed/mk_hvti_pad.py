import os, sys
# The value pad writes 8*((col>>3)+1)-col words (<=8) at [base + 2*idx] after the gate
# `idx < cap-8` (which falls through to the no-grow branch for idx in [cap-8, cap-1]).
# Capacity starts and grows by 8192 words, so tabs are planted at every position whose
# residue mod 8192 is 8176..8191 or 0..15, whichever cap the buffer ends up with.
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
CJK = u"\u4e00"
def plant(total, step_lo=8160, step_hi=8191, tail=31, ch=u"a", tab=u"\t"):
    buf = [ch] * total
    for i in range(total):
        r = i % 8192
        if step_lo <= r <= step_hi or r <= tail:
            buf[i] = tab
    return "".join(buf)
n = 0
for total in (16384, 17000, 24576, 32000, 32767, 40000, 49152, 65536):
    for enc, w in (("plain", 1), ("cjk", 2)):
        if enc == "plain":
            body = plant(total)
        else:
            body = plant(total // 2, ch=CJK)
        for q in (0, 1):
            text = "h1,h2\r\n" + ('"' + body.replace('"', '""') + '"' if q else body) + "\r\n"
            name = "pad_%s_%d_%s.csv" % (enc, total, "q" if q else "n")
            with open(os.path.join(out, name), "wb") as fh:
                fh.write(text.encode("utf-8"))
            n += 1
for total in (16384, 32767, 49152, 65536):
    with open(os.path.join(out, "padw_%d.prn" % total), "wb") as fh:
        fh.write((plant(total) + "\r\n").encode("utf-8"))
    n += 1
for total in (32767, 49152):
    data = b"\xff\xfe" + ("h1,h2\r\n" + plant(total) + "\r\n").encode("utf-16-le")
    with open(os.path.join(out, "padu_%d.csv" % total), "wb") as fh:
        fh.write(data)
    n += 1
print("carriers=%d" % n)


def dif_doc(widths, da_value, nrow=2):
    """A syntactically complete MS-DIF document: header, Name/Type/DDL/VD/VW/US/BK/NS/DF/NH/DI,
    then DA/ND rows and E.  Earlier .dif batches only proved the HrLoadTextDIF entry breakpoint, so
    the record grammar itself is the variable here."""
    k = len(widths)
    lines = ["DIF 1.00ASIOMP DIF EXPORT V1.1 IBM MICRO 02/12/85",
             'Name "T" "PADTEST"',
             'Type "sys"',
             'DDL 0 %d "X"' % k,
             "VD " + " ".join(["255"] * k),
             "VW " + " ".join(str(w) for w in widths),
             'US "0"',
             "BK 0 0 0",
             "NS 3 1 2",
             'DF NA 0 0 0 "General" "Left" 1 1']
    head = ["NH %d " % k]
    for i in range(k):
        head.append('"%s" %s %s 0 0 1 "General" "Left" 1 1' % ("C%d" % i, 0, 1 if i == 0 else 0))
    lines.append(" ".join(head).strip())
    lines.append("DI " + " ".join(["1"] * k) + " 0 1 0")
    for r in range(nrow):
        lines.append("DA " + " ".join('"%s"' % da_value for _ in range(k)))
        lines.append("ND " + " ".join(["0"] * k))
    lines.append("E")
    return "\r\n".join(lines) + "\r\n"


for w in (16384, 32767):
    # one very wide field so the value constructor sees a long run of characters
    doc = dif_doc([w], "a" * min(w, 4000))
    open(os.path.join(out, "difw_%d.dif" % w), "wb").write(doc.encode("utf-8"))
    n += 1
for tabn in (1000, 4000):
    doc = dif_doc([max(tabn * 8, 8192)], ("a" * 7 + "\t") * tabn)
    open(os.path.join(out, "diftab_%d.dif" % tabn), "wb").write(doc.encode("utf-8"))
    n += 1
for cols in (8, 64, 512, 2048):
    doc = dif_doc([64] * cols, "abcdefghij" * 8)
    open(os.path.join(out, "difc_%d.dif" % cols), "wb").write(doc.encode("utf-8"))
    n += 1

print("with_dif_total=%d" % n)
