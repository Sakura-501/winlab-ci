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
