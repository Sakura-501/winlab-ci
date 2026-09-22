#!/usr/bin/env python3
"""Fail the corpus build if any .msg has two directory entries with the same stream name.

Why: MAPI resolves __substg1.0_10090102 by name, and with two entries present it picks the small
one -- measured cb=16 (all zero) while the real compressed body was 9078 bytes holding 42307 bytes
of RTF. Every carrier built from such a base exercises the parsers on a stub, not on a body, so a
clean sweep means nothing. Also prints the surviving RTF stream size so the corpus step itself
records that carriers are body-bearing.
"""
import struct
import sys
from collections import Counter
from pathlib import Path


def entries(path):
    d = Path(path).read_bytes()
    if d[:8] != bytes.fromhex('d0cf11e0a1b11ae1'):
        return None
    ssz = 1 << struct.unpack_from('<H', d, 30)[0]
    nfat = struct.unpack_from('<I', d, 44)[0]
    difat = [struct.unpack_from('<I', d, 0x4C + 4 * i)[0] for i in range(109)]
    words = []
    for k in range(nfat):
        fs = difat[k]
        if fs >= (len(d) - ssz) // ssz:
            break
        words += list(struct.unpack_from('<%dI' % (ssz // 4), d, (1 + fs) * ssz))
    ch, s, seen = [], struct.unpack_from('<I', d, 48)[0], set()
    while s not in (0xFFFFFFFE, 0xFFFFFFFF) and s < len(words) and s not in seen:
        seen.add(s); ch.append(s); s = words[s]
    blob = b''.join(d[(1 + x) * ssz:(1 + x) * ssz + ssz] for x in ch)
    out = []
    for i in range(len(blob) // 128):
        e = blob[i * 128:(i + 1) * 128]
        nl = struct.unpack_from('<H', e, 64)[0]
        if not nl:
            continue
        nm = e[:max(0, nl - 2)].decode('utf-16-le', errors='replace')
        sz = struct.unpack_from('<Q', e, 120)[0]
        out.append((nm, sz))
    return out


def main(d):
    bad, sizes = [], []
    n = 0
    for f in sorted(Path(d).glob('*.msg')):
        n += 1
        es = entries(f)
        if not es:
            continue
        # Only MAPI stream names are meaningful here: the deliberately-corrupted-header carriers
        # ('hfirstdir_*') produce entries whose name bytes are all 0xFFFF, which are artifacts of the
        # mutation, not a shadowed property.
        real = [nm for nm, _ in es if nm.startswith('__')]
        c = Counter(real)
        dup = {k for k, v in c.items() if v > 1}
        if dup:
            bad.append((f.name, sorted(dup)))
        for nm, sz in es:
            if nm == '__substg1.0_10090102' and sz < (1 << 30):
                sizes.append(sz)
    if sizes:
        print('CHECK files=%d rtf_streams=%d min=%d max=%d' % (n, len(sizes), min(sizes), max(sizes)))
    else:
        print('CHECK files=%d rtf_streams=0  <== no PR_RTF_COMPRESSED in the corpus' % n)
    for nm, dup in bad[:12]:
        print('DUP %s %s' % (nm, dup))
    if bad:
        print('CHECKFAIL duplicate_stream_names=%d' % len(bad))
        return 2
    if not sizes or max(sizes) < 1000:
        print('CHECKFAIL carriers carry no real compressed body (max rtf size=%s)' % (max(sizes) if sizes else 0))
        return 3
    print('CHECKOK')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
