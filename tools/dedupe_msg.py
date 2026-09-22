#!/usr/bin/env python3
"""Make a .msg unambiguous for MAPI by renaming the SECOND of two same-named CFB directory entries.

Why: __substg1.0_10090102 appears twice in the hand-built base (one real compressed-RTF stream,
one 8-byte leftover). MAPI resolves the name to the 8-byte one, so OpenProperty handed back a 16-byte
all-zero stream and the decompressor never saw a body -- measured with crtfbench mode 28:
    OK tag=10090102 flags=0 opt=0 stat=00000000 cb=16 rawread(hr=00000000 got=16 00000000...)
The rename is done in place with an equal-length name so the directory layout stays byte-identical
apart from the UTF-16 name bytes, and the chosen replacement tag is outside the MAPI property ranges
the readers care about.
"""
import struct
import sys

NAME_LEN_OFF = 64
TYPE_OFF = 66
ENT = 128


def dir_bytes(data):
    """Return (offset_of_directory, number_of_128B_entries) using the FAT chain from the header."""
    ssz = 1 << struct.unpack_from('<H', data, 30)[0]
    dirstart = struct.unpack_from('<I', data, 48)[0]
    nfat = struct.unpack_from('<I', data, 44)[0]
    # The FAT's own sectors are listed in the header DIFAT array at 0x4C (109 entries); assuming
    # sector 0 is wrong for files that were rewritten by a tool.
    difat = [struct.unpack_from('<I', data, 0x4C + 4 * i)[0] for i in range(109)]
    words = []
    for k in range(nfat):
        fs = difat[k]
        if fs >= (len(data) - ssz) // ssz:
            break
        words += list(struct.unpack_from('<%dI' % (ssz // 4), data, (1 + fs) * ssz))
    fat = words
    END, FREE = 0xFFFFFFFE, 0xFFFFFFFF
    sectors, s, seen = [], dirstart, set()
    while s not in (END, FREE) and s < len(fat) and s not in seen:
        seen.add(s)
        sectors.append(s)
        s = fat[s]
    return sectors, ssz


def main(path_in, path_out, keep=0):
    data = bytearray(open(path_in, 'rb').read())
    sectors, ssz = dir_bytes(data)
    blob = b''.join(bytes(data[(1 + x) * ssz:(1 + x) * ssz + ssz]) for x in sectors)
    n = len(blob) // ENT
    # collect names, in directory order
    ents = []
    for i in range(n):
        e = blob[i * ENT:(i + 1) * ENT]
        nl = struct.unpack_from('<H', e, NAME_LEN_OFF)[0]
        nm = e[:max(0, nl - 2)].decode('utf-16-le', errors='replace')
        ents.append((i, nm, nl))
    from collections import Counter
    dup = Counter(nm for _, nm, _ in ents if nm)
    dups = {k for k, v in dup.items() if v > 1}
    print('entries=%d duplicate_names=%s' % (n, sorted(dups)))
    if not dups:
        print('nothing to do')
        open(path_out, 'wb').write(bytes(data))
        return 0
    renamed = 0
    for name in sorted(dups):
        idxs = [i for i, nm, _ in ents if nm == name]
        for j, i in enumerate(idxs):
            if j < keep + 1:
                continue          # keep the first live one, rename the rest
            off = (1 + sectors[i // (ssz // ENT)]) * ssz + (i % (ssz // ENT)) * ENT
            nl = struct.unpack_from('<H', data, off + NAME_LEN_OFF)[0]
            # equal-length replacement: swap the property id digits for an unused private range
            newnm = name[:-8] + 'FE01FE01' if name.endswith('0102') or name.endswith('001E') else None
            if newnm is None or len(newnm) != len(name):
                print('  skip %s (cannot rename in place)' % name)
                continue
            enc = newnm.encode('utf-16-le')
            data[off:off + len(enc)] = enc
            renamed += 1
            print('  entry #%d %s -> %s (type=%d)' % (i, name, newnm, data[off + TYPE_OFF]))
    if not renamed:
        print('no rename applied')
        return 1
    open(path_out, 'wb').write(bytes(data))
    print('wrote %s' % path_out)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 0))
