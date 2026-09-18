#!/usr/bin/env python3
"""Minimal MSF 7.00 + DBI reader to list S_PUB32 public symbols with RVAs.

Usage: msfpdb.py <pdb> <pe> <out.tsv>
Output lines: RVA<TAB>name
"""
import struct, sys

MAGIC = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00'


class MSF:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        if self.d[:len(MAGIC)] != MAGIC:
            raise ValueError('not MSF 7.00')
        (self.block_size, self.fpm, self.num_blocks, self.num_dir_bytes,
         self.unknown, self.block_map_addr) = struct.unpack_from('<IIIIII', self.d, 32)
        self._read_dir()

    def _block(self, idx):
        off = idx * self.block_size
        return self.d[off:off + self.block_size]

    def _read_dir(self):
        bs = self.block_size
        ndir_blocks = (self.num_dir_bytes + bs - 1) // bs
        bm_blocks = (ndir_blocks * 4 + bs - 1) // bs
        raw = b''.join(self._block(self.block_map_addr + i) for i in range(bm_blocks))
        dir_blocks = list(struct.unpack_from('<%dI' % ndir_blocks, raw, 0))
        dir_data = b''.join(self._block(b) for b in dir_blocks)[:self.num_dir_bytes]
        nstreams = struct.unpack_from('<I', dir_data, 0)[0]
        sizes = struct.unpack_from('<%dI' % nstreams, dir_data, 4)
        p = 4 + 4 * nstreams
        self.streams = []
        for i in range(nstreams):
            nb = (sizes[i] + bs - 1) // bs
            blks = list(struct.unpack_from('<%dI' % nb, dir_data, p)) if nb else []
            p += 4 * nb
            self.streams.append((sizes[i], blks))

    def stream(self, i):
        size, blks = self.streams[i]
        return b''.join(self._block(b) for b in blks)[:size]

    def omap_from_src(self):
        """Return the OMAPFromSrc table (list of (src,dst)) or None.

        S_PUB32 offsets live in the *original* (pre-optimisation) address
        space; OMAPFromSrc translates them to the final image RVA.
        """
        try:
            dbi = self.stream(3)
            modinfo, seccont, secmap, srcinfo, tsmap = struct.unpack_from('<iiiii', dbi, 24)
            mfc, optdbg, ec = struct.unpack_from('<Iii', dbi, 44)
            off_opt = 64 + modinfo + seccont + secmap + srcinfo + tsmap + ec
            nent = optdbg // 2
            opt = struct.unpack_from('<%dH' % nent, dbi, off_opt)
            if len(opt) < 5:
                return None
            si = opt[4]                      # OMAPFromSrc
            if si in (0, 0xFFFF):
                return None
            raw = self.stream(si)
            n = len(raw) // 8
            return [struct.unpack_from('<II', raw, 8 * i) for i in range(n)]
        except Exception:
            return None



class PE:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        pe = struct.unpack_from('<I', self.d, 0x3c)[0]
        if self.d[pe:pe + 4] != b'PE\0\0':
            raise ValueError('not PE')
        nsec = struct.unpack_from('<H', self.d, pe + 6)[0]
        optsz = struct.unpack_from('<H', self.d, pe + 20)[0]
        so = pe + 24 + optsz
        self.secs = []
        for i in range(nsec):
            o = so + 40 * i
            nm = self.d[o:o + 8].rstrip(b'\0').decode('latin1')
            vsz, va, rsz, ptr = struct.unpack_from('<IIII', self.d, o + 8)
            self.secs.append((nm, va, vsz, ptr, rsz))
        self.nsec = nsec

    def sec_by_number(self, n):
        # PDB segment numbers are 1-based over .text-style sections
        if 1 <= n <= len(self.secs):
            return self.secs[n - 1]
        return None


S_PUB32 = 0x110E


def parse_pub32(pe, rec_stream):
    """Yield (rva, name) from a symbol-record stream."""
    p = 0
    n = len(rec_stream)
    out = []
    while p + 4 <= n:
        ln, kind = struct.unpack_from('<HH', rec_stream, p)
        if ln == 0:
            break
        end = p + 2 + ln
        if end > n:
            break
        if kind == S_PUB32 and ln >= 10:
            flags, off, seg = struct.unpack_from('<IIH', rec_stream, p + 4)
            name_bytes = rec_stream[p + 14:end]
            try:
                name = name_bytes.split(b'\0')[0].decode('utf-8', 'replace')
            except Exception:
                name = ''
            s = pe.sec_by_number(seg)
            if s and name:
                nm, va, vsz, ptr, rsz = s
                out.append((va + off, name, flags))
        p = end
    return out


def main():
    pdb, pe_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    m = MSF(pdb)
    pe = PE(pe_path)
    dbi = m.stream(3)
    (vers_sig, vers_hdr, age, gsidx, build, pubidx, pdbrev,
     symrec, pdbrbld) = struct.unpack_from('<iIIHHHHHH', dbi, 0)
    if symrec == 0xFFFF:
        sys.stderr.write('no symbol record stream\n')
        return 1
    rec = m.stream(symrec)
    rows = parse_pub32(pe, rec)
    om = m.omap_from_src()
    if om:
        import bisect as _bs
        keys = [e[0] for e in om]

        def _map(a):
            i = _bs.bisect_right(keys, a) - 1
            if i < 0:
                return a
            return om[i][1] + (a - om[i][0])
        rows = [(_map(a), n, f) for a, n, f in rows]
        sys.stderr.write('omap applied (%d entries)\n' % len(om))
    # dedupe by (rva,name)
    seen = set()
    uniq = []
    for rva, name, fl in rows:
        k = (rva, name)
        if k in seen:
            continue
        seen.add(k)
        uniq.append((rva, name, fl))
    uniq.sort()
    with open(out_path, 'w', encoding='utf-8') as f:
        for rva, name, fl in uniq:
            f.write('%08x\t%s\t%x\n' % (rva, name, fl))
    sys.stderr.write('streams=%d symrec=%d publics=%d uniq=%d\n'
                     % (len(m.streams), symrec, len(rows), len(uniq)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
