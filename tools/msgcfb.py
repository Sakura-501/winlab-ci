"""Minimal MS-CFB (v3) reader/writer for a single .msg: locate streams incl. mini-stream, patch bytes."""
import struct

class CFB:
    def __init__(self, data):
        self.b = bytearray(data)
        h = self.b[:512]
        assert bytes(h[:8]) == bytes.fromhex("d0cf11e0a1b11ae1"), "not CFB"
        self.minor, self.major = struct.unpack("<HH", h[0x18:0x1C])
        self.sshift, self.mshift = struct.unpack("<HH", h[0x1E:0x22])
        self.SS = 1 << self.sshift
        self.MS = 1 << self.mshift
        self.n_minifat = struct.unpack("<I", h[0x2C:0x30])[0]
        self.dir_start = struct.unpack("<I", h[0x30:0x34])[0]
        self.cutoff = struct.unpack("<I", h[0x38:0x3C])[0]
        self.minifat_start = struct.unpack("<I", h[0x3C:0x40])[0]
        self.n_minifat2 = struct.unpack("<I", h[0x40:0x44])[0]
        self.difat_start = struct.unpack("<I", h[0x44:0x48])[0]
        self.n_difat = struct.unpack("<I", h[0x48:0x4C])[0]
        self.difat = [v for v in struct.unpack("<109I", bytes(h[0x4C:0x200])) if v not in (0xFFFFFFFF,)]
        if self.n_difat:
            sec = self.difat_start
            while sec not in (0xFFFFFFFE, 0xFFFFFFFF):
                d = self.sect(sec)
                self.difat += [v for v in struct.unpack("<%dI" % (self.SS // 4), bytes(d[:-4])) if v != 0xFFFFFFFF]
                sec = struct.unpack("<I", bytes(d[-4:]))[0]
                if len(self.difat) > 200000: break
        self.fat = {}
        for i, s in enumerate(self.difat[:self.n_minifat if False else len(self.difat)]):
            if s >= 0xFFFFFFFA: continue
            d = self.sect(s)
            for j, v in enumerate(struct.unpack("<%dI" % (self.SS // 4), bytes(d))):
                self.fat[i * (self.SS // 4) + j] = v
        self.minifat = {}
        if self.minifat_start not in (0xFFFFFFFE, 0xFFFFFFFF):
            for s_ in self.chain(self.minifat_start):
                d = self.sect(s_)
                pass
            # rebuild with explicit sector list
            k = self.minifat_start
            sec_ids = []
            while k not in (0xFFFFFFFE, 0xFFFFFFFF) and k in self.fat:
                sec_ids.append(k); k = self.fat[k]
                if len(sec_ids) > 100000: break
            vals = []
            for x in sec_ids:
                vals += list(struct.unpack("<%dI" % (self.SS // 4), bytes(self.sect(x))))
            self.minifat = {i: v for i, v in enumerate(vals)}
        self.entries = self.read_dir()

    def sect(self, k):
        off = 512 + k * self.SS
        return self.b[off:off + self.SS]

    def chain(self, start, limit=200000):
        out = []
        s = start
        while s not in (0xFFFFFFFE, 0xFFFFFFFF) and len(out) < limit:
            if s not in self.fat: break
            out.append(s)
            s = self.fat[s]
            if s >= 0xFFFFFFFA and s != 0xFFFFFFFE: break
        return out

    def read_dir(self):
        ents = []
        s = self.dir_start
        while s not in (0xFFFFFFFE, 0xFFFFFFFF):
            d = self.sect(s)
            for i in range(self.SS // 128):
                e = bytes(d[i * 128:(i + 1) * 128])
                nl = struct.unpack("<H", e[64:66])[0]
                name = e[:max(0, nl - 2)].decode("utf-16-le", "replace") if nl >= 2 else ""
                ents.append(dict(name=name, typ=e[66], start=struct.unpack("<I", e[116:120])[0],
                                 size=struct.unpack("<Q", e[120:128])[0], raw=e, idx=len(ents), sect=s, off_in_sect=i * 128))
            if s not in self.fat: break
            s = self.fat[s]
        return ents

    def mini_chain(self, start, n=None):
        out = []
        k = start
        while k not in (0xFFFFFFFE, 0xFFFFFFFF) and k in self.minifat:
            out.append(k)
            if n and len(out) >= n: break
            k = self.minifat[k]
            if len(out) > 400000: break
        return out

    def mini_data(self):
        root = [e for e in self.entries if e["name"] == "Root Entry"][0]
        return bytearray(b"".join(bytes(self.sect(x)) for x in self.chain(root["start"])))

    def mini_sect(self, k):
        root = [e for e in self.entries if e["name"] == "Root Entry"][0]
        ch = self.chain(root["start"])
        data = b"".join(bytes(self.sect(x)) for x in ch)
        off = k * self.MS
        return data[off:off + self.MS], data

    def read_stream(self, name):
        e = [x for x in self.entries if x["name"] == name]
        if not e: return None
        e = e[0]
        if e["size"] >= self.cutoff or e["size"] == 0:
            return b"".join(bytes(self.sect(x)) for x in self.chain(e["start"]))[:e["size"]]
        data = self.mini_data()
        out = b""
        for k in self.mini_chain(e["start"]):
            out += bytes(data[k * self.MS:(k + 1) * self.MS])
        return out[:e["size"]]

    def write_mini(self, name, newdata):
        e = [x for x in self.entries if x["name"] == name][0]
        root = [x for x in self.entries if x["name"] == "Root Entry"][0]
        ch = self.chain(root["start"])
        data = bytearray(b"".join(bytes(self.sect(x)) for x in ch))
        pos = e["start"] * self.MS
        blob = bytearray(data)
        need = ((len(newdata) + self.MS - 1) // self.MS) * self.MS
        if pos + len(newdata) > len(blob): blob += b"\0" * (pos + len(newdata) - len(blob))
        blob[pos:pos + len(newdata)] = newdata
        for i, x in enumerate(ch):
            self.b[512 + x * self.SS:512 + x * self.SS + self.SS] = bytes(blob[i * self.SS:(i + 1) * self.SS])
        return bytes(self.b)

    def write_stream(self, name, newdata):
        e = [x for x in self.entries if x["name"] == name][0]
        if e["size"] < self.cutoff:
            return self.write_mini(name, newdata)
        ch = self.chain(e["start"])
        for i, x in enumerate(ch):
            off = 512 + x * self.SS
            self.b[off:off + self.SS] = newdata[i * self.SS:(i + 1) * self.SS].ljust(self.SS, b"\0")[:self.SS]
        return bytes(self.b)
