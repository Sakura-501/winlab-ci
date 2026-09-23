#!/usr/bin/env python3
"""Byte-level scan of an x64 PE for "release helper, then a second release of the same block".

Shape sought (the two sites found by decompilation in OLMAPI32 look exactly like this):

    48 8B Dx            mov rdx, rX          ; the block, passed as the helper's 2nd argument
    <0..6 bytes>                            ; the count/flag argument set-up in front of it
    E8 rel32            call helper           ; the helper releases the block itself
    48 8B C?            mov rcx, rX           ; SAME register, unmodified in between
    FF 15 rel32         call [IAT slot]       ; second release

Two things make a match mean something, and both are decided from bytes:

* the register identity lives in the ModRM r/m field (low 3 bits), not the whole byte -
  `mov rdx,rdi` is 48 8B D7 and `mov rcx,rdi` is 48 8B CF, so comparing full ModRM bytes matches
  nothing;
* an indirect FF 15 says nothing about its callee until the IAT slot is resolved to a name -
  requiring a free-family import for both the site's second call and the helper's own release is
  what keeps a telemetry property-bag accessor out of the result.

Function bounds come from .pdata (the x64 image runtime function table), so the helper's body is
analysed exactly and not by a heuristic length.
"""
import struct
import sys

FREE_HINTS = ("free", "delete", "Free", "Release")
EXEC = 0x20000000
WRITE = 0x80000000


class PE:
    def __init__(self, path):
        self.b = open(path, "rb").read()
        b = self.b
        self.pe = struct.unpack_from("<I", b, 0x3C)[0]
        self.nsec = struct.unpack_from("<H", b, self.pe + 6)[0]
        self.optsz = struct.unpack_from("<H", b, self.pe + 20)[0]
        self.magic = struct.unpack_from("<H", b, self.pe + 24)[0]
        so = self.pe + 24 + self.optsz
        self.secs = []
        for i in range(self.nsec):
            e = so + i * 40
            self.secs.append(dict(
                name=b[e:e + 8].rstrip(b"\0").decode("latin1"),
                vs=struct.unpack_from("<I", b, e + 8)[0],
                va=struct.unpack_from("<I", b, e + 12)[0],
                rawsz=struct.unpack_from("<I", b, e + 16)[0],
                raw=struct.unpack_from("<I", b, e + 20)[0],
                ch=struct.unpack_from("<I", b, e + 36)[0]))
        # Data directories start at offset 112 of the PE32+ optional header (96 for PE32), and the
        # import table is entry 1, i.e. +8. Getting this wrong silently yields zero resolved slots,
        # which then drops every real hit as "unknown".
        ddir = self.pe + 24 + (112 if self.magic == 0x20B else 96)
        self.imp_rva, self.imp_sz = struct.unpack_from("<II", b, ddir + 8)
        self.imports = self._imports()
        self.funcs = self._pdata()

    def r2o(self, rva):
        for s in self.secs:
            if s["va"] <= rva < s["va"] + max(s["vs"], s["rawsz"]):
                return s["raw"] + (rva - s["va"])
        return None

    def read(self, rva, n):
        o = self.r2o(rva)
        return self.b[o:o + n] if o is not None else b""

    def cstr(self, rva, n=80):
        w = self.read(rva, n)
        if len(w) < 3:
            return ""
        t = w.split(b"\0")[0]
        if 3 <= len(t) and all(32 <= c < 127 for c in t):
            return t.decode("latin1")
        return ""

    def _imports(self):
        """IAT slot rva -> (dll, imported name)."""
        out = {}
        if not self.imp_sz:
            return out
        base = self.imp_rva
        i = 0
        while True:
            blk = self.read(base + i * 20, 20)
            if len(blk) < 20:
                break
            # IMAGE_IMPORT_DESCRIPTOR is 20 bytes: Characteristics/OrigFirstThunk(4) TimeDateStamp(4)
            # ForwarderChain(4) Name(4) FirstThunk(4).
            oft, name, iat = struct.unpack_from("<III", blk, 0)[0], struct.unpack_from("<I", blk, 12)[0], \
                struct.unpack_from("<I", blk, 16)[0]
            if oft == 0 and name == 0 and iat == 0:
                break
            dll = self.cstr(name)
            j = 0
            while True:
                v = self.read(iat + j * 8, 8)
                if len(v) < 8:
                    break
                val = struct.unpack("<Q", v)[0]
                if val == 0:
                    break
                if oft:
                    tv = self.read(oft + j * 8, 8)
                    if len(tv) == 8:
                        th = struct.unpack("<Q", tv)[0]
                        if th and not (th >> 63):
                            nm = self.cstr(th + 2, 120)
                            if nm:
                                out[iat + j * 8] = (dll, nm)
                j += 1
            i += 1
        return out

    def _pdata(self):
        s = [x for x in self.secs if x["name"] == ".pdata"]
        if not s:
            return []
        s = s[0]
        tbl = self.b[s["raw"]:s["raw"] + s["rawsz"]]
        out = []
        for i in range(0, len(tbl) - 11, 12):
            a, e = struct.unpack_from("<II", tbl, i)
            if a and e > a:
                out.append((a, e))
        out.sort()
        return out

    def fn_of(self, rva):
        lo, hi = 0, len(self.funcs) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            a, e = self.funcs[mid]
            if rva < a:
                hi = mid - 1
            elif rva >= e:
                lo = mid + 1
            else:
                return (a, e)
        return None

    def slot_kind(self, slot):
        n = self.imports.get(slot)
        if n is None:
            return "unknown"
        dll, nm = n
        return "free" if any(h in nm for h in FREE_HINTS) else "%s!%s" % (dll, nm)

    def helper_frees_arg(self, rva, arg_index=1):
        """Does the function release a pointer derived from its parameter at arg_index?

        x64 passes the first four integer arguments in rcx, rdx, r8, r9. `wstring::assign(this,
        src, len)` frees the string's previous buffer (reached through `this`), which is not a
        release of `src`, so an "any free anywhere inside" test passes on correct code - that is
        how a protocolhandler site looked like a double free. Propagate register-to-register
        copies from the chosen argument only; a memory load clears the tag, so a pointer that
        came out of a field never counts as the argument.
        """
        f = self.fn_of(rva)
        if not f:
            return "no-fn", ""
        try:
            import capstone
        except Exception:
            return "no-capstone", ""
        arg = ["rcx", "rdx", "r8", "r9"][arg_index]
        tainted = {arg}
        slots = {}                        # (base reg, disp) -> holds the tagged pointer
        REG, MEM = capstone.x86.X86_OP_REG, capstone.x86.X86_OP_MEM
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        freed = []
        for ins in md.disasm(self.read(f[0], f[1] - f[0]), f[0]):
            try:
                m = ins.mnemonic
                ops = list(ins.operands)
                if not ops:
                    continue
                d0 = ops[0].reg if ops[0].type == REG else None
                dn = ins.reg_name(d0) if d0 else ""
                if m == "mov" and len(ops) == 2 and ops[0].type == REG:
                    if ops[1].type == REG:
                        if ins.reg_name(ops[1].reg) in tainted:
                            tainted.add(dn)
                        else:
                            tainted.discard(dn)
                    elif ops[1].type == MEM:
                        # MSVC keeps a parameter in an rbp/rsp-relative local and reloads it later.
                        # Treating every reload as "unknown" loses true positives - that is how the
                        # in-service 20430.20092 copy of FreeFileDescW stopped matching while the
                        # 20144 copy still did. Track the spill slot instead.
                        base = ins.reg_name(ops[1].mem.base) if ops[1].mem.base else ""
                        key = (base, ops[1].mem.disp)
                        if key in slots:
                            tainted.add(dn)
                        else:
                            tainted.discard(dn)      # value read out of memory: not the argument
                elif m == "xchg" and len(ops) == 2 and ops[0].type == REG and ops[1].type == REG:
                    a, b = ins.reg_name(ops[0].reg), ins.reg_name(ops[1].reg)
                    if (a in tainted) != (b in tainted):
                        tainted ^= {a, b}
                elif m == "lea" and ops[0].type == REG and len(ops) > 1 and ops[1].type == MEM:
                    parts = {ins.reg_name(ops[1].mem.base)} if ops[1].mem.base else set()
                    ix = getattr(ops[1].mem, "index", 0)
                    if ix:
                        parts.add(ins.reg_name(ix))
                    if parts & tainted:
                        tainted.add(dn)              # interior pointer, still frees the block
                    else:
                        tainted.discard(dn)
                elif ops[0].type == REG and m in ("add", "sub", "and", "or", "xor", "neg", "not"):
                    tainted.discard(dn)
                elif m in ("push",) and ops[0].type == REG:
                    pass
                if m == "mov" and ops[0].type == MEM and len(ops) > 1 and ops[1].type == REG:
                    base = ins.reg_name(ops[0].mem.base) if ops[0].mem.base else ""
                    key = (base, ops[0].mem.disp)
                    if ins.reg_name(ops[1].reg) in tainted:
                        slots[key] = True
                    else:
                        slots.pop(key, None)         # the local now holds something else
                if ops[0].type == MEM and ins.reg_name(ops[0].mem.base) == "rip" and m in ("call", "jmp"):
                    tgt = ins.address + ins.size + ops[0].mem.disp
                    if self.slot_kind(tgt) == "free" and "rcx" in tainted:
                        freed.append("%06X" % ins.address)
            except Exception:
                continue
        return ("YES" if freed else "no"), ",".join(freed[:4])


def main():
    path = sys.argv[1]
    pe = PE(path)
    print("file=%s magic=0x%X imports_resolved=%d functions=%d" %
          (path, pe.magic, len(pe.imports), len(pe.funcs)))
    if pe.magic != 0x20B:
        print("not AMD64 -> the x64 byte shapes below cannot apply (ARM64X files carry ARM64 code)")
        return
    hits = kept = scanned = 0
    for s in pe.secs:
        if not (s["ch"] & EXEC) or (s["ch"] & WRITE):
            continue
        blk = pe.b[s["raw"]:s["raw"] + s["rawsz"]]
        L = len(blk)
        i = 0
        while i + 19 < L:
            scanned += 1
            # ModRM must be register-to-register (mod=11) in both moves:
            #   48 8B D<base>   mov rdx, r<base>      mod=11 reg=2(rdx)  r/m=base
            #   48 8B C<8|base> mov rcx, r<base>      mod=11 reg=1(rcx)  r/m=base
            # `48 8B 0B` is mov rcx,[rbx] - a member pointer, i.e. a different block - and letting
            # the memory form through turned Excel's "free member, then free container" idiom into
            # eight phantom hits while hiding nothing.
            m0 = blk[i]
            if blk[i] != 0x48 or blk[i + 1] != 0x8B or blk[i + 2] != (0xD0 | (blk[i + 2] & 7)):
                i += 1
                continue
            base = blk[i + 2] & 7
            found = False
            for k in range(0, 7):
                p2 = i + 3 + k
                if p2 + 14 > L or blk[p2] != 0xE8:
                    continue
                if blk[p2 + 5] != 0x48 or blk[p2 + 6] != 0x8B:
                    continue
                md = blk[p2 + 7]
                if md != (0xC8 | base):          # mov rcx, r<base>  (mod=11, reg=1)
                    continue
                if blk[p2 + 8] != 0xFF or blk[p2 + 9] != 0x15:
                    continue
                site = s["va"] + i
                rel = struct.unpack_from("<i", blk, p2 + 1)[0]
                helper = s["va"] + p2 + 5 + rel
                frel = struct.unpack_from("<i", blk, p2 + 10)[0]
                slot = s["va"] + p2 + 14 + frel
                kind = pe.slot_kind(slot)
                hk, hn = pe.helper_frees_arg(helper, 1)
                sf = pe.fn_of(site) or (0, 0)
                hits += 1
                keep = kind == "free" and hk == "YES"
                kept += 1 if keep else 0
                print("%s site=0x%07X in_fn=0x%X..0x%X helper=0x%07X helper_releases=%s(%s) second_call=%s base=r%s" %
                      ("KEEP" if keep else "drop", site, sf[0] if sf else 0, sf[1] if sf else 0,
                       helper, hk, hn, kind,
                       "r%s" % "ax cx dx bx sp bp si di".split()[base]))
                if found:
                    break
                found = True
                i = p2 + 7
                break
            if not found:
                i += 1
    print("DFREE-SCAN file=%s scanned=%d shape_hits=%d kept_after_free_check=%d" % (path, scanned, hits, kept))


if __name__ == "__main__":
    main()
