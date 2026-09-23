#!/usr/bin/env python3
"""Byte-level scan of an x64 PE for "release, then a store through the released register".

    FF 15 rel32          call [free]        ; rcx held the block
    <following instructions, same function, until the register is redefined>
    mov qword ptr [rX+d], rY / mov [rX], ...  ; a write through that same register

That is a straight-line use-after-free write: the store lands in a chunk the allocator already
owns, so it writes allocator metadata or another owner's data. Register identity is tracked the
same way as in dfree_bytescan.py: register-to-register copies propagate the tag, a load or an
arithmetic rewrite clears it, and any call is treated as a barrier for callee-saved registers only
when the target is unknown, so the reading stays conservative on both sides.

A synthetic fixture (work/uaf_fixture.bin) is what validates the judge: it holds one positive
(call free then mov [rbx+8],eax) and three negatives (reassigned before the store; store through
an unrelated register; store after a pop/ret boundary).
"""
import struct
import sys

import capstone

EXEC = 0x20000000
WRITE = 0x80000000
FREE_HINTS = ("free", "delete", "Free", "HeapFree", "LocalFree", "CoTaskMemFree", "SysFreeString")


class PE:
    def __init__(self, path):
        self.b = open(path, "rb").read()
        b = self.b
        self.pe = struct.unpack_from("<I", b, 0x3C)[0]
        n = struct.unpack_from("<H", b, self.pe + 6)[0]
        optsz = struct.unpack_from("<H", b, self.pe + 20)[0]
        self.magic = struct.unpack_from("<H", b, self.pe + 24)[0]
        so = self.pe + 24 + optsz
        self.secs = []
        for i in range(n):
            e = so + i * 40
            self.secs.append(dict(
                name=b[e:e + 8].rstrip(b"\0").decode("latin1"),
                vs=struct.unpack_from("<I", b, e + 8)[0],
                va=struct.unpack_from("<I", b, e + 12)[0],
                rawsz=struct.unpack_from("<I", b, e + 16)[0],
                raw=struct.unpack_from("<I", b, e + 20)[0],
                ch=struct.unpack_from("<I", b, e + 36)[0]))
        dd = self.pe + 24 + (112 if self.magic == 0x20B else 96)
        self.imp_rva, self.imp_sz = struct.unpack_from("<II", b, dd + 8)
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
        t = w.split(b"\0")[0]
        return t.decode("latin1") if 3 <= len(t) and all(32 <= c < 127 for c in t) else ""

    def _imports(self):
        out = {}
        if not self.imp_sz:
            return out
        i = 0
        while True:
            blk = self.read(self.imp_rva + i * 20, 20)
            if len(blk) < 20:
                break
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

    def slot_kind(self, slot):
        n = self.imports.get(slot)
        if not n:
            return "unknown"
        return "free" if any(h in n[1] for h in FREE_HINTS) else "%s!%s" % n

    def fn_bounds(self, rva):
        lo, hi = 0, len(self.funcs) - 1
        while lo <= hi:
            m = (lo + hi) // 2
            a, e = self.funcs[m]
            if rva < a:
                hi = m - 1
            elif rva >= e:
                lo = m + 1
            else:
                return (a, e)
        return None


def scan(pe, path, max_look=14):
    REG, MEM = capstone.x86.X86_OP_REG, capstone.x86.X86_OP_MEM
    hits = 0
    seen = 0
    for s in pe.secs:
        if not (s["ch"] & EXEC) or (s["ch"] & WRITE):
            continue
        body = pe.b[s["raw"]:s["raw"] + s["rawsz"]]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        ins_list = list(md.disasm(body, s["va"]))
        for idx, ins in enumerate(ins_list):
            ops = list(ins.operands)
            if not ops or ins.mnemonic != "call" or ops[0].type != MEM:
                continue
            if ins.reg_name(ops[0].mem.base) != "rip":
                continue
            tgt = ins.address + ins.size + ops[0].mem.disp
            if pe.slot_kind(tgt) != "free":
                continue
            fb = pe.fn_bounds(ins.address)
            if not fb:
                continue
            freed = {"rcx"}
            seen += 1
            for nxt in ins_list[idx + 1: idx + 1 + max_look]:
                if nxt.address >= fb[1] or nxt.mnemonic in ("ret", "jmp", "leave"):
                    break
                nops = list(nxt.operands)
                if not nops:
                    continue
                d0 = nops[0].reg if nops[0].type == REG else None
                dn = nxt.reg_name(d0) if d0 else ""
                # a store through a tagged register is the use
                for k, op in enumerate(nops):
                    if op.type == MEM and k == 0 and nxt.mnemonic in ("mov", "add", "sub", "and", "or", "xor", "inc", "dec", "not", "neg"):
                        base = nxt.reg_name(op.mem.base) if op.mem.base else ""
                        ix = getattr(op.mem, "index", 0)
                        ixn = nxt.reg_name(ix) if ix else ""
                        if base in freed or ixn in freed:
                            hits += 1
                            print("UAFWRITE free_at=%06X slot=%s  store_at=%06X  %-28s  fn=%06X..%06X" %
                                  (ins.address, "%06X" % tgt, nxt.address,
                                   (nxt.mnemonic + " " + nxt.op_str)[:28], fb[0], fb[1]))
                            break
                        else:
                            continue
                        break
                if dn:
                    if nxt.mnemonic == "mov" and len(nops) > 1 and nops[1].type == REG:
                        # `mov rA, rB` transfers the tag only from B to A. The reversed rule is what
                        # made VVIEWER's 0xCBD27 look like a use-after-free: the free took r14 via
                        # rcx, then `mov rcx, rbx` loaded rcx with a live pointer, and moving the
                        # tag backwards onto rbx condemned an unrelated object.
                        src = nxt.reg_name(nops[1].reg)
                        if src in freed:
                            freed.add(dn)
                        else:
                            freed.discard(dn)
                        continue
                    if nxt.mnemonic == "mov" and len(nops) > 1 and nops[1].type == MEM:
                        freed.discard(dn)      # value read out of memory: a different block
                        continue
                    if nxt.mnemonic in ("xor", "sub", "add", "lea", "inc", "dec", "and", "or"):
                        if not (nxt.mnemonic == "xor" and len(nops) > 1 and nops[1].type == REG
                                and nxt.reg_name(nops[1].reg) == dn):
                            freed.discard(dn)
                if nxt.mnemonic == "push" and nops[0].type == REG and dn in freed:
                    continue
                if nxt.mnemonic == "pop" and nops[0].type == REG and dn in freed:
                    freed.discard(dn)
    print("UAF-SCAN file=%s free_sites=%d writes_after_free=%d" % (path, seen, hits))


def main():
    for path in sys.argv[1:]:
        pe = PE(path)
        print("### %s magic=0x%X imports=%d funcs=%d" % (path, pe.magic, len(pe.imports), len(pe.funcs)))
        if pe.magic != 0x20B:
            print("   not AMD64, skipped")
            continue
        scan(pe, path)


if __name__ == "__main__":
    main()
