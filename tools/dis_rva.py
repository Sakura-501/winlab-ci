#!/usr/bin/env python3
"""Disassemble a range of an x64 PE by RVA and annotate RIP-relative operands.

Used to name a site found by dfree_bytescan.py without building a database: the function's own
string and vtable references usually identify what it parses. .pdata gives the enclosing bounds.
"""
import struct, sys
import capstone

path, lo, hi = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
b = open(path, "rb").read()
pe = struct.unpack_from("<I", b, 0x3C)[0]
nsec = struct.unpack_from("<H", b, pe + 6)[0]
optsz = struct.unpack_from("<H", b, pe + 20)[0]
so = pe + 24 + optsz
secs = []
for i in range(nsec):
    e = so + i * 40
    secs.append(dict(name=b[e:e + 8].rstrip(b"\0").decode(),
                     va=struct.unpack_from("<I", b, e + 12)[0],
                     vs=struct.unpack_from("<I", b, e + 8)[0],
                     raw=struct.unpack_from("<I", b, e + 20)[0],
                     rawsz=struct.unpack_from("<I", b, e + 16)[0],
                     ch=struct.unpack_from("<I", b, e + 36)[0]))
def r2o(rva):
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vs"], s["rawsz"]):
            return s["raw"] + (rva - s["va"])
    return None
def cstr(rva, n=90):
    o = r2o(rva)
    if o is None: return None
    w = b[o:o + n]
    if w[:2] == b"\xff\xfe" or (len(w) > 2 and w[1] == 0 and w[3] == 0):
        try: return "W:" + w.decode("utf-16-le", "replace").split("\0")[0][:n]
        except Exception: pass
    t = w.split(b"\0")[0]
    if 3 <= len(t) < n and all(32 <= c < 127 for c in t):
        return "A:" + t.decode()
    return None
pf = [s for s in secs if s["name"] == ".pdata"]
funcs = []
if pf:
    s0 = pf[0]
    tbl = b[s0["raw"]:s0["raw"] + s0["rawsz"]]
    for i in range(0, len(tbl) - 11, 12):
        funcs.append(struct.unpack_from("<II", tbl, i))
funcs.sort()
for a, e in funcs:
    if a <= lo < e:
        print("enclosing function rva=0x%X..0x%X" % (a, e)); break
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
o = r2o(lo)
code = b[o:o + (hi - lo)]
for ins in md.disasm(code, lo):
    line = "  %08X  %-26s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str)
    note = ""
    ops = list(ins.operands)
    if ops and ops[0].type == capstone.x86.X86_OP_MEM and ops[0].mem.base == capstone.x86.X86_REG_RIP:
        tgt = ins.address + ins.size + ops[0].mem.disp
        s = cstr(tgt)
        note = "  ->0x%X %s" % (tgt, s or "")
    if len(ops) > 1 and ops[1].type == capstone.x86.X86_OP_MEM and ops[1].mem.base == capstone.x86.X86_REG_RIP:
        tgt = ins.address + ins.size + ops[1].mem.disp
        s = cstr(tgt)
        note += "  [->0x%X %s]" % (tgt, s or "")
    if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
        note += "  (target)"
    print(line + note)
