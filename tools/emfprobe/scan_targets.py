#!/usr/bin/env python3
"""Locate vulnerable EMF-consumer functions in x64 Office DLLs WITHOUT symbols.

Outputs RVA lines:  <tag> <module> <rva>
  mso_cboa_reg      CbOAFromHENHMETAFILE (registrar: calls EnumEnhMetaFile w/ cbE)
  mso_cbe_cb        GDICOMMENT callback consuming (rec+0xC, DataSize)
  ppc_icononly      FIsIconOnlyComment (DataSize-trusting wide search)
  ppc_enumemf       EnumEmfExtractIcon (callback hosting the 0x72 + comment branches)
"""
import struct, sys, bisect

def sections(d):
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    out = []
    for i in range(nsec):
        o = pe + 24 + optsz + i * 40
        nm = d[o:o+8].rstrip(b'\0').decode('latin1')
        vsz, va, rsz, ptr = struct.unpack_from('<IIII', d, o + 8)
        out.append((nm, va, vsz, ptr, rsz))
    return out

def r2o(secs, rva):
    for nm, va, vsz, ptr, rsz in secs:
        if va <= rva < va + max(vsz, rsz):
            return ptr + (rva - va)
    return None

def pdata_funcs(d, secs):
    pd = [s for s in secs if s[0] == '.pdata'][0]
    fs = {}
    for k in range(0, pd[4] - 11, 12):
        b, e, u = struct.unpack_from('<III', d, pd[3] + k)
        if b and e > b and e - b < 0x40000:
            fs[b] = e
    return fs

def func_of(fs, rva):
    starts = sorted(fs.keys())
    i = bisect.bisect_right(starts, rva) - 1
    if i >= 0 and rva < fs[starts[i]]:
        return starts[i], fs[starts[i]]
    return None

def find_str_rva(d, secs, needle):
    for nm, va, vsz, ptr, rsz in secs:
        if nm.startswith('.rdata'):
            blob = d[ptr:ptr+rsz]
            j = blob.find(needle)
            if j >= 0:
                return va + j
    return None

def lea_targets(body, text_rva, target_rva):
    """all RVAs of `lea r64,[rip+d]` resolving to target_rva"""
    out = []
    i = 0
    while True:
        i = body.find(b'\x48\x8d', i)
        if i < 0: break
        modrm = body[i+2]
        if (modrm & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', body, i + 3)[0]
            if text_rva + i + 7 + disp == target_rva:
                out.append(text_rva + i)
        i += 1
    i = 0
    while True:
        i = body.find(b'\x4c\x8d', i)
        if i < 0: break
        modrm = body[i+2]
        if (modrm & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', body, i + 3)[0]
            if text_rva + i + 7 + disp == target_rva:
                out.append(text_rva + i)
        i += 1
    return out

def direct_callers(body, text_rva, target_rva):
    out = []
    i = 0
    while True:
        i = body.find(b'\xe8', i)
        if i < 0 or i + 5 > len(body): break
        rel = struct.unpack_from('<i', body, i + 1)[0]
        if text_rva + i + 5 + rel == target_rva:
            out.append(text_rva + i)
        i += 1
    return out

def delayed_iat_slot(d, secs, dll_name, func_name):
    """Find delayed-import IAT slot RVA for func_name from dll_name."""
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    ddoff = pe + 24 + 112
    drva, dsz = struct.unpack_from('<II', d, ddoff + 13 * 8)
    o = r2o(secs, drva)
    if o is None:
        return None
    for k in range(0, dsz, 32):
        gr, dlln, hmod, iat, int_ = struct.unpack_from('<IIIII', d, o + k)
        if not gr and not dlln:
            break
        cands = []
        for imagebase in (0x180000000, 0):
            # try interpreting fields as VA (subtract base) or raw RVA
            base_rva = (dlln - imagebase) if dlln >= imagebase else None
            if base_rva is not None and r2o(secs, base_rva) is not None:
                nm = d[r2o(secs, base_rva):].split(b'\0')[0].decode('latin1', 'replace')
                if not nm.startswith('MZ') and len(nm) > 3 and '.' in nm:
                    cands.append(imagebase)
        ok = any(d.lower().startswith(dll_name.lower()) for d in
                 [d[r2o(secs, dlln - ib):].split(b'\0')[0].decode('latin1', 'replace') for ib in cands]) if cands else False
        if not ok:
            continue
        ib = cands[0] if cands else 0x180000000
        t, u = iat - ib, int_ - ib
        if t is None or u is None or t < 0 or u < 0:
            continue
        while True:
            v = struct.unpack_from('<Q', d, r2o(secs, u))[0]
            if v == 0: break
            if not (v >> 63):
                vr = (v - 0x180000000) if v >= 0x180000000 else v
                ho = r2o(secs, vr)
                if ho:
                    nm = d[ho+2:].split(b'\0')[0].decode('latin1')
                    if nm == func_name:
                        return t
            t += 8; u += 8
    return None

def call_sites_of_slot(body, text_rva, slot_rva):
    out = []
    i = 0
    while True:
        i = body.find(b'\xff\x15', i)
        if i < 0 or i + 6 > len(body): break
        disp = struct.unpack_from('<i', body, i + 2)[0]
        if text_rva + i + 6 + disp == slot_rva:
            out.append(text_rva + i)
        i += 1
    return out

def analyze_mso(path):
    d = open(path, 'rb').read()
    secs = sections(d)
    text = [s for s in secs if s[0] == '.text'][0]
    body = d[text[3]:text[3]+text[4]]
    fs = pdata_funcs(d, secs)
    slot = delayed_iat_slot(d, secs, 'gdi32', 'EnumEnhMetaFile')
    if slot is None:
        raise RuntimeError('EnumEnhMetaFile delayed slot not found')
    sites = call_sites_of_slot(body, text[1], slot)
    res = {}
    oz = find_str_rva(d, secs, b'msOZMSOFFICE9.0')
    # registrar = function containing a call site whose preceding window loads
    # a callback that itself references the msOZ string
    cb = None; reg = None
    for site in sites:
        fo = func_of(fs, site)
        if not fo: continue
        # search this function for `lea/mov r8, [rip+X]` (callback) shortly before the call
        o = r2o(secs, fo[0]); n = site - fo[0]
        win = d[o:o+n]
        for j in range(len(win) - 7, -1, -1):
            if win[j:j+2] in (b'\x48\x8d', b'\x4c\x8d') and (win[j+2] & 0xC7) == 0x05:
                disp = struct.unpack_from('<i', win, j + 3)[0]
                tgt = fo[0] + j + 7 + disp
                cfo = func_of(fs, tgt)
                if cfo:
                    co = r2o(secs, cfo[0])
                    cbody = d[co:co + (cfo[1]-cfo[0])]
                    if oz is not None and any(lea_targets(cbody, cfo[0], oz)):
                        cb = cfo[0]; reg = fo[0]
                        break
        if cb is not None:
            break
    res['mso_cbe_cb'] = cb
    res['mso_cboa_reg'] = reg
    if cb is not None:
        co = r2o(secs, cb)
        cbody = d[co:co + 0x200]
        # last direct call inside cb = GELOASCAN::FRead consumer
        i = 0; last = None
        while True:
            i = cbody.find(b'\xe8', i)
            if i < 0 or i + 5 > len(cbody): break
            rel = struct.unpack_from('<i', cbody, i + 1)[0]
            tgt = cb + i + 5 + rel
            if func_of(fs, tgt):
                last = tgt
            i += 1
        res['mso_fread'] = last
    return res

def analyze_wwlib(path):
    d = open(path, 'rb').read()
    secs = sections(d)
    text = [s for s in secs if s[0] == '.text'][0]
    body = d[text[3]:text[3]+text[4]]
    fs = pdata_funcs(d, secs)
    slot = delayed_iat_slot(d, secs, 'gdi32', 'EnumEnhMetaFile')
    res = {}
    if slot is None:
        return res
    ico = None
    needle = b'I\x00c\x00o\x00n\x00O\x00n\x00l\x00y\x00'
    for nm, va, vsz, ptr, rsz in secs:
        if nm.startswith('.rdata'):
            j = d[ptr:ptr+rsz].find(needle)
            if j >= 0:
                ico = va + j
                break
    if ico is None:
        return res
    for site in call_sites_of_slot(body, text[1], slot):
        fo = func_of(fs, site)
        if not fo:
            continue
        o = r2o(secs, fo[0]); n = site - fo[0]
        win = d[o:o+n]
        seen = set()
        for j in range(len(win) - 7, -1, -1):
            if win[j:j+2] in (b'\x48\x8d', b'\x4c\x8d') and (win[j+2] & 0xC7) == 0x05:
                disp = struct.unpack_from('<i', win, j + 3)[0]
                tgt = fo[0] + j + 7 + disp
                if tgt in seen:
                    continue
                seen.add(tgt)
                cfo = func_of(fs, tgt)
                if cfo:
                    co = r2o(secs, cfo[0])
                    cbody = d[co:co + (cfo[1]-cfo[0])]
                    if lea_targets(cbody, cfo[0], ico):
                        res['wwlib_icon_cb'] = cfo[0]
                        res['wwlib_icon_drv'] = fo[0]
        if res:
            break
    return res

def enumemf_registrar(d, secs, fs, text, icononly=None):
    st_lea = lea_targets
    """function calling EnumEnhMetaFile whose callback leas the marker string
    or directly calls the marker-scanning function"""
    body = d[text[3]:text[3]+text[4]]
    needle = b'I\x00c\x00o\x00n\x00O\x00n\x00l\x00y\x00'
    ico = find_str_rva(d, secs, needle)
    slot = delayed_iat_slot(d, secs, 'gdi32', 'EnumEnhMetaFile')
    if slot is None:
        return None, None
    out = []
    for site in call_sites_of_slot(body, text[1], slot):
        fo = func_of(fs, site)
        if not fo:
            continue
        o = r2o(secs, fo[0]); n = site - fo[0]
        win = d[o:o+n]
        seen = set()
        for j in range(len(win) - 7, -1, -1):
            if win[j:j+2] in (b'\x48\x8d', b'\x4c\x8d') and (win[j+2] & 0xC7) == 0x05:
                disp = struct.unpack_from('<i', win, j + 3)[0]
                tgt = fo[0] + j + 7 + disp
                if tgt in seen:
                    continue
                seen.add(tgt)
                cfo = func_of(fs, tgt)
                if cfo:
                    co = r2o(secs, cfo[0])
                    cbody = d[co:co + (cfo[1]-cfo[0])]
                    if ico is not None and st_lea(cbody, cfo[0], ico):
                        out.append((fo[0], cfo[0])); continue
                    if icononly is not None and direct_callers(cbody, cfo[0], icononly):
                        out.append((fo[0], cfo[0]))
    return out

def analyze_ppcore(path):
    d = open(path, 'rb').read()
    secs = sections(d)
    text = [s for s in secs if s[0] == '.text'][0]
    body = d[text[3]:text[3]+text[4]]
    fs = pdata_funcs(d, secs)
    needle = b'I\x00c\x00o\x00n\x00O\x00n\x00l\x00y\x00'
    ico = find_str_rva(d, secs, needle)
    if ico is None:
        raise RuntimeError('IconOnly string not found')
    refs = lea_targets(body, text[1], ico)
    icononly = None
    for r in refs:
        fo = func_of(fs, r)
        if fo:
            # FIsIconOnlyComment: contains cmp [rbx],0x46 style check in its head
            o = r2o(secs, fo[0])
            head = d[o:o+0x120]
            if b'\x0f\x85' in head or b'\x74' in head:
                # verify: cmp [reg],0x46 (83 3x 46) then mov edx,[reg+8]; shr edx,1
                hit46 = head.find(bytes.fromhex('833b46')) 
                if hit46 < 0:
                    for modrm in range(0x38, 0x40):
                        hit46 = head.find(bytes([0x83, modrm, 0x46]))
                        if hit46 >= 0: break
                shr = head.find(bytes.fromhex('8b5308d1ea'))
                if shr < 0:
                    shr = head.find(bytes.fromhex('d1ea'))
                if hit46 >= 0 and shr >= 0:
                    icononly = fo[0]
                    break
    res = {'ppc_icononly': icononly}
    if icononly is not None:
        fo2 = func_of(fs, icononly)
        o2 = r2o(secs, fo2[0])
        fbody = d[o2:o2 + (fo2[1] - fo2[0])]
        j = fbody.find(b'\xff\x15')
        if j >= 0:
            res['ppc_scancall'] = fo2[0] + j  # regs set: rcx=data rdx=len r8=pat
    for idx, (reg, cb) in enumerate(enumemf_registrar(d, secs, fs, text, icononly)):
        res[f'ppc_enumemf{"" if idx==0 else idx}'] = cb
        res[f'ppc_reg{"" if idx==0 else idx}'] = reg
    return res

if __name__ == '__main__':
    mode, path = sys.argv[1], sys.argv[2]
    fns = {'mso': analyze_mso, 'ppcore': analyze_ppcore, 'wwlib': analyze_wwlib}
    r = fns[mode](path)
    for k, v in r.items():
        print(f'{k} {hex(v) if v else None}')
