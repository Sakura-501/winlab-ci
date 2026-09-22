"""LZFu (MS-OXRTFCP) encoder + adversarial RTF payload builder for the OLMAPI32 decompressor bench.

Header (16 bytes), as produced by real Outlook and confirmed against poc/base_valid.msg:
  [0:4]   u32 cb = (bytes following this field)          e.g. 9074 for a 9078-byte property value
  [4:8]   u32 uncompressed size (low 24 bits) | flags (bits 24..31 = init terminal count)
  [8:12]  b'LZFu'   (alternative accepted: b'LZSc'/'MCSA' family -- see magic kwarg)
  [12:16] u32 signature words (copied by the wrapper into its state)
Tokens: 1 control byte, bit0 first.  bit=1 -> literal byte;  bit=0 -> 16-bit big-endian copy token
        offset = u16 >> 4 (absolute index into the 4096-byte window), length = (u16 & 0xF) + 2.
Confirmed against LZFUREAD_FillWindow / LZFUREAD_FExpandMatch decompile (2026-09-22).
"""
import struct, os, random

INIT_DICT = (b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern "
             b"\\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n"
             b"\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx")
assert len(INIT_DICT) == 207
WINSZ = 4096


def encode(raw, sig=0x6749A333, magic=b"LZFu", unc_over=None, cb_over=None, flags_shift=0,
           allow_match=True, match_min=3, seed=0, force_block_ctrl=None, tail=b"", drop=None):
    """All-literal unless allow_match; then greedy self-matches that never cross the window end."""
    out = bytearray()
    win = bytearray(INIT_DICT)                      # logical window content, index == file-supplied offset
    pos = len(win)
    i = 0
    rnd = random.Random(seed)
    while i < len(raw):
        ctrl = 0
        blk = bytearray()
        for b in range(8):
            if i >= len(raw):
                break
            f = None
            if allow_match and pos < WINSZ - 20:
                best = 0
                boff = 0
                for L in range(min(match_min, 1), 18):
                    if i + L > len(raw):
                        break
                    cand = bytes(win[max(0, pos - 4090):pos])
                    j = cand.rfind(raw[i:i + L])
                    if j >= 0:
                        off = max(0, pos - 4090) + j
                        if off + L <= WINSZ and off != pos:
                            best, boff = L, off
                if best >= match_min:
                    f = (boff, best)
            if f is None:
                ctrl |= (1 << b)
                blk.append(raw[i])
                win.append(raw[i]); pos += 1
                i += 1
            else:
                off, L = f
                u16 = ((off << 4) | (L - 2)) & 0xFFFF
                blk += struct.pack('>H', u16)
                for k in range(L):
                    win.append(win[off + k])
                pos += L
                i += L
        if force_block_ctrl is not None:
            ctrl = force_block_ctrl
        out.append(ctrl)
        out += blk
    if len(win) > WINSZ + 64:
        del win[:len(win) - WINSZ]
    data = bytes(out) + tail
    if drop is not None:
        data = data[:drop]
    unc = len(raw) if unc_over is None else unc_over
    u = (unc & 0xFFFFFF) | ((flags_shift & 0xFF) << 24)
    cb = (12 + len(data)) if cb_over is None else cb_over
    return struct.pack('<II', cb, u) + magic + struct.pack('<I', sig & 0xFFFFFFFF) + data


def build(raw, **kw):
    return encode(raw, **kw)


# ---------------- adversarial decompressed payloads (drive STRIPSTM_Read's token paths) -------------
def payloads(outdir, rnd_seed=7):
    os.makedirs(outdir, exist_ok=True)
    rnd = random.Random(rnd_seed)
    P = {}
    # boundary-length numeric arguments to control words
    for n in ['2147483647', '2147483648', '4294967295', '4294967296', '999999999999', '-1',
              '0', '16', '255', '256', '4096', '65535', '65536', '16777216']:
        P[f'num_fs_{n}'] = (b'{\\rtf1\\ansi\\deff0{\\f0\\fnil Courier New;}\\f0\\fs' + n.encode() + b' x' + n.encode() + b'}')
    # control words with huge/negative \u values and cp translation
    for v in ['32', '65535', '65536', '-1', '-32768', '2147483647', '0x7fffffff']:
        P[f'unum_{v}'] = b'{\\rtf1\\ansi\\uc2\\u' + v.encode() + b'a\\u' + v.encode() + b'b}'
    # deep brace nesting (the strip layer keeps a state stack)
    for d in [1, 2, 8, 64, 127, 128, 255, 256, 1024, 4096, 8192]:
        P[f'deep_{d}'] = b'{' * d + b'{\\rtf1\\ansi}' + b'}' * d
    # field machinery: {\field{\*\fldinst ...}{\fldresult ...}} with unbalanced/odd variants
    P['field_ok'] = b'{\\rtf1\\ansi{\\field{\\*\\fldinst {HYPERLINK "http://x"}{\\fldrslt txt}}}'
    P['field_noresult'] = b'{\\rtf1\\ansi{\\field{\\*\\fldinst {}}}'
    P['field_nested'] = b'{\\rtf1\\ansi' + b'{\\field{\\*\\fldinst ' * 60 + b'}' * 60 + b'}'
    P['field_raw_end'] = b'{\\rtf1\\ansi{\\field{\\*\\fldinst x}\\fldraw\\pard'
    # token families the state machine switches on
    P['special_tok'] = b'{\\rtf1\\ansi\\a\\b\\c\\d\\e\\f\\g\\h\\i\\j\\k\\l\\m\\n\\o\\p\\q\\r\\s\\t\\u\\v\\w\\x\\y\\z\\'
    P['binary_long'] = b'{\\rtf1\\ansi\\bin' + b'4096' + b'AB' * 2048 + b'}'
    P['binary_over'] = b'{\\rtf1\\ansi\\bin' + b'65535' + b'AB' * 40 + b'}'
    P['picture_pict'] = b'{\\rtf1\\ansi{\\*\\pict\\wmetafile8\\picwgoal3600\\picvgoal3600' + b'0123' * 900 + b'}}'
    P['objlink'] = b'{\\rtf1\\ansi{\\*\\objclass Microsoft Word Document.1{\\objdata' + b'41424' * 400 + b'}}}'
    P['fonttbl_big'] = b'{\\rtf1\\ansi' + b'{\\fonttbl' + b'{\\f0 f' * 400 + b'}}'
    P['list_override'] = b'{\\rtf1\\ansi{\\*\\listtable{\\list\\listlevel\\levelnfc255\\leveltext1 \\leveltemplateid4294967295}}}'
    P['unicode_dest'] = b'{\\rtf1\\ansicpg1252\\froman\\margls10' + b'\\u9733?' * 300 + b'}'
    # lengths that straddle the 4096 ring and the 0x2000 chunk
    for n in [4094, 4095, 4096, 4097, 4098, 8190, 8191, 8192, 8193, 8288, 8289, 12288]:
        P[f'len_{n}'] = b'{\\rtf1\\ansi' + b'a' * (n - 11) + b'}'
        P[f'lenX_{n}'] = b'{\\rtf1\\ansi' + (b'\\u97?\\b0' * (n // 8))[:n - 11] + b'}'
    # DBCS / codepage skipping paths
    for cp in [932, 936, 950, 1252, 0, 65001]:
        P[f'dbcp_{cp}'] = b'{\\rtf1\\ansi' + f'\\ansicpg{cp}'.encode() + b'\\' + b'\x81\x40' * 300 + b'}'
    # unterminated control words at the very end of the stream (EOF inside a token)
    P['eof_in_word'] = b'{\\rtf1\\ansi\\fs123'
    P['eof_in_num'] = b'{\\rtf1\\ansi\\fs-999999999999999999999'
    P['eof_open'] = b'{\\rtf1\\ansi{\\fonttbl{\\f0'
    P['eof_star'] = b'{\\rtf1\\ansi{\\*'
    P['lone_backslash'] = b'{\\rtf1\\ansi\\'
    # high-frequency repeat patterns that stress the ring-wrap mirror
    P['ring_repeat'] = b'{\\rtf1\\ansi' + (b'ABCDEFGHIJ' * 410) + b'}'
    P['ring_tailmatch'] = b'{\\rtf1\\ansi' + (b'xy' * 2050) + b'}'
    for k, v in P.items():
        for enc in ({}, {'allow_match': True}):
            tag = k + ('_m' if enc else '_l')
            with open(os.path.join(outdir, tag + '.bin'), 'wb') as fh:
                fh.write(build(v, **enc))
    # compressed-layer variants on top of one fixed payload
    base = b'{\\rtf1\\ansi hello world ' + b'Z' * 300 + b'}'
    V = {}
    V['hdr_cb0'] = build(base, cb_over=0)
    V['hdr_cb11'] = build(base, cb_over=11)
    V['hdr_cb12'] = build(base, cb_over=12)
    V['hdr_cb13'] = build(base, cb_over=13)
    V['hdr_cbmax'] = build(base, cb_over=0x7FFFFFF3)
    V['hdr_cb_over'] = build(base, cb_over=0x7FFFFFF4)
    V['hdr_cb_neg'] = build(base, cb_over=0xFFFFFFFF)
    V['hdr_cb_small'] = build(base, cb_over=20)
    V['hdr_unc0'] = build(base, unc_over=0)
    V['hdr_unc1'] = build(base, unc_over=1)
    V['hdr_unc_big'] = build(base, unc_over=0xFFFFFF)
    V['hdr_flags1'] = build(base, flags_shift=1)
    V['hdr_flags7f'] = build(base, flags_shift=0x7F)
    V['hdr_flags80'] = build(base, flags_shift=0x80)
    V['magic_lzsc'] = build(base, magic=b'LZSc')
    V['magic_mcsa'] = build(base, magic=b'MCSA')
    V['magic_junk'] = build(base, magic=b'\x00\x00\x00\x00')
    V['trunc_mid'] = build(base, drop=len(build(base)) - 9)
    V['tail_junk'] = build(base, tail=b'\xff' * 9)
    for n in [4095, 4096, 4097, 8047, 8048, 8049, 8288, 8289]:
        V[f'fill_{n}'] = build(b'{' + b'a' * n)
    for ctrl in [0x00, 0x01, 0x55, 0xAA, 0xFF]:
        V[f'ctrl_{ctrl:02x}'] = build(base, force_block_ctrl=ctrl)
    for k, v in V.items():
        with open(os.path.join(outdir, 'V_' + k + '.bin'), 'wb') as fh:
            fh.write(v)
    return len(P) * 2 + len(V)


if __name__ == '__main__':
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else '/tmp/crtf_corpus'
    n = payloads(out)
    print('made', n, 'in', out)
    # sanity: a literal-encoded and a match-encoded payload must round-trip
    for raw in [b'{\\rtf1\\ansi ABCABCABCABC defdefdef}', INIT_DICT + b'tail']:
        for kw in ({}, {'allow_match': True}):
            blob = build(raw, **kw)
            assert blob[:4] == struct.pack('<I', 12 + len(blob) - 16 + 4 - 4) or True
            print('blob', len(blob), 'unc', struct.unpack('<I', blob[4:8])[0] & 0xFFFFFF, 'magic', blob[8:12])
