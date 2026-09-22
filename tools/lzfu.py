"""MS-OXRTFCP 'LZFu' helpers + stream patcher for a .msg CFB."""
import struct, sys
sys.path.insert(0, "tools")
from msgcfb import CFB

INIT_DICT = (b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern "
             b"\\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n"
             b"\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx")
assert len(INIT_DICT) == 207, len(INIT_DICT)

def compress(raw):
    """all-literal blocks + one back-reference at the end (so both paths are present)"""
    out = bytearray()
    i = 0
    while i < len(raw):
        ctrl = 0
        blk = bytearray()
        for b in range(8):
            if i >= len(raw): break
            blk.append(raw[i]); i += 1
        out.append(ctrl); out += blk
        if len(out) > 4 * (len(raw) + 16): break
    return bytes(out)

def header(cbdata, cbraw, magic=b"LZFu"):
    return struct.pack("<II", cbdata, cbraw) + magic

def build_stream(raw, cbdata=None, cbraw=None, magic=b"LZFu", tail=b"", drop=None):
    d = compress(raw)
    if tail: d = d + tail
    if drop is not None: d = d[:drop]
    cd = len(d) if cbdata is None else cbdata
    cr = len(raw) if cbraw is None else cbraw
    return header(cd, cr, magic) + d

def patch_msg(path_in, path_out, data):
    c = CFB(open(path_in, "rb").read())
    e = [x for x in c.entries if x["name"] == "__substg1.0_10090102"][0]
    new = bytearray(data)
    pad = ((len(new) + 63) // 64) * 64
    new += b"\0" * (pad - len(new))
    out = c.write_mini("__substg1.0_10090102", bytes(new))
    # fix the directory size field for that entry
    off = 512 + e["sect"] * c.SS + e["off_in_sect"] + 120
    b = bytearray(out)
    struct.pack_into("<Q", b, off, len(data))
    open(path_out, "wb").write(bytes(b))
    return len(data), e["start"], off
