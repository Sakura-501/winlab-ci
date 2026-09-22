"""Build a .msg corpus: base_valid.msg with __substg1.0_10090102 replaced by adversarial
LZFu streams (MS-OXRTFCP) whose *decompressed* content is the RTF payload family from lzfu_mut.py.
Usage: python3 mk_msg_corpus.py <base.msg> <payloads_dir> <out_dir>
"""
import os, sys, glob, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from msgcfb import CFB
from lzfu_mut import encode, INIT_DICT

sys.setrecursionlimit(10000)


def read_stream(c, name):
    for e in c.entries:
        if e['name'] == name:
            return c.read_stream(name)
    return None


def patch(path_in, path_out, data):
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


def main():
    base, pdir, out = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(out, exist_ok=True)
    blobs = sorted(glob.glob(os.path.join(pdir, '*.bin')))
    if not blobs:
        # fall back: generate payloads straight from lzfu_mut's builders
        tmp = os.path.join(out, '_bins')
        n = __import__('lzfu_mut').payloads(tmp)
        blobs = sorted(glob.glob(os.path.join(tmp, '*.bin')))
    made = 0
    for b in blobs:
        data = open(b, 'rb').read()
        name = 'm_' + os.path.basename(b).replace('.bin', '') + '.msg'
        try:
            real = patch(base, os.path.join(out, name), data)[0]
            made += 1
        except SystemExit as ex:
            print('skip', os.path.basename(b), ex)
            continue
    print('made', made, 'of', len(blobs), '->', out)
    for probe in sorted(glob.glob(os.path.join(out, 'm_*.msg')))[:3]:
        c = CFB(open(probe, 'rb').read())
        st = c.read_stream('__substg1.0_10090102') or b''
        print(' ', os.path.basename(probe), 'entries', len(c.entries), 'rtf_len', len(st), 'head', st[:16].hex())


if __name__ == '__main__':
    main()
