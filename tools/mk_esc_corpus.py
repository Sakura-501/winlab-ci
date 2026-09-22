r"""Escape-expansion focused corpus: ScTextToRTF turns each of < > & " into a 38-40 byte
htmltag/htmlrtf sequence when the state is in HTML mode (\fromhtml1), so 1 input byte can
become 40 output bytes. Dense runs of those four characters, at lengths around the destination
counters (112-byte body-tag buffer, the _state remaining-bytes field, 0x2000 chunk), are the
payloads this generator makes.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lzfu_mut import build
from mk_msg_corpus import patch as patch_msg

def head(html=True):
    h = b'{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0\\fnil MS Sans Serif;}}'
    if html:
        h += b'\\fromhtml1'
    return h

def main(base, out):
    os.makedirs(out, exist_ok=True)
    P = {}
    for n in [1, 2, 3, 5, 10, 28, 29, 56, 57, 100, 112, 128, 200, 512, 1000, 2048, 4096]:
        for name, ch in (('lt', b'<'), ('gt', b'>'), ('amp', b'&'), ('quot', b'"'), ('mix', b'<>&"')):
            body = (ch * n) if name != 'mix' else (b'<>&"' * ((n + 3) // 4))[:n]
            P[f'e_{name}_{n}'] = head() + b'{\\*\\bodytagn 18 }' + body + b'\\par }'
            P[f'en_{name}_{n}'] = head(html=False) + b'{\\*\\bodytagn 18 }' + body + b'\\par }'
        # escapes interleaved with the aux-prop control words the sync layer rewrites
        P[f'e_seq_{n}'] = head() + (b'<a>&b"\\u65?c' * ((n + 7) // 8))[:n] + b'}'
        # url-ish payloads: the htmltag path also runs through the field/hyperlink code
        P[f'e_url_{n}'] = head() + b'{\\field{\\*\\fldinst {HYPERLINK "' + b'&<>"' * ((n + 3) // 4) or b'' + b'"}}{\\fldrslt x}}'
    made = 0
    for k, raw in sorted(P.items()):
        for tag, kw in (('l', {}), ('m', {'allow_match': True})):
            blob = build(raw, **kw)
            try:
                patch_msg(base, os.path.join(out, f'e_{k}_{tag}.msg'), blob)
                made += 1
            except BaseException as ex:
                print('skip', k, tag, type(ex).__name__, ex)
    print('made', made, 'of', len(P) * 2, '->', out)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
