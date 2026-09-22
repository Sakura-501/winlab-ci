r"""Grammar-targeted corpus for the OLMAPI32 RTF-sync layer (RTFSync -> ScFullRTFSync / ScUpdateRTF).

Every payload here is a decompressed RTF body: the LZFu layer only transports it, so the mutation
budget goes into what the strip/sync state machine reads -- body-tag control words, numeric
arguments at the buffer/counter boundaries (64/100/112/128/0x2000), the two chunk strings the
sender/delegation path feeds, font tables, \u translation runs, and unterminated tokens.
"""
import os, sys, struct, random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lzfu_mut import build
from mk_msg_corpus import patch as patch_msg


def head(uc=1, cp='\\ansicpg1252'):
    return ('{\\rtf1\\ansi' + cp + '\\deff0{\\fonttbl{\\f0\\fnil MS Sans Serif;}}').encode()


def sync_payloads(P):
    # body-tag machinery (MS-OXRTFSY): \*\bodytagn <digits> ; \*\benc ; \fromhtml1
    for n in ['0', '1', '9', '10', '18', '19', '20', '21', '33', '34', '35', '63', '64', '65',
              '99', '100', '101', '111', '112', '113', '127', '128', '129', '255', '256',
              '1000', '4096', '65535', '65536', '2147483647', '2147483648', '4294967295']:
        P['bt_' + n] = head() + ('{\\*\\bodytagn ' + n + ' }{\\*\\benc0}text\\par }').encode()
        P['btX_' + n] = head() + ('\\fromhtml1{\\*\\bodytagn ' + n + 'x}' + ('a' * int(min(int(n), 4096) or 1)) + '}').encode()
    # font names / one-off strings that flow into the chunk's two inline strings
    for L in [1, 2, 15, 16, 17, 32, 33, 34, 35, 52, 53, 63, 64, 73, 74, 90, 100, 120, 127, 128, 129, 200, 255, 256, 512]:
        P['fnA_' + str(L)] = head().replace(b'MS Sans Serif', b'A' * L) + b'x}'
        P['fnB_' + str(L)] = head() + ('{\\field{\\*\\fldinst {HYPERLINK "' + ('b' * L) + '"}}{\\fldrslt r}}').encode() + b'}'
        P['mail_' + str(L)] = head() + ('{\\*\\ud' + ('c' * L) + '}{\\rtlch none}').encode() + b'}'
    # \ucN codepage translation runs (TranslateCP / ScCodePageConvert path)
    for uc in [0, 1, 2, 6, 31, 32, 33, 63, 64, 127, 128, 0xFFFF, 2147483647]:
        for rep in [1, 8, 64, 128, 512]:
            P[f'uc{uc}_r{rep}'] = ('{\\rtf1\\ansi\\uc' + str(uc) + '}').encode() + (b'\\u' + str(0x4E00).encode() + b'?' * min(uc if uc < 64 else 1, 8)) * rep + b'}'
    # DBCS lead/trail splits at every buffer boundary
    for L in [16, 32, 33, 63, 64, 65, 99, 100, 111, 112, 127, 128]:
        P['dbcs_' + str(L)] = head(cp='\\ansicpg932') + (b'\\' + b'\x81\x40' * L) + b'}'
    # unterminated tokens and EOF-in-the-middle of each sync-relevant control word
    for kw in [b'\\*\\bodytagn ', b'\\*\\benc', b'\\fromhtml1\\fromimage1', b'\\uc', b'\\ansicpg', b'\\*', b'\\*\\', b'{\\*\\ud']:
        P['eof_' + kw.decode('latin1').replace('\\', '').replace('{', '').replace('}', '').replace('*', 'S')] = head() + kw
    # repeated aux props and multiple body tags in one document (two-pass sync arithmetic)
    for k in [2, 3, 8, 40, 100, 101]:
        P['multi_bt_' + str(k)] = head() + (b'{\\*\\bodytagn 18 }' * k) + b'}'
        P['multi_html_' + str(k)] = (b'{\\rtf1\\ansi' + b'\\fromhtml1' * k) + b'}'
    # lengths that cross the 0x2000 chunk and 4096 window exactly, with/without matches
    for L in [4093, 4094, 4095, 4096, 4097, 8189, 8190, 8191, 8288, 8289, 8290, 12287, 12288]:
        P['win_' + str(L)] = head() + (b'a' * (L - len(head()))) + b'}'
        P['winmix_' + str(L)] = head() + (b'abcdefgh' * ((L - len(head())) // 8 + 1))[:L - len(head())] + b'}'
    return P


def main():
    base, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    P = sync_payloads({})
    made = 0
    for k, raw in sorted(P.items()):
        for tag, kw in (('l', {}), ('m', {'allow_match': True})):
            blob = build(raw, **kw)
            tmp = os.path.join(out, '_p_' + k + '_' + tag + '.bin')
            open(tmp, 'wb').write(blob)
            try:
                patch_msg(base, os.path.join(out, f's_{k}_{tag}.msg'), blob)
                made += 1
            except BaseException as ex:
                print('skip', k, tag, ex)
            os.remove(tmp)
    print('made', made, 'of', len(P) * 2, '->', out)


if __name__ == '__main__':
    main()
