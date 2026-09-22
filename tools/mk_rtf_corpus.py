#!/usr/bin/env python3
"""RTF carriers aimed at wwlib's counted-string / counted-array loaders.

Every form changes one counted field or one nesting/token structure that the RTF reader
turns into an allocation, so an armed page heap sees the boundary of each fill:

  * \\atnauth / \\atnnext   -> FFinishAtn side attribute strings
  * {\\stylesheet} names    -> style table name copies
  * {\\listtemplate}{\\listtext} -> list name / style name writes (ChngToRdsList*)
  * \\bin<N> with declared length vs actual bytes
  * \\pict \\picwgoal with dimension text lengths, \\shppict parts
  * numeric control words past 2^31, negative, and with trailing space vs not
  * \\'xx hex runs, \\u<N> unicode escapes with mismatched \\ucN
  * long control words (name > 255), unknown groups, deep nesting

usage: mk_rtf_corpus.py <outdir> [cap]
"""
import os
import sys

HEAD = '{\\rtf1\\ansi\\ansicpg1252\\deff0\\deflang1033'


def w(d, name, text):
    p = os.path.join(d, name)
    open(p, 'wb').write(text if isinstance(text, bytes) else text.encode('latin-1', 'replace'))
    return p


def num_forms():
    """numeric argument boundary set for a generic counted control word"""
    vals = ['0', '1', '2', '-1', '-2147483648', '2147483647', '2147483648', '4294967295',
            '4294967296', '99999999999999', '0x10', '1e5', ' ', '-', '+', '1-2', '0777',
            '65535', '65536', '32767', '32768', '255', '256', '16384', '1048576']
    out = []
    for i, v in enumerate(vals):
        # \fN font declaration table index
        out.append(('rtf_font_%03d.doc' % i,
                    HEAD + '{\\fonttbl{\\f%d\\froman Times New Roman;}}' % 0 +
                    '{\\pard x\\par}' + '}'))
        # long text under a control word whose argument is the boundary value
        out.append(('rtf_num_%03d.doc' % i,
                    HEAD + '{\\stylesheet {\\s%d StyleName%s;}}' % (0, 'A' * int(abs(hash(v)) % 40)) +
                    '\\pard ' + v + ' abc\\par}'))
    return out


def bin_forms():
    out = []
    for declared in ['0', '1', '8', '16', '32', '64', '100', '255', '256', '1024', '65535',
                     '65536', '2147483647', '-1', '4294967295']:
        for actual in [0, 4, 16, 64]:
            payload = bytes(range(256)) * 2
            out.append(('rtf_bin_%s_%03d.doc' % (declared.replace('-', 'm'), actual),
                        HEAD + '\\pict\\pngblip\\bin' + declared + ' ' +
                        payload[:actual].hex() + '}'))
    return out


def atn_forms():
    """\\atnauth / \\atnnext -> the author-string family FFinishAtn copies"""
    out = []
    lens = [0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512,
            1023, 1024, 4095, 4096]
    for i, n in enumerate(lens):
        body = ('\\atnauth ' + 'A' * n + '\n' + '\\atnnext ' + 'B' * max(0, n - 1) + '\n')
        out.append(('rtf_atn_%03d.doc' % i,
                    HEAD + '{\\rtf1\\ansi' + body + '}' + '{\\pard txt\\par}'))
        # hex-escaped author string of the same length (different code path)
        hx = ''.join('\\x%02x' % (0x41 + (j % 26)) for j in range(n))
        out.append(('rtf_atnhex_%03d.doc' % i,
                    HEAD + '{\\rtf1\\ansi\\atnauth ' + hx + '\\atnnext ' + hx + '}'))
        # unicode escapes with mismatching \ucN
        out.append(('rtf_atnu_%03d.doc' % i,
                    HEAD + '\\uc1{\\atnauth ' + ''.join('\\u%d?' % (0x4e00 + j % 8) for j in range(n)) +
                    '}'))
    return out


def style_forms():
    out = []
    lens = [1, 8, 31, 32, 63, 64, 127, 128, 254, 255, 256, 511, 512, 1023, 1024, 4000]
    for i, n in enumerate(lens):
        nm = 'S' * n
        out.append(('rtf_style_%03d.doc' % i,
                    HEAD + '{\\stylesheet{\\s0\\snext0 ' + nm + ';}{\\s1 ' + nm[:-1] + ';}}'))
        out.append(('rtf_styledbl_%03d.doc' % i,
                    HEAD + '{\\stylesheet' + ('{\\s0 ' + nm + ';}' * 4) + '}'))
        out.append(('rtf_stylehex_%03d.doc' % i,
                    HEAD + '{\\stylesheet{\\s0 ' + ''.join('\\%02x' % (0x41 + j % 26)
                                                          for j in range(n)) + ';}}'))
        out.append(('rtf_styleunicode_%03d.doc' % i,
                    HEAD + '\\uc2{\\stylesheet{\\s0 ' + ''.join('\\u%d?' % (0x2000 + j)
                                                               for j in range(n)) + ';}}'))
    return out


def list_forms():
    out = []
    for i, n in enumerate([1, 4, 16, 32, 64, 128, 255, 256, 512, 1024, 2048]):
        lt = ''.join('{\\list\\listlevel\\levelnfc0\\leveltext%02d\\lvltext %s;}'
                     '\\listtemplatekey ltp%02d}' % (j % 97, 'L' * n, j) for j in range(3))
        out.append(('rtf_list_%03d.doc' % i, HEAD + '{\\listtable' + lt + '}' +
                    '{\\fonttbl{\\f0 Times;}}'))
        fonts = ''.join('{\\f%d\\froman %s;}' % (j, 'F' * n) for j in range(3))
        out.append(('rtf_fonts_%03d.doc' % i, HEAD + '{\\fonttbl' + fonts + '}'))
    return out


def pict_forms():
    out = []
    for tag, extra in [('png', '\\pngblip'), ('jpeg', '\\jpegblip'), ('emf', '\\emfblip'),
                       ('wmf', '\\wmetafile8'), ('shp', 'shppict'), ('pict', ''),
                       ('metafilepict', '\\macpict')]:
        for n in [0, 4, 32, 256, 4096]:
            payload = 'ab' * (n // 2)
            out.append(('rtf_pict_%s_%04d.doc' % (tag, n),
                        HEAD + '{\\pict' + extra + '\\picwgoal1440\\pichgoal1440 '
                        + payload + '}' + '{\\pard x\\par}'))
        # nested object with \objdata inside \pict
        out.append(('rtf_pict_%s_obj.doc' % tag,
                    HEAD + '{\\pict\\objd \\objautlink' + extra +
                    '\\objdata{\\pict' + extra + 'deadbeef}}'))
    return out


def struct_forms():
    out = []
    # deep group nesting
    for d in [1, 2, 8, 16, 63, 64, 65, 127, 128, 255, 256, 512, 1024, 4096, 20000]:
        out.append(('rtf_nest_%05d.doc' % d, HEAD + ('{' * d) + 'x' + ('}' * d)))
        out.append(('rtf_nestbad_%05d.doc' % d, HEAD + ('{' * d) + 'x'))
    # ignored destinations
    for tag, grp in [('aftnc', '{\\*\\atncR'), ('nonshppict', '{\\*\\nonshppict'),
                     ('bkmkstart', '{\\*\\bkmkstart'), ('xmlopen', '{\\xmlopen'),
                     ('themedata', '{\\xmlnestedintheme'), ('fontsembedded', '{\\*\\fontscheme')]:
        for n in [8, 256, 65536]:
            out.append(('rtf_ign_%s_%05d.doc' % (tag, n),
                        HEAD + grp + ' ' + 'Z' * n + '}' + '{\\pard x\\par}'))
    # unterminated control words and stray backslashes
    for tag, body in [('trail_bs', '\\\\'), ('nul', '\x00'), ('cr_only', '\r'),
                      ('lone_tilde', '~'), ('brace_esc', '\\{\\}'), ('star_nogroup', '{\\*}'),
                      ('esc2', '\\\\\n'), ('col_semi', ';:'), ('longword', '\\' + 'k' * 400)]:
        out.append(('rtf_odd_%s.doc' % tag, HEAD + body + '{\\pard x\\par}'))
    # hex escapes near boundaries
    for n in [1, 2, 3, 31, 32, 33, 255, 256, 257, 4096]:
        out.append(('rtf_hex_%04d.doc' % n,
                    HEAD + '{\\pard ' + ''.join('\\%02x' % (i % 256) for i in range(n)) + '\\par}'))
    return out


def main():
    out = sys.argv[1]
    cap = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    os.makedirs(out, exist_ok=True)
    groups = [('num', num_forms()), ('bin', bin_forms()), ('atn', atn_forms()),
              ('style', style_forms()), ('list', list_forms()), ('pict', pict_forms()),
              ('struct', struct_forms())]
    flat = []
    depth = max(len(i) for _, i in groups)
    for k in range(depth):
        for g, items in groups:
            if k < len(items):
                flat.append(items[k])
    made = []
    for name, text in flat:
        if cap and len(made) >= cap:
            break
        made.append(w(out, name, text))
    print('groups=%s sizes=%s cases=%d' % ([g for g, _ in groups], [len(i) for _, i in groups], len(made)))


if __name__ == '__main__':
    main()
