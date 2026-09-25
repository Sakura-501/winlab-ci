#!/usr/bin/env python3
"""eml_from_htm.py -- wrap existing .htm carriers into .eml messages, one file per carrier.

The HTML body is copied verbatim, so a reading taken through the `.eml` channel is a single-variable
change against the `.htm` channel (same body, different delivery): the only differences are the
RFC822/MIME envelope and which application parses it.

Why a second channel: `.htm` reaches Protected View in Word (PV=1) while PowerPoint opens it without
PV, and an inbound HTML message body is the path the mso HTML importer was written for.  `.eml` has no
Protected View in this lab's matrix, and OUTLOOK.EXE registers
`...\\OUTLOOK.EXE /eml "%1"` under HKCR:\\Outlook.File.eml.15\\shell\\open\\command, so the wave launches
that exact form instead of relying on a user choice.

Each message carries `Subject: GTMSG<basename>END` as the per-file observer: Outlook is single-process
and multi-window, so a process-level window title cannot attribute a file.  The marker survives into
the reading window's title, which is what the probe matches on.

    eml_from_htm.py <src-dir-with-htm> <dest-dir>
"""
import glob
import os
import sys

HEADERS = [
    'From: "Ann Example" <ann@example.invalid>',
    'To: user@example.invalid',
    'Subject: GTMSG{mark}END',
    'Date: Thu, 25 Sep 2026 10:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset="us-ascii"',
    'Content-Transfer-Encoding: 7bit',
]


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else 'carriers_h'
    dst = sys.argv[2] if len(sys.argv) > 2 else 'carriers_e'
    os.makedirs(dst, exist_ok=True)
    n = 0
    for p in sorted(glob.glob(os.path.join(src, '*.htm')) + glob.glob(os.path.join(src, '*.html'))):
        base = os.path.splitext(os.path.basename(p))[0]
        body = open(p, 'rb').read()
        mark = base.replace(' ', '_')
        head = '\r\n'.join(HEADERS).format(mark=mark).encode('ascii')
        with open(os.path.join(dst, base + '.eml'), 'wb') as fh:
            fh.write(head + b'\r\n\r\n' + body + b'\r\n')
        n += 1
    print('eml=%d dest=%s' % (n, dst))
    if n == 0:
        raise SystemExit('NO_INPUT_CARRIERS: nothing to wrap, a 0-hit wave would be meaningless')


if __name__ == '__main__':
    main()
