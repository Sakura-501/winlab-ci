#!/usr/bin/env python3
"""Dense single-quantity iCalendar / vCalendar / vCard corpus for the in-process MIMEDIR probe.

The existing generators (mut_ics.py, mut_ics3.py) randomise around the fold boundary and mutate bytes
in place. A copy loop that overshoots only for particular remainders - "move 8 bytes at a time, then
write the tail with one wide store", or "allocate for N elements, write N+1 in the last chunk" - is
unlikely to be hit by random mutation and is exactly what a dense walk of one quantity catches. Here
every file is a well-formed document except for the single number being swept.

Output: one file per case in the given directory, CRLF line endings, names prefixed with the axis so a
fault can be read back to the quantity that produced it.
"""
import base64
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "icsdense"
DENSE = list(range(1, 121))
EDGE = [127, 128, 129, 191, 192, 255, 256, 257, 383, 384, 511, 512, 513, 1023, 1024, 4095, 4096]
os.makedirs(OUT, exist_ok=True)
made = 0


def put(name, lines):
    global made
    data = "\r\n".join(lines) + "\r\n"
    open(os.path.join(OUT, name), "wb").write(data.encode("latin-1", "replace"))
    made += 1


def fold(line, width=74):
    """RFC 5545 folding: continuation lines start with a single space."""
    if len(line) <= width:
        return [line]
    out, i = [], 0
    while i < len(line):
        out.append(line[i:i + width] if i == 0 else " " + line[i + 1:i + width])
        i += width - 1 if i else width
    return out


def ics(body, tail=None):
    l = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//dense//EN", "CALSCALE:GREGORIAN",
         "METHOD:PUBLISH", "BEGIN:VEVENT", "UID:dense-1@example.invalid",
         "DTSTAMP:20260923T000000Z"]
    l += body
    l += ["END:VEVENT"]
    if tail:
        l += tail
    l += ["END:VCALENDAR"]
    return l


# 1. plain property value length, dense, folded canonically
for L in DENSE + EDGE:
    put("len_%05d.ics" % L, ics(["SUMMARY:" + "a" * L, "DTSTART:20260923T090000Z",
                                 "DTEND:20260923T100000Z"]))
# 2. one long logical line, folded at a boundary-sensitive width
for W in (73, 74, 75, 76, 127, 128, 129):
    for L in DENSE[:60]:
        put("fold%03d_%04d.ics" % (W, L), ics(fold("DESCRIPTION:" + "b" * L, W)))
# 3. number of ATTENDEE lines (recipient array)
for N in DENSE + [127, 128, 129, 255, 256, 257]:
    body = ["DTSTART:20260923T090000Z", "ORGANIZER:mailto:o@example.invalid"]
    body += ["ATTENDEE;CN=u%d;RSVP=TRUE:mailto:u%d@example.invalid" % (i, i) for i in range(N)]
    put("att_%05d.ics" % N, ics(body))
# 4. comma-separated multi-value list on one line (EXDATE / RDATE)
for N in DENSE + [127, 128, 129, 255, 256]:
    vals = ",".join("2026%02d%02dT%02d0000Z" % ((i % 12) + 1, (i % 27) + 1, i % 24) for i in range(N))
    put("exd_%05d.ics" % N, ics(["DTSTART:20260923T090000Z", "EXDATE:" + vals]))
# 5. RRULE expansion count (instances the expander materialises)
for N in DENSE + [255, 256, 257, 1000, 4096, 65535, 65536]:
    put("rrc_%06d.ics" % N, ics(["DTSTART:20260923T090000Z", "DTEND:20260923T100000Z",
                                 "SUMMARY:recurring", "RRULE:FREQ=DAILY;COUNT=%d" % N]))
# 6. escape sequences (2 source bytes -> 1 stored byte)
for N in DENSE:
    put("esc_%05d.ics" % N, ics(["SUMMARY:" + ("\\n\\,\\;" * (N // 3)) + "\\N" * (N % 3),
                                 "DTSTART:20260923T090000Z"]))
# 7. base64 payload length (decoder output buffer vs input length)
for L in DENSE + [255, 256, 257, 1023, 1024]:
    raw = ("z" * L)[:L]
    b64 = base64.b64encode(raw.encode()).decode()
    put("b64_%05d.ics" % L, ics(["DTSTART:20260923T090000Z",
                                 "ATTACH;VALUE=BINARY;ENCODING=BASE64:" + b64]))
# 8. parameter value length (parameter parser)
for L in DENSE + [127, 128, 129, 255, 256, 257]:
    put("prm_%05d.ics" % L, ics(["DTSTART:20260923T090000Z",
                                 'ATTENDEE;CN="' + "p" * L + '";ROLE=REQ-PARTICIPANT:mailto:x@example.invalid']))
# 9. repeated sub-components (VTIMEZONE offsets, VALARM per event)
for N in DENSE[:80] + [127, 128, 129]:
    tail = []
    for i in range(N):
        tail += ["BEGIN:VALARM", "ACTION:DISPLAY", "DESCRIPTION:alarm %d" % i,
                 "TRIGGER:-PT%dM" % (i % 60), "END:VALARM"]
    put("alm_%05d.ics" % N, ics(["DTSTART:20260923T090000Z", "SUMMARY:alarmed"], tail))
# 10. vCalendar (the older flavour the same module serves) with dense item count
for N in DENSE[:60] + [127, 128]:
    l = ["BEGIN:VCALENDAR", "VERSION:1.0", "PRODID:-//dense vcal//EN"]
    for i in range(N):
        l += ["BEGIN:VEVENT", "DTSTART:20260923T090000Z", "SUMMARY:item %d" % i, "END:VEVENT"]
    l += ["END:VCALENDAR"]
    put("vcs_%05d.vcs" % N, l)
# 11. vCard: property lengths and repeated TYPE parameters
for L in DENSE + [255, 256, 257]:
    put("vcf_%05d.vcf" % L, ["BEGIN:VCARD", "VERSION:3.0", "N:" + "n" * L + ";" + "f" * L,
                             "FN:" + "c" * L, "TEL;TYPE=" + ",".join(["WORK"] * (1 + L % 7)) + ":+15551234",
                             "EMAIL;TYPE=INTERNET:v%s@example.invalid" % ("e" * (L % 40)), "END:VCARD"])
print("made=%d dir=%s" % (made, OUT))
