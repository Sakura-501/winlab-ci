#!/usr/bin/env python3
"""ppt_html_carriers.py -- .htm/.html/.mht decks whose structure makes PowerPoint's own HTML
import build slide/shape references that may not materialise.

Why HTML rather than hand-written <p:timing>: PowerPoint *synthesises* build/animation nodes while
importing HTML (list nesting becomes builds), and the importer's slide assembly ends with
`TimeXMLImportSite::FixupOAVReferences` -> `FValidateSlideTiming`.  So a structural oddity in the
HTML can produce the dangling-target state through the application's own code instead of through a
hand-authored tree.  Every dimension below is a single-variable change against `h01_plain`:

  h01_plain                control: two slides, two list levels
  h02_empty_items          list items that carry no text
  h03_nested_deep          five nesting levels (five synthesised build levels)
  h04_hidden               items hidden with visibility/display styles
  h05_div_in_li            a nested <div class=Slide> inside a list item
  h06_vml_spid_absent      VML group with o:spid values that name no shape
  h07_spid_dupe            two VML shapes sharing one o:spid
  h08_table_lists          lists nested inside table cells
  h09_img_missing_part     <img> pointing at a part the package does not contain
  h10_many_items           40 items in one list (iteration-count stress)
  h11_mht_orphan_part      MHTML whose Content-Location names a part no link refers to
"""
import os
import sys

HEAD = ('<html xmlns:o="urn:schemas-microsoft-com:office:office" '
        'xmlns:v="urn:schemas-microsoft-com:vml" '
        'xmlns="http://www.w3.org/TR/REC-html40">'
        '<head><meta name=Generator content="Microsoft PowerPoint 16">'
        '<title>%(title)s</title></head><body>')
TAIL = "</body></html>"

SLIDE = ('<div class=Slide%(extra)s><ul>'
         '%(items)s</ul></div>')


def li(text, lvl=1, style=""):
    st = (" style='%s'" % style) if style else ""
    return ('<li style="mso-level-number-format:bullet;mso-ansi-level-percent-left:{pct}%"'
            '{st}><span{st}>{t}</span></li>').format(pct=lvl * 100, st=st, t=text)


def deck(items_by_slide, extra_by_slide=None):
    parts = [HEAD % {"title": "ppt html carrier"}]
    for i, items in enumerate(items_by_slide):
        parts.append(SLIDE % {"extra": (extra_by_slide or {}).get(i, ""), "items": "".join(items)})
    parts.append(TAIL)
    return "\r\n".join(parts)


MHT = ("Content-Type: multipart/related; boundary=\"----_=_NextPart_PPTHTML\"\r\n"
       "Subject: ppt html carrier\r\n\r\n"
       "------_=_NextPart_PPTHTML\r\n"
       "Content-Location: index.htm\r\n"
       "Content-Transfer-Encoding: quoted-printable\r\n"
       "Content-Type: text/html; charset=\"utf-8\"\r\n\r\n"
       "%(html)s\r\n"
       "------_=_NextPart_PPTHTML\r\n"
       "Content-Location: orphanpart.png\r\n"
       "Content-Transfer-Encoding: base64\r\n"
       "Content-Type: image/png\r\n\r\n"
       "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==\r\n"
       "------_=_NextPart_PPTHTML--\r\n")


def build(outdir):
    os.makedirs(outdir, exist_ok=True)
    plain = deck([[li("alpha"), li("beta", 2)], [li("gamma")]])
    files = {"h01_plain.htm": plain}

    files["h02_empty_items.htm"] = deck([[li(""), li("   "), li("delta", 2)], [li("")]])
    files["h03_nested_deep.htm"] = deck([[li("l1"), li("l2", 2), li("l3", 3), li("l4", 4), li("l5", 5)],
                                        [li("again", 3)]])
    files["h04_hidden.htm"] = deck([[li("shown"),
                                     li("hidden1", 2, "visibility:hidden"),
                                     li("hidden2", 2, "display:none")],
                                    [li("x", 1, "visibility:hidden")]])
    files["h05_div_in_li.htm"] = deck([[li("outer"),
                                        '<li><div class=Slide><ul>' + li("inner") + '</ul></div></li>'],
                                       [li("tail")]])
    vml = ('<v:group o:spid="_x0000_s9001" style="position:absolute;left:0;top:0;width:100pt;height:80pt">'
           '<v:rect o:spid="_x0000_s9002" filled="t" fillcolor="#ff0000" '
           'style="position:absolute;left:0;top:0;width:50pt;height:40pt"></v:rect>'
           '<v:oval o:spid="_x0000_s9002" filled="f" '
           'style="position:absolute;left:20pt;top:20pt;width:50pt;height:40pt"></v:oval>'
           '</v:group>')
    files["h06_vml_spid_absent.htm"] = deck([[li("before vml")],
                                             ['<div class=Slide>' + vml.replace('_x0000_s9001', '_x0000_s7777') + '</div>']])
    files["h07_spid_dupe.htm"] = deck([[li("dupe")], ['<div class=Slide>' + vml + '</div>']])
    files["h08_table_lists.htm"] = deck([[('<table><tr><td><ul>' + li("cell item") + li("cell item2", 2) +
                                           '</ul></td><td>' + li("outside") + '</td></tr></table>')],
                                         [li("after")]])
    files["h09_img_missing_part.htm"] = deck([[li("pic slide"),
                                               ('<img src="missingpart.png" o:spid="_x0000_i1025" '
                                                'alt="x" width="40" height="40">')],
                                              [li("z")]])
    files["h11_mht_orphan_part.mht"] = MHT % {"html": plain}
    many = [li("item %d" % k, 1 + (k % 4)) for k in range(40)]
    files["h10_many_items.htm"] = deck([many, [li("end")]])

    for name, body in sorted(files.items()):
        p = os.path.join(outdir, name)
        with open(p, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(body)
        print("wrote %s %d" % (p, len(body)))
    print("carriers=%d" % len(files))


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "carriers_h")
