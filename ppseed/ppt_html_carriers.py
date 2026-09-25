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
  h17..h30                 div/span nesting and text-run-length shapes (see the block comment)
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

    # div/span balance dimensions for the mso FCommitDivSpanCore length path
    files["h12_div_unclosed.htm"] = deck([[li("a"), ('<div class=Slide><ul>' + li("b") + '</ul>')],
                                          [li("c")]])
    files["h13_span_close_div.htm"] = deck([[li("a"), '<span class=X>' + li("b") + '</div>'],
                                            [li("c")]])
    files["h14_div_in_span.htm"] = deck([[('<div><span>' + li("nested") + '</span></div>')],
                                         [li("d")]])
    files["h15_many_close.htm"] = deck([[li("a"), ('</div>' * 6 + li("b"))], [li("c"), '</span></span>']])
    files["h16_empty_div_slide.htm"] = deck([['<div class=Slide></div>'], [li("only")]])
    # ---- div/span commit-length family: shapes that re-enter the div/span commit loop while an
    # outer commit is still running, and shapes that vary the text-run length around the
    # "|fetched count| <= used elements" magnitude check inside FCommitDivSpanCore.
    def run(text):
        return '<span>%s</span>' % text

    files["h17_div_in_div.htm"] = deck([[('<div class=Slide><div class=Slide>' + li("inner") +
                                          '</div>' + li("after inner close") + '</div>')], [li("t")]])
    files["h18_span_in_span.htm"] = deck([[('<span><span>' + li("deep") + '</span>' + li("tail") + '</span>')],
                                          [li("u")]])
    files["h19_div_after_span_open.htm"] = deck([[('<span class=Slide><div>' + li("swapped") +
                                                   '</div></span>')], [li("v")]])
    files["h20_two_div_open_one_close.htm"] = deck([[('<div class=Slide><div class=Slide>' + li("two one") +
                                                      '</div>')], [li("w")]])
    files["h21_list_inside_div_close_then_text.htm"] = deck([[('<div class=Slide><ul>' + li("l") +
                                                               '</ul></div>' + li("text after close"))],
                                                             [li("x")]])
    files["h22_table_inside_div.htm"] = deck([[('<div class=Slide><table><tr><td>' + li("c1") +
                                                '</td><td>' + li("c2") + '</td></tr></table>' +
                                                li("after table") + '</div>')], [li("y")]])
    for n, ln in (("h23_longrun_120.htm", 120), ("h24_longrun_1200.htm", 1200),
                  ("h25_longrun_4000.htm", 4000), ("h26_longrun_66000.htm", 66000)):
        files[n] = deck([[('<div class=Slide>' + run("z" * ln) + '</div>' + li("after"))], [li("q")]])
    files["h27_close_before_open.htm"] = deck([[('</div>' + li("orphan close") +
                                                 '<div class=Slide>' + li("then open") + '</div>')],
                                               [li("r")]])
    files["h28_five_deep_alternation.htm"] = deck([[('<div class=Slide>' + '<span>' * 5 + li("deep5") +
                                                     '</span>' * 5 + '</div>' + li("out"))],
                                                   [li("s")]])
    files["h29_nested_div_text_between.htm"] = deck([[('<div class=Slide>' + run("between1") +
                                                       '<div>' + run("between2") + '</div>' +
                                                       run("between3") + '</div>' + li("fin"))],
                                                     [li("g")]])
    files["h30_div_in_div_in_li.htm"] = deck([[('<li><div class=Slide><div>' + li("d") +
                                                '</div>' + li("e") + '</div></li>')], [li("h")]])

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
