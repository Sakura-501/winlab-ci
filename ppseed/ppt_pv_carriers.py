#!/usr/bin/env python3
"""ppt_pv_carriers.py -- one carrier per PowerPoint document extension, same content family.

Purpose: measure, under the real delivery condition (ZoneId=3 written before opening), which
PowerPoint container formats the shell/PowerPoint path takes into Protected View and which are
parsed straight away.  That decides the delivery channel for every PowerPoint parsing candidate,
so it is worth measuring once with a minimal, identical payload across extensions.

usage: ppt_pv_carriers.py <outdir> [base.pptx]
"""
import os
import shutil
import sys
import zipfile

from pptx import Presentation
from pptx.util import Inches

CT_PRESENTATION = b"presentationml.presentation.main+xml"
CT_SLIDESHOW = b"presentationml.slideshow.main+xml"
CT_TEMPLATE = b"presentationml.template.main+xml"


def relabel(src, dst, new_ct):
    zin = zipfile.ZipFile(src, "r")
    zout = zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED)
    for item in zin.namelist():
        blob = zin.read(item)
        if item == "[Content_Types].xml":
            blob = blob.replace(CT_PRESENTATION, new_ct)
        zout.writestr(item, blob)
    zin.close()
    zout.close()


def base_deck(path):
    prs = Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    tb = slide.shapes.add_textbox(Inches(1), Inches(1), Inches(6), Inches(2))
    tb.text_frame.text = "pv probe"
    prs.save(path)


HTML = """<html xmlns:o="urn:schemas-microsoft-com:office:office"
 xmlns:v="urn:schemas-microsoft-com:vml" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta name=Generator content="Microsoft PowerPoint 16">
<title>pv probe</title></head>
<body>
<div class=Slide><p class=MsoNormal><span style='font-size:36.0pt'>pv probe</span></p>
<p class=MsoNormal><span style='font-size:20.0pt'>line two</span></p></div>
<div class=Slide><p class=MsoNormal><span style='font-size:28.0pt'>second</span></p></div>
</body></html>
"""

MHTML = """Content-Type: multipart/related; boundary="----_=_NextPart_001_01D9F0D1.PVPROBE"

This is a Microsoft Internet Picture/HTML document.

------_=_NextPart_001_01D9F0D1.PVPROBE
Content-Location: slide01.htm
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset="utf-8"

<html><head><meta name=Generator content="Microsoft PowerPoint 16"></head>
<body><div class=Slide><p>pv probe mhtml</p></div></body></html>
------_=_NextPart_001_01D9F0D1.PVPROBE--
"""


def main(outdir, seed=None):
    os.makedirs(outdir, exist_ok=True)
    pptx = os.path.join(outdir, "pv_probe.pptx")
    if seed and os.path.exists(seed):
        shutil.copyfile(seed, pptx)
    else:
        base_deck(pptx)
    made = [pptx]
    for name, ct in (("pv_probe_show.ppsx", CT_SLIDESHOW), ("pv_probe_tpl.potx", CT_TEMPLATE)):
        dst = os.path.join(outdir, name)
        relabel(pptx, dst, ct)
        made.append(dst)
    for name in ("pv_probe_htm.htm", "pv_probe_html.html", "pv_probe_mht.mht", "pv_probe_mhtml.mhtml"):
        p = os.path.join(outdir, name)
        with open(p, "w", encoding="ascii") as fh:
            fh.write(MHTML if name.startswith(("pv_probe_mht", "pv_probe_mhtml")) else HTML)
        made.append(p)
    with open(os.path.join(outdir, "pv_probe_txt.txt"), "w") as fh:
        fh.write("pv;probe;1,2,3\n")
    made.append(os.path.join(outdir, "pv_probe_txt.txt"))
    print("carriers=%d" % len(made))
    for m in made:
        print("  %s %d" % (os.path.basename(m), os.path.getsize(m)))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "carriers_pv",
         sys.argv[2] if len(sys.argv) > 2 else None)
