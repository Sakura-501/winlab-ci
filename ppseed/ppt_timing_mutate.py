#!/usr/bin/env python3
"""ppt_timing_mutate.py -- build .pptx decks whose <p:timing> tree carries different target-id shapes.

Dimensions covered (one variant per structural edge a timing-tree walker can take):
  - the two behaviour elements PowerPoint itself emits for an entrance animation (p:set / p:animEffect)
  - target id that names no shape on the slide
  - target id reached only through a nested par/subTnLst chain
  - target id inside the build list (p:bldLst/p:bldP)
  - target id inside the sequence's event conditions (p:prevCondLst / p:nextCondLst)
  - two shapes sharing one spid
  - an auto-starting (afterEffect) chain, i.e. no click between open and the consumer

usage: ppt_timing_mutate.py <outdir>
"""
import os
import sys
import copy

from pptx import Presentation
from pptx.util import Inches
from lxml import etree

NS = "http://schemas.openxmlformats.org/presentationml/2006/main"
NSA = "http://schemas.openxmlformats.org/drawingml/2006/main"


def q(t):
    return "{%s}%s" % (NS, t)


def timing_xml(spids, bad=99001, opts=()):
    """spids: list of real shape ids on the slide.  bad: an id that exists nowhere."""
    good = spids[0]
    tgt_for_behaviors = bad if "bad_beh" in opts else good
    depth = int("deep" in opts) and 5 or 1

    def cTn(i, extra="", children=""):
        return '<p:cTn id="%d" %s>%s</p:cTn>' % (i, extra, children)

    def cond(i, delay):
        return '<p:cTn id="%d" fill="hold"><p:stCondLst><p:cond delay="%s"/></p:stCondLst></p:cTn>' % (i, delay)

    def behavior_set(i, spid):
        return (
            '<p:set><p:cBhvr>' + cond(i, "0") +
            '<p:tgtEl><p:spTgt spid="%d"/></p:tgtEl>'
            '<p:attrNameLst><p:attrName>style.visibility</p:attrName></p:attrNameLst>'
            '</p:cBhvr><p:to><p:strVal val="visible"/></p:to></p:set>'
        ) % spid

    def behavior_anim(i, spid):
        return (
            '<p:animEffect transition="in" filter="fade"><p:cBhvr>'
            '<p:cTn id="%d" dur="500"/>'
            '<p:tgtEl><p:spTgt spid="%d"/></p:tgtEl>'
            '</p:cBhvr></p:animEffect>'
        ) % (i, spid)

    inner = behavior_set(6, tgt_for_behaviors) + behavior_anim(7, tgt_for_behaviors)
    if "bad_bld_only" in opts:
        inner = behavior_set(6, good) + behavior_anim(7, good)
    node = '<p:cTn id="5" presetID="10" presetClass="entr" presetSubtype="0" fill="hold" grpId="0" nodeType="%s">%s<p:childTnLst>%s</p:childTnLst></p:cTn>' % (
        "afterEffect" if "autostart" in opts else "clickEffect",
        '<p:stCondLst><p:cond delay="0"/></p:stCondLst>',
        inner,
    )
    # nest the effect chain `depth` par levels deep
    cur = node
    nid = 30
    for _ in range(depth - 1):
        cur = '<p:par><p:cTn id="%d" fill="hold"><p:stCondLst><p:cond delay="0"/></p:stCondLst><p:childTnLst>%s</p:childTnLst></p:cTn></p:par>' % (nid, cur)
        nid += 1
    effect_par = "<p:par>%s</p:par>" % cur

    cond_tgt = '<p:tgtEl><p:spTgt spid="%d"/></p:tgtEl>' % bad if "bad_cond" in opts else "<p:tgtEl><p:sldTgt/></p:tgtEl>"
    sub = ""
    if "subTnLst" in opts:
        sub = '<p:subTnLst><p:par><p:cTn id="40" fill="hold"><p:stCondLst><p:cond delay="0"/></p:stCondLst><p:childTnLst>%s</p:childTnLst></p:cTn></p:par></p:subTnLst>' % behavior_set(41, bad)

    bld = "".join('<p:bldP spid="%d" grpId="0"/>' % (bad if "bad_bld_only" in opts or "bad_beh" in opts else s) for s in spids)

    return (
        '<p:timing xmlns:p="%s" xmlns:a="%s"><p:tnLst><p:par>'
        '<p:cTn id="1" dur="indefinite" restart="never" nodeType="tmRoot"><p:childTnLst>'
        '<p:seq concurrent="1" nextAc="seek">'
        '<p:cTn id="2" dur="indefinite" nodeType="mainSeq"><p:childTnLst>%s%s</p:childTnLst></p:cTn>'
        '<p:prevCondLst><p:cond evt="onPrev" delay="0">%s</p:cond></p:prevCondLst>'
        '<p:nextCondLst><p:cond evt="onNext" delay="0">%s</p:cond></p:nextCondLst>'
        '</p:seq></p:childTnLst></p:cTn></p:par></p:tnLst>'
        '<p:bldLst>%s</p:bldLst></p:timing>'
    ) % (NS, NSA, effect_par, sub, cond_tgt, cond_tgt, bld)


def add_shapes(prs, n=2, dup=False):
    slide = prs.slides[0]
    ids = []
    for i in range(n):
        tb = slide.shapes.add_textbox(Inches(1 + i), Inches(1.2), Inches(2.2), Inches(1.2))
        tb.text_frame.text = "shape %d" % i
        ids.append(tb.shape_id)
    if dup and len(ids) >= 2:
        # force two shapes to share one spid
        for sh in slide.shapes:
            if sh.shape_id == ids[1]:
                sh._element.nvSpPr.cNvPr.set("id", str(ids[0]))
    return ids


VARIANTS = {
    "t01_ctl_valid": {},
    "t02_bad_beh": {"bad_beh": 1},
    "t03_bad_beh_deep": {"bad_beh": 1, "deep": 1},
    "t04_bad_bld_only": {"bad_bld_only": 1},
    "t05_bad_cond": {"bad_cond": 1},
    "t06_bad_subtn": {"subTnLst": 1},
    "t07_bad_autostart": {"bad_beh": 1, "autostart": 1},
    "t08_bad_deep_autostart": {"bad_beh": 1, "deep": 1, "autostart": 1},
    "t09_dup_spid": {"dup": 1, "bad_beh": 1},
    "t10_ctl_deep_autostart": {"deep": 1, "autostart": 1},
}


def build(outdir):
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for name, opts in sorted(VARIANTS.items()):
        prs = Presentation()
        prs.slide_width = Inches(9)
        prs.slide_height = Inches(7)
        blank = prs.slide_layouts[6]
        prs.slides.add_slide(blank)
        # drop any placeholder, then add real shapes
        spids = add_shapes(prs, 2, dup=bool(opts.get("dup")))
        xml = timing_xml(spids, bad=99001 if not opts.get("dup") else 99002, opts=opts)
        sld = prs.slides[0]._element  # <p:sld>
        frag = etree.fromstring(xml.encode("utf-8"))
        for old in sld.findall(q("timing")):
            sld.remove(old)
        sld.append(frag)  # p:timing comes last in CT_Slide
        path = os.path.join(outdir, name + ".pptx")
        prs.save(path)
        n += 1
        print("wrote %s shapes=%s" % (path, spids))
    print("carriers=%d" % n)


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "carriers_t")
