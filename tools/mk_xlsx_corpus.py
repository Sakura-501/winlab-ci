#!/usr/bin/env python3
"""OOXML workbook carriers whose declared counts disagree with the elements present.

Excel's xlsx reader turns count attributes into allocations before it walks the child
elements, so each of these is a "count from one attribute, fill from the document" pair:
  xl/sharedStrings.xml   <sst count= uniqueCount=>   vs the <si> children (and <r> runs)
  xl/styles.xml          <cellXfs numFmtIds.. count=> / <fonts count=> / <fills count=>
                         / <borders count=> / <cellStyleXfs> / <dxfs count=> vs children
  xl/worksheets/sheet1   <dimension ref=> vs the rows/cells actually present
                         <sheetData> rows with out-of-order / duplicate / huge r= indices
  xl/worksheets/_rels    hyperlink / drawing ids that index a table
Every package keeps every other part valid, and each carries a benign control so an
"opened=" reading can be attributed.

usage: mk_xlsx_corpus.py <outdir>
"""
import io
import os
import sys
import zipfile

OUT = sys.argv[1]
NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
NSR = ('xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
       'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')


def part_ct():
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
            '</Types>')


def root_rels():
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>')


def workbook():
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook %s><sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>' % NSR)


def wb_rels():
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>'
            '</Relationships>')


def styles(nfonts=1, nfills=1, nborders=1, ncellxfs=1, ndxfs=0, nfmtids=1,
           fake_counts=None, extra=''):
    body = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet %s>' % NS)
    body += ('<numFmts count="%d"><numFmt numFmtId="164" formatCode="General"/></numFmts>'
             % nfmtids)
    body += '<fonts count="%d">' % nfonts + \
        ('<font><sz val="11"/><name val="Calibri"/></font>' * max(1, min(nfonts, 400))) + '</fonts>'
    body += '<fills count="%d">' % nfills + \
        ('<fill><patternFill patternType="none"/></fill>' * max(1, min(nfills, 400))) + '</fills>'
    body += '<borders count="%d">' % nborders + \
        ('<border><left/><right/><top/><bottom/></border>' * max(1, min(nborders, 400))) + '</Borders>'.replace('>b', '>b')
    body = body.replace('</Borders>', '</borders>')
    body += '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    body += '<cellXfs count="%d">' % ncellxfs + \
        ('<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' * max(1, min(ncellxfs, 400))) + '</cellXfs>'
    body += '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
    body += '<dxfs count="%d">' % ndxfs + ('<dxf><font><b/></font></dxf>' * min(ndxfs, 200)) + '</dxfs>'
    body += extra + '</styleSheet>'
    return body


def sst(count=None, unique=None, nsi=1, runper=0, longness=5, extra_attr=''):
    c = len(range(0)) if count is None else count
    body = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<sst %s count="%d" uniqueCount="%d"%s>' % (NS, c, unique if unique is not None else nsi, extra_attr))
    for i in range(nsi):
        if runper:
            body += '<si>' + ('<r><rPr><sz val="11"/></rPr><t>%s</t></r>' % ('a' * longness)) * runper + '</si>'
        else:
            body += '<si><t>%s%d</t></si>' % ('x' * longness, i)
    return body + '</sst>'


def sheet(dimrows=3, dimcols=3, row_tags=None, cells=None, dimension=None, extra=''):
    body = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet %s>' % NS)
    if dimension:
        body += '<dimension ref="%s"/>' % dimension
    body += '<sheetViews><sheetView workbookViewId="0"/></sheetViews>'
    body += '<sheetFormatPr defaultRowHeight="15"/>'
    body += '<sheetData>'
    rows = row_tags if row_tags else list(range(1, dimrows + 1))
    for r in rows:
        body += '<row r="%d" spans="1:%d">' % (r, dimcols)
        for c in (cells if cells else range(1, dimcols + 1)):
            body += '<c r="%s%d" t="s"><v>%d</v></c>' % (chr(64 + (c % 26 or 26)), r, (r + c) % 40)
        body += '</row>'
    body += '</sheetData>' + extra + '</worksheet>'
    return body


def pack(parts):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', part_ct())
        z.writestr('_rels/.rels', root_rels())
        z.writestr('xl/workbook.xml', workbook())
        z.writestr('xl/_rels/workbook.xml.rels', wb_rels())
        for k, v in parts.items():
            z.writestr(k, v)
    return buf.getvalue()


def w(name, parts):
    open(os.path.join(OUT, name), 'wb').write(pack(parts))


BOUNDS = [0, 1, 2, 3, 4, 8, 15, 16, 17, 32, 33, 64, 65, 128, 129, 255, 256, 512, 1024,
          4096, 65535, 65536, 2147483647]


def main():
    os.makedirs(OUT, exist_ok=True)
    made = 0

    # --- sharedStrings: count / uniqueCount vs the <si> children actually present
    for n in BOUNDS:
        real = min(n, 60)
        for tag, cnt, uni in (('over', n + 1000, real), ('under', max(0, n - 1), real),
                              ('zero', 0, real), ('huge', 0x7FFFFFFF, real),
                              ('neg', -1, real), ('match', real, real),
                              ('uni_gt', real, n + 1000), ('uni_neg', real, -5)):
            w('sst_%s_%010d.xlsx' % (tag, n),
              {'xl/sharedStrings.xml': sst(count=cnt, unique=uni, nsi=max(1, real)),
               'xl/styles.xml': styles(),
               'xl/worksheets/sheet1.xml': sheet()})
            made += 1
    # --- run counts inside <si>
    for runs in (0, 1, 2, 17, 256, 4096):
        for ln in (1, 40, 4000):
            w('sst_r%05d_l%05d.xlsx' % (runs, ln),
              {'xl/sharedStrings.xml': sst(count=runs or 1, unique=1, nsi=3, runper=runs, longness=ln),
               'xl/styles.xml': styles(), 'xl/worksheets/sheet1.xml': sheet()})
            made += 1
    # --- styles: each count attribute decoupled from its children
    for attr in ('nfonts', 'nfills', 'nborders', 'ncellxfs', 'ndxfs', 'nfmtids'):
        for n in (0, 1, 2, 17, 255, 256, 65535, 0x7FFFFFFF):
            kw = {attr: n}
            w('st_%s_%011d.xlsx' % (attr, n),
              {'xl/styles.xml': styles(**kw), 'xl/sharedStrings.xml': sst(count=1, unique=1, nsi=1),
               'xl/worksheets/sheet1.xml': sheet()})
            made += 1
    # --- xf/fontId/index references beyond the tables
    for fid in (0, 1, 2, 255, 65535, 2147483647, -1):
        extra_xf = ('<cellXfs count="1"><xf numFmtId="%d" fontId="%d" fillId="%d" borderId="%d" xfId="%d"/></cellXfs>'
                    % (fid, fid, fid, fid, fid))
        s = styles(ncellxfs=1).replace('<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>', extra_xf)
        w('st_xfref_%011d.xlsx' % (fid + 1),
          {'xl/styles.xml': s, 'xl/sharedStrings.xml': sst(count=1, unique=1, nsi=1),
           'xl/worksheets/sheet1.xml': sheet()})
        made += 1
    # --- sheet dimension vs actual rows/cells, and row index abuse
    for dim in ('A1:C3', 'A1:XFD1048576', 'A1', 'XFD1048576', 'A1:A0', 'ZZ999999999', ''):
        w('sh_dim_%s.xlsx' % (abs(hash(dim)) % 997),
          {'xl/styles.xml': styles(), 'xl/sharedStrings.xml': sst(count=1, unique=1, nsi=1),
           'xl/worksheets/sheet1.xml': sheet(dimension=dim, dimrows=5, dimcols=5)})
        made += 1
    for tag, rows in (('rev', [5, 4, 3, 2, 1]), ('dup', [1, 1, 1, 2, 2]),
                      ('huge', [1, 2, 1048576, 1048577, 2147483647]),
                      ('zero', [0, 1, 2]), ('negish', [1, 2, 3, 4, 5])
                      ):
        w('sh_rows_%s.xlsx' % tag,
          {'xl/styles.xml': styles(), 'xl/sharedStrings.xml': sst(count=5, unique=5, nsi=5),
           'xl/worksheets/sheet1.xml': sheet(row_tags=rows, dimension='A1:E5')})
        made += 1
    # --- cells whose r= is outside the row / duplicated / empty
    for cells in ([1, 2, 16384, 16385, 0, -3], [1, 1, 1, 1], [1000, 2000, 3000]):
        w('sh_cells_%04d.xlsx' % (cells[0] % 9999),
          {'xl/styles.xml': styles(), 'xl/sharedStrings.xml': sst(count=3, unique=3, nsi=3),
           'xl/worksheets/sheet1.xml': sheet(dimcols=max(1, len(cells)), cells=cells, dimension='A1:C3')})
        made += 1
    # --- sst index used by cells beyond the table
    w('sh_sstindex.xlsx',
      {'xl/styles.xml': styles(), 'xl/sharedStrings.xml': sst(count=2, unique=2, nsi=2),
       'xl/worksheets/sheet1.xml': sheet(cells=[1], dimcols=1,
                                         extra='')})
    made += 1
    for idx in (1000, 65535, 2147483647, -1):
        sh = sheet().replace('<v>0</v>', '<v>%d</v>' % idx)
        w('sh_sstidx_%011d.xlsx' % (idx + 2),
          {'xl/styles.xml': styles(), 'xl/sharedStrings.xml': sst(count=1, unique=1, nsi=1),
           'xl/worksheets/sheet1.xml': sh})
        made += 1
    # benign controls
    w('xctrl_ok.xlsx', {'xl/styles.xml': styles(), 'xl/sharedStrings.xml': sst(count=9, unique=9, nsi=9),
                        'xl/worksheets/sheet1.xml': sheet()})
    w('xctrl_nostr.xlsx', {'xl/styles.xml': styles(),
                           'xl/sharedStrings.xml': '<?xml version="1.0"?><sst %s count="0" uniqueCount="0"/>' % NS,
                           'xl/worksheets/sheet1.xml': sheet()})
    print('made=%d dir=%s' % (made + 2, OUT))


if __name__ == '__main__':
    main()
