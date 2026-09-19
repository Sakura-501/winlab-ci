#!/usr/bin/env python3
"""Run 13 driver: canvas AddPicture (mso GELOASCAN) + icon-mode OLE (wwlib) + cross-app paste.
Actions run as child powershell processes with hard timeout + kill (no Start-Job deadlock)."""
import subprocess, sys, time, os

WORK = r'C:\emfwork'
GFXBP = r'C:\emfwork\bps_run13.txt'

# runtime-scan installed binaries for target RVAs (build-independent)
import importlib.util
spec = importlib.util.spec_from_file_location('st', r'C:\emfwork\tools\scan_targets.py')
st = importlib.util.module_from_spec(spec); spec.loader.exec_module(st)
MSO = r'C:\Program Files\Common Files\Microsoft Shared\Office16\mso.dll'
if not os.path.exists(MSO):
    MSO = r'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\mso.dll'
WW = r'C:\Program Files\Microsoft Office\root\Office16\wwlib.dll'
PPC = r'C:\Program Files\Microsoft Office\root\Office16\ppcore.dll'
bps = ['.echo ===BPS_ARMED===']
try:
    m = st.analyze_mso(MSO)
    if m.get('mso_cboa_reg'): bps.append(f"bp mso+{hex(m['mso_cboa_reg'])} \".echo ===HIT_mso_cboa_reg===; g\"")
    if m.get('mso_fread'): bps.append(f"bp mso+{hex(m['mso_fread'])} \".echo ===HIT_mso_fread===; r rcx; r rdx; r r8; r r9; g\"")
except Exception as e:
    print('mso scan fail', e)
try:
    w = st.analyze_wwlib(WW)
    if w.get('wwlib_icon_cb'): bps.append(f"bp wwlib+{hex(w['wwlib_icon_cb'])} \".echo ===HIT_wwlib_icon_cb===; r r8; dd r8 L8; g\"")
except Exception as e:
    print('wwlib scan fail', e)
try:
    pp = st.analyze_ppcore(PPC)
    if pp.get('ppc_icononly'): bps.append(f"bp ppcore+{hex(pp['ppc_icononly'])} \".echo ===HIT_ppc_icononly===; g\"")
except Exception as e:
    print('ppcore scan fail', e)
bps.append('sxe -c ".echo ===AV===; r; kvn 12; qd" av')
bps.append('bl')
bps.append('g')
open(r'C:\emfwork\bps_run13.txt','w').write('\n'.join(bps)+'\n')
print('\n'.join(bps))
open(r'C:\emfwork\dbgrun13.txt','w').write(
'''.sympath C:\\sym
.reload
$$<C:\\emfwork\\bps_run13.txt
''')

def action_ps(body):
    return ('$ErrorActionPreference=\'Continue\'\n'
            '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n'
            'try{\n' + body +
            '\n}catch{ "ACTION-THREW: " + $_.Exception.Message }\n')

ACTIONS = {
 # P1: Word drawing canvas AddPicture with evil EMF
 'canvas': action_ps("""
$w=[Runtime.InteropServices.Marshal]::GetActiveObject('Word.Application')
$w.DisplayAlerts=0
$d=$w.Documents.Add()
$cv=$d.Shapes.AddCanvas(100,100,300,300)
"canvas ok"
$cv.CanvasItems.AddPicture('C:\\emfwork\\evil.emf')
"addpicture ok"
Start-Sleep -Seconds 8
"""),
 # P2: open patched icon-mode OLE docx
 'icondoc': action_ps("""
$w=[Runtime.InteropServices.Marshal]::GetActiveObject('Word.Application')
$w.DisplayAlerts=0
$d=$w.Documents.Open('C:\\emfwork\\oleicon_evil.docx')
"opened shapes=$($d.Shapes.Count) ole=$($d.InlineShapes.Count)"
Start-Sleep -Seconds 10
$d.Activate()
$w.ActiveDocument.Repaginate()
Start-Sleep -Seconds 5
"""),
 # P3: build icon-mode docx (no cdb) - phase 0
 'iconbuild': action_ps("""
$w=[Runtime.InteropServices.Marshal]::GetActiveObject('Word.Application')
$w.DisplayAlerts=0
$d=$w.Documents.Add()
$ole=$d.OLEObjects.Add($false,'C:\\emfwork\\seed.txt','Word.Document.12','C:\\Windows\\System32\\shell32.dll',1,$true,'Seed Icon')
"ole added type=$($ole.Type)"
$d.SaveAs2('C:\\emfwork\\oleicon_src.docx',16)
$d.Close(0)
"saved"
"""),
 # P4: cross-app: PPT copy OLE shape, Word paste
 'xapp': action_ps("""
$pp=[Runtime.InteropServices.Marshal]::GetActiveObject('PowerPoint.Application')
$pres=$pp.Presentations.Open('C:\\emfwork\\ole_evil.pptx',$true,$false,$true)
$pres.Slides.Item(1).Shapes.Item(1).Copy()
"ppt copied"
Start-Sleep -Seconds 2
$pres.Close()
$w=[Runtime.InteropServices.Marshal]::GetActiveObject('Word.Application')
$w.DisplayAlerts=0
$d=$w.Documents.Add()
$r=$d.Range()
$r.Paste()
"word pasted"
Start-Sleep -Seconds 8
"""),
}

def run_action(name, timeout=90):
    path = os.path.join(WORK, f'act_{name}.ps1')
    open(path,'w').write(ACTIONS[name])
    t0=time.time()
    p=subprocess.Popen(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-File',path],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        out,_=p.communicate(timeout=timeout)
        return out.strip()
    except subprocess.TimeoutExpired:
        p.kill()
        return 'ACTION-TIMEOUT'

def probe(app_args, tag, action, wait_after=25):
    exe, args = app_args
    log = os.path.join(WORK, f'cdb13_{tag}.log')
    cdb = os.path.join(WORK, 'dbg', 'cdb.exe')
    subprocess.run(['powershell','-c',
        "Get-Process WINWORD,POWERPNT,cdb -EA SilentlyContinue|Stop-Process -Force"],
        capture_output=True)
    time.sleep(4)
    app = subprocess.Popen([exe]+args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(22)
    cp = subprocess.Popen([cdb,'-p',str(app.pid),'-logo',log,'-cf',r'C:\emfwork\dbgrun13.txt'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(18)
    res = run_action(action[0], timeout=action[1])
    print(f'[{tag}] action: {res[:400]}')
    time.sleep(wait_after)
    # hit analysis
    try:
        c = open(log, errors='replace').read().splitlines()
    except Exception as e:
        print(f'[{tag}] no log: {e}'); c=[]
    hits = {}
    for ln in c:
        if ln.startswith('===HIT_') or ln.startswith('===AV'):
            hits[ln] = hits.get(ln,0)+1
    armed = sum(1 for ln in c if 'Unable to resolve' in ln)
    alive = _alive(app.pid)
    print(f'[{tag}] armed_fail={armed} alive={alive} hits={hits or "NONE"}')
    # dump fread register lines
    for i,ln in enumerate(c):
        if ln.startswith('===HIT_mso_fread') or ln.startswith('===HIT_wwlib_icon_cb'):
            print('   ', ' | '.join(c[i+1:i+4]))
    subprocess.run(['powershell','-c',
        "Get-Process cdb -EA SilentlyContinue|Stop-Process -Force; Get-Process WINWORD,POWERPNT -EA SilentlyContinue|Stop-Process -Force"],
        capture_output=True)
    time.sleep(3)
    return hits

def _alive(pid):
    r=subprocess.run(['powershell','-c',f"if(Get-Process -Id {pid} -EA SilentlyContinue){{'Y'}}else{{'N'}}"],
                     capture_output=True,text=True)
    return r.stdout.strip()=='Y'

if __name__=='__main__':
    WORD=r'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'
    PPT=r'C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE'
    # phase 0: build icon docx (no cdb)
    print('[iconbuild]', run_action('iconbuild', timeout=120)[:300])
    # phase 0b: patch media emf inside oleicon_src.docx -> oleicon_evil.docx
    import zipfile, shutil, struct
    src=os.path.join(WORK,'oleicon_src.docx'); dst=os.path.join(WORK,'oleicon_evil.docx')
    if os.path.exists(src):
        evil=open(os.path.join(WORK,'evil.emf'),'rb').read()
        zin=zipfile.ZipFile(src)
        emfs=[n for n in zin.namelist() if n.endswith('.emf')]
        print('docx emf parts:',emfs)
        zout=zipfile.ZipFile(dst,'w',zipfile.ZIP_DEFLATED)
        for it in zin.infolist():
            data=zin.read(it.filename)
            if it.filename.endswith('.emf'):
                data=evil
            zout.writestr(it,data)
        zout.close()
        print('oleicon_evil.docx packed', os.path.getsize(dst))
    else:
        print('NO ICON SRC - skipping P2')
    # P1 canvas
    probe((WORD,['/n','/q']), 'canvas', ('canvas',90))
    # P2 icon doc
    if os.path.exists(dst):
        probe((WORD,['/n','/q']), 'icondoc', ('icondoc',90))
    # P4 cross-app
    probe((WORD,['/n','/q']), 'xapp', ('xapp',120))
    print('=== DONE ===')
