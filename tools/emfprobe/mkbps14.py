#!/usr/bin/env python3
"""run14: emit runtime-resolved cdb breakpoint config (module+offset bps)."""
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location('st', r'C:\emfwork\tools\scan_targets.py')
st = importlib.util.module_from_spec(spec); spec.loader.exec_module(st)

MSO = r'C:\Program Files\Common Files\Microsoft Shared\Office16\mso.dll'
if not os.path.exists(MSO):
    MSO = r'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\mso.dll'
WW = r'C:\Program Files\Microsoft Office\root\Office16\wwlib.dll'
PPC = r'C:\Program Files\Microsoft Office\root\Office16\ppcore.dll'

lines = ['.sympath C:\\sym', '.reload']
try:
    m = st.analyze_mso(MSO)
    if m.get('mso_cboa_reg'):
        lines.append(f"bp mso+{hex(m['mso_cboa_reg'])} \".echo ===HIT_mso_cboa_reg===; g\"")
    if m.get('mso_fread'):
        lines.append(f"bp mso+{hex(m['mso_fread'])} \".echo ===HIT_mso_fread===; r rcx; r rdx; r r8; r r9; g\"")
except Exception as e:
    print('mso scan fail', e)
try:
    w = st.analyze_wwlib(WW)
    if w.get('wwlib_icon_cb'):
        lines.append(f"bp wwlib+{hex(w['wwlib_icon_cb'])} \".echo ===HIT_wwlib_icon_cb===; r r8; dd r8 L8; g\"")
except Exception as e:
    print('wwlib scan fail', e)
try:
    pp = st.analyze_ppcore(PPC)
    if pp.get('ppc_icononly'):
        lines.append(f"bp ppcore+{hex(pp['ppc_icononly'])} \".echo ===HIT_ppc_icononly===; g\"")
except Exception as e:
    print('ppcore scan fail', e)
lines.append('sxe -c ".echo ===AV===; r; kvn 12; qd" av')
lines.append('bl')
lines.append('g')
open(r'C:\emfwork\dbgcmd14.txt', 'w', newline='\n').write('\n'.join(lines) + '\n')
print('\n'.join(lines))
