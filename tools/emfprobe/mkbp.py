#!/usr/bin/env python3
"""Convert scan_targets.py output into a cdb breakpoint command file."""
import sys
lines = ['.echo ===ATTACHED===']
mods = {'mso': 'mso', 'ppc': 'ppcore'}
for line in sys.stdin:
    q = line.split()
    if len(q) != 2 or not q[1].startswith('0x'):
        continue
    tag, rva = q[0], q[1]
    mod = mods.get(tag.split('_')[0])
    if mod is None:
        continue
    lines.append(f'bp {mod}+{rva} ".echo ===HIT_{tag}===; g"')
lines.append('sxe -c ".echo ===AV===; r; kvn 12; qd" av')
lines.append('sxe -c "$$<C:\\emfwork\\bps_mod.txt" ld:mso.dll')
lines.append('sxe -c "$$<C:\\emfwork\\bps_mod.txt" ld:ppcore.dll')
lines.append('bl')
lines.append('g')
open(sys.argv[1], 'w', newline='\n').write('\n'.join(lines) + '\n')
# module-armed file: same bps minus the ld hooks (used inside ld handler)
mod = ['.echo ===MOD_BPS===']
for line in sys.stdin if False else []:
    pass
modlines = [l for l in lines if l.startswith('bp ') or l.startswith('sxe -c ".echo ===AV===')]
modlines.append('bl')
modlines.append('g')
import os
open(sys.argv[1] + '.mod', 'w', newline='\n').write('\n'.join(modlines) + '\n')
print(f'bps file written: {len(lines)} lines')
