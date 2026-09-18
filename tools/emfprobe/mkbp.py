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
lines.append('bl')
lines.append('g')
open(sys.argv[1], 'w', newline='\n').write('\n'.join(lines) + '\n')
print(f'bps file written: {len(lines)} lines')
