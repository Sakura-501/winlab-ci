# mso_ec_slot_read.ps1 - read the *live* value of mso's indirect-call data slots and dump the module map,
# so the callee behind `call qword ptr [rip+disp]` can be named offline from the local PDB publics dump.
#
# Why: in the shipping ARM64X mso.dll the x64 code calls several helpers through slots that live between
# `__guard_eh_cont_table` and `__guard_fids_table`; in the file those slots hold placeholders of the form
# 0x800000000000xxxx, so nothing in the binary names the callee (measured 2026-09-28: the div/span
# committer's fetch call uses slot rva 0x19E1DE0, and the PDB's own `__imp_?PwchFetchToIhtks@...` slot is a
# different rva 0x19D569B with zero `ff15` references to it in .text).  The loader-filled value plus the
# `lm` module map is enough to attribute the address to a module and a RVA, which the host resolves with
# `msfpdb.py` publics - no symbol server involved.
param([string]$Base = '.', [string]$Corpus = 'corpus\mime25.txt', [string]$Records = '3',
      [string]$Tag = 'ecslot',
      [string]$Slots = '0x19E1DE0,0x19DF958,0x19DDEF0,0x19DEF10,0x19ED4E0,0x19ED4E8')
$ErrorActionPreference = 'Continue'
$base = (Resolve-Path $Base).Path
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
function Say([string]$s) { ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $s) | Add-Content $log; $s }

$gbx = Join-Path $base 'bin\gbx.exe'
if (-not (Test-Path $gbx)) { Say "GBX_MISSING $gbx"; exit 1 }
$cdb = $null
foreach ($c in @('C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe','C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe')) {
  if (Test-Path $c) { $cdb = $c; break } }
if (-not $cdb) {
  $h = Get-ChildItem 'C:\Program Files\WindowsApps' -Recurse -Filter cdb.exe -EA SilentlyContinue |
       Where-Object { $_.DirectoryName -match 'amd64|x64' } | Select-Object -First 1
  if ($h) { $cdb = $h.FullName } }
if (-not $cdb) { Say 'NO_CDB'; exit 1 }
Say "cdb=$cdb"
$priv = 'C:\dsdbg'; New-Item -ItemType Directory -Force -Path $priv | Out-Null
Copy-Item $cdb (Join-Path $priv 'cdb.exe') -Force
Get-ChildItem (Split-Path $cdb) -Filter *.dll -EA SilentlyContinue | Copy-Item -Destination $priv -Force
$cdbExe = Join-Path $priv 'cdb.exe'
$env:PATH = 'C:\Program Files\Microsoft Office\root\Office16;' + $env:PATH

# empty symbol dir + no network: module names come from `lm`, nothing is downloaded
$symLocal = Join-Path $env:TEMP ('symslot_' + $Tag)
New-Item -ItemType Directory -Force -Path $symLocal | Out-Null
$env:_NT_SYMBOL_PATH = $symLocal

$cm = Join-Path $base ('out\cmds_' + $Tag + '.txt')
$tr = Join-Path $base ('out\trans_' + $Tag + '.txt')
$tmpl = @'
sxd av
sxe ld:mso.dll
.echo ====WAITLOAD
g
.echo ====MSO_LOADED
? mso
lm
lm m mso
lm m mso98win32client
SLOTREAD
q
'@
$reads = @()
foreach ($sv in ($Slots.Split(',') | ForEach-Object { $_.Trim() })) {
  $reads += ('.echo SLOT_' + $sv)
  $reads += ('dqs mso+' + $sv + ' L1')
}
$lines = @()
foreach ($ln in ($tmpl -split "`n")) {
  $t = $ln.Trim()
  if ($t -eq 'SLOTREAD') { $lines += $reads } else { $lines += ($ln -replace "`r", '') }
}
Set-Content -Path $cm -Value ($lines -join "`n") -Encoding ascii
$p = Start-Process -FilePath $cdbExe -ArgumentList @('-y', $symLocal, '-cf', $cm, '-o', $gbx, 'msohtml',
          (Join-Path $base $Corpus), $Records, '0', 'none', 'norel', 'noskip', 'slot=17') `
        -NoNewWindow -PassThru -RedirectStandardOutput $tr
$p.WaitForExit()
$txt = ''
if (Test-Path $tr) { $txt = Get-Content $tr -Raw -EA SilentlyContinue }
Say ('transcript_bytes=' + $txt.Length + ' mso_loaded=' + ([regex]::Match($txt, '(?m)^====MSO_LOADED')).Success)
foreach ($m in [regex]::Matches($txt, '(?m)^SLOT_(0x[0-9a-fA-F]+)\s*\r?\n([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)')) {
  Say ('SLOT rva=' + $m.Groups[1].Value + ' slot_va=' + $m.Groups[2].Value + ' target=' + $m.Groups[3].Value)
}
$modlines = (($txt -split "`n") | Where-Object { $_ -match '^\s*[0-9a-fA-F`]+\s+[0-9a-fA-F`]+\s+mso' }) -join ' ;; '
Say ('MODULES ' + $modlines.Substring(0, [Math]::Min(900, $modlines.Length)))
$u = (($txt -split "`n") | Where-Object { $_ -match '^\s*Evaluate expression' }) -join ' ;; '
Say ('MSO_BASE ' + $u)
Say 'ALLDONE'
