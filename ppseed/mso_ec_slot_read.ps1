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

# The div/span committer's fetch call is `call qword ptr [rip+disp32]` followed by `mov r15,rax` and
# `test r13b,r13b`.  That 10-byte run matches exactly once in the installed mso.dll (rva 0x3E999E on
# 20430.20092 x64; the same call with no `test` tail matches 2093 times, so the tail is what makes it
# unique), which means both the slot index and the call site come out of the file instead of being
# assumed.  Stepping through that one call at runtime is what names the callee.
$FETCH_SIG = 'FF15????????4C8BF84584ED'
$SIG = [ordered]@{ FETCH = $FETCH_SIG }
$SIGOFF = @{ FETCH = 0 }
function Get-Anchors([string]$path, $table) {
  $out = @{}
  $bytes = [IO.File]::ReadAllBytes($path)
  $pe = [BitConverter]::ToInt32($bytes, 0x3C)
  $opt = $pe + 24
  $nsec = [BitConverter]::ToInt16($bytes, $pe + 6)
  $sh = $opt + [BitConverter]::ToInt16($bytes, $pe + 20)
  $tva = 0; $tpraw = 0
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $sh + $i * 40
    if ([Text.Encoding]::ASCII.GetString($bytes, $o, 8).Trim([char]0) -eq '.text') {
      $tva = [BitConverter]::ToInt32($bytes, $o + 12); $tpraw = [BitConverter]::ToInt32($bytes, $o + 20); break }
  }
  if (-not $tpraw) { return $out }
  $latin = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
  foreach ($k in $table.Keys) {
    $h = $table[$k]
    $bts = @(); for ($j = 0; $j -lt $h.Length; $j += 2) {
      $pair = $h.Substring($j, 2)
      if ($pair -eq '??') { $bts += -1 } else { $bts += [Convert]::ToInt32($pair, 16) } }
    $lit = ''
    foreach ($v in $bts) { if ($v -lt 0) { break }; $lit += [char]$v }
    $idx = -1; $from = 0
    $all = @()
    while ($true) {
      $c = $latin.IndexOf($lit, $from, [StringComparison]::Ordinal)
      if ($c -lt 0) { break }
      $ok = $true
      for ($m = 0; $m -lt $bts.Count; $m++) {
        if ($bts[$m] -ge 0 -and [int][byte]$latin[$c + $m] -ne $bts[$m]) { $ok = $false; break } }
      if ($ok) { $all += $c; $idx = $c }
      $from = $c + 1
    }
    if ($idx -lt 0) { continue }
    $out[$k] = ($tva + ($idx - $tpraw)) + $SIGOFF[$k]
    $out[$k + '_N'] = $all.Count
    $out[$k + '_ALL'] = (($all | ForEach-Object { '0x{0:X}' -f ($tva + ($_ - $tpraw)) }) -join ',')
  }
  return $out
}
$msoPath = 'C:\Program Files\Microsoft Office\root\Office16\mso.dll'
$rv = Get-Anchors $msoPath $SIG
$fetchRva = $rv['FETCH']
Say ("FETCH anchor n={0} rva={1} all={2}" -f $rv['FETCH_N'], $fetchRva, $rv['FETCH_ALL'])
if (-not $fetchRva) { Say 'FETCH_ANCHOR_MISSING'; exit 1 }
# the slot the call dispatches through is read from the live instruction bytes (`db` below) rather than
# from a second pass over the file, so the disp32 and the call site come from the same loaded module.

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
lm m mso
lm m mso98win32client
u <MODTOK>+0x<FETCH> L4
db <MODTOK>+0x<FETCH> L6
bp /c 12 <MODTOK>+0x<FETCH> "r $t0=@$t0+1; .echo ECT; t; .echo C1; ln @rip; u @rip L3; t; .echo C2; ln @rip; u @rip L3; g"
bl
.echo ====BP_SET
SLOTREAD
.printf "FETCH_HITS=%d\n", @$t0
q
'@
$tmpl = $tmpl.Replace('<FETCH>', ('{0:X}' -f $fetchRva)).Replace('<MODTOK>', 'mso')
$reads = @()
foreach ($sv in (@($Slots.Split(',')) | ForEach-Object { $_.Trim() })) {
  $reads += ('.echo SLOT_' + $sv)
  $reads += ('dq mso+' + $sv + ' L1')
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
Say ('transcript_bytes=' + $txt.Length + ' mso_loaded=' + ([regex]::Match($txt, '(?m)^====MSO_LOADED')).Success + ' bp_set=' + ([regex]::Match($txt, '(?m)^====BP_SET')).Success)
Say ('FETCH_HITS ' + (([regex]::Matches($txt, 'FETCH_HITS=(\d+)') | ForEach-Object { $_.Groups[1].Value }) -join ','))
foreach ($m in [regex]::Matches($txt, '(?m)^SLOT_(0x[0-9a-fA-F]+)[\r\n]+([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)')) {
  Say ('SLOT rva=' + $m.Groups[1].Value + ' slot_va=' + $m.Groups[2].Value + ' target=' + $m.Groups[3].Value)
}
# each step-into gives two labeled stops; `ln` prints "module+0x…" when the symbol server is empty, which
# is exactly the module+rva pair that the local publics dump resolves to a name.
foreach ($m in [regex]::Matches($txt, '(?m)^(C[12])[\r\n]+([^\r\n]*)[\r\n]+(mso\+0x[0-9a-fA-F]+|[^ ]+)')) {
  Say ('STEP ' + $m.Groups[1].Value + ' ln=' + $m.Groups[2].Value.Trim() + ' first=' + $m.Groups[3].Value)
}
foreach ($m in [regex]::Matches($txt, '(?m)^(C[12])[\r\n]+.*[\r\n]+.*[\r\n]+\s*([0-9a-fA-F`]+)\s+([0-9a-fA-F ]+)')) {
  Say ('CODE ' + $m.Groups[1].Value + ' at=' + $m.Groups[2].Value + ' bytes=' + ($m.Groups[3].Value -replace '\s+', ' '))
}
$modlines = (($txt -split "`n") | Where-Object { $_ -match '^\s*[0-9a-fA-F`]+\s+[0-9a-fA-F`]+\s+mso' }) -join ' ;; '
# raw window around every step-into marker, so the callee's first instructions are readable even when the
# `ln`/`u` line shapes differ from the regexes above
$ectRaw = (($txt -split "`n") | Where-Object { $_ -match '^(ECT|C1|C2)\b|^\s*[0-9a-fA-F`]+\s+(endbr|mov|push|sub|jmp|test|ret|nop|db )|No symbols|^\s+mso' }) -join "`n"
if ($ectRaw.Length -gt 3000) { $ectRaw = $ectRaw.Substring(0, 3000) }
Say ("ECT_RAW=`n" + $ectRaw)
Say ('MODULES ' + $modlines.Substring(0, [Math]::Min(900, $modlines.Length)))
$u = (($txt -split "`n") | Where-Object { $_ -match '^\s*Evaluate expression' }) -join ' ;; '
Say ('MSO_BASE ' + $u)
Say 'ALLDONE'
