# mso_html_len_probe.ps1 - runner-side measurement of the mso HTML div/span commit length.
#
# Anchors four sites inside the *installed* mso.dll by code signature (no PDB, no symbol server),
# then opens each HTML carrier under cdb with full page heap armed and counts:
#   FDS  ?FCommitDivSpanCore@ @0x1c9b68        - every div/span commit
#   NEG  the `test ecx,ecx / jns` block @0x1c9cd2 - commits whose fetched count is negative
#   CPY  the memcpy argument site @0x1c9d50     - the copy actually issued, with r8 = 2*count
# The interesting reading is NEG>0 and/or a CPY whose r8 is enormous (negative doubled).
# Signature source: office-sep2026-fixsurface-20260913/bin/mso_20326.20144_x64.dll
#
# LEX is a positive control: ?TkLexHtml@@YAHXZ @0x180019490, the HTML lexer that drives the tag
# callback feeding the div/span commit.  Its prologue (push rbx..rbp sequence + frame alloc) matches
# exactly once in both 20132 and 20144 x64.  LEX>0 with FDS=0 separates "the app never ran the HTML
# lexer" from "the sink breakpoints are not live"; FDS=0 with LEX=0 cannot be read as a negative
# about the sink at all.
param([string]$Dir = 'carriers_h',
      [string]$Tag = 'htmllen',
      [string]$Base = '.',
      [string]$App = 'POWERPNT.EXE',
      [int]$WaitSec = 110,
      [int]$MaxCases = 0,
      [string]$NameFilter = '',
      [string]$Ext = '.htm,.html,.mht,.mhtml',
      [switch]$NoCdb,
      [int]$Stops = 400)
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$root = 'C:\Program Files\Microsoft Office\root\Office16'
$appPath = Join-Path $root $App
# mso.dll is not under root\Office16: C2R lays the shared core down under the virtualized
# ProgramFilesCommon view, so resolve it by candidate path first and then by a bounded search.
$msoCand = @(
  'C:\Program Files\Common Files\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\OFFICE16\mso.dll',
  (Join-Path $root 'mso.dll'))
$mso = $null
foreach ($c in $msoCand) {
  $t = Get-Item $c -EA SilentlyContinue
  if ($t) { $mso = $t; break }
}
if (-not $mso) {
  $mso = Get-ChildItem 'C:\Program Files\Microsoft Office\root' -Recurse -Filter 'mso.dll' -EA SilentlyContinue |
         Sort-Object Length -Descending | Select-Object -First 1
}
$msoPath = if ($mso) { $mso.FullName } else { 'missing' }
# PowerShell variable names are case-insensitive: `$app` and the `$App` parameter were the same
# variable, so the bare exe name got replaced by its full path and every downstream use
# (gflags target, IFEO/WER key, Stop-Process image name) silently received a path instead.
if ($App -notmatch '\.EXE$') { $appPath = Get-ChildItem $root -Filter $App -EA SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName }
$base = (Resolve-Path $Base).Path
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out'), (Join-Path $base 'dumps') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
if (-not $mso) { "START $(Get-Date -Format HH:mm:ss) MSO_NOT_FOUND candidates=$($msoCand -join ';')" | Set-Content $log; Get-Content $log; exit 1 }
"START $(Get-Date -Format HH:mm:ss) app=$App msoPath=$msoPath mso=$($mso.VersionInfo.FileVersion) size=$($mso.Length)" | Set-Content $log

$SIG = [ordered]@{
  FDS = '4C894C2420488954241055535657415441554157488D6C24'
  NEG = 'F7D98BD1483BD077E2482BC2'
  # lea rcx,[rax+rcx*2] ; call memcpy(rel32 wildcarded) ; mov eax,[rbp+<off>](offset wildcarded) ;
  # add dword ptr [rdi+0x260],eax   -- 0x260 is a struct field offset and is kept literal.
  CPY = '488D0C48E8????????8B45??018760020000'
  # `push rbp/rbx/rsi/rdi/r12-r15` prologue + `lea rbp,[rsp+disp]` + `sub rsp,<frame>` + `xor edi,edi`
  # + `mov [rbp+0x10],edi`; disp and frame size wildcarded (both move with servicing builds).
  # Measured 2026-09-25 10:39Z: this one matched 20132/20144 but NOT the installed 20430.20092
  # (`TRY mso.dll -> CPY,FDS,NEG`), so it is kept as an optional control only.
  LEX = '40555356574154415541564157488D6C24??4881EC????????33FF48897D10'
  # ?FCommitHtmlTag@@YAH... prologue at 20144 RVA 0x1c540: `push rbx ; sub rsp,imm ; mov r11,r8 ;
  # mov eax,<bound> ; mov r8,rdx ; mov r10,r9 ; mov rbx,rcx ; mov edx,1 ; cmp r8,eax`.  Every imported
  # tag passes through here, so TAGS>0 with FDS=0 separates "importer ran, no div/span commit" from
  # "importer never ran".  Optional (the imm8 form may have become imm32 on the installed build).
  TAGS = '40534883EC??4D8BD8B8????????448BC24D8BD1488BD9BA01000000443BC0'
}
$REQUIRED = @('FDS','NEG','CPY')

# The xml-item scratch routine lives in the Mso98Win32Client module and mso reaches it through an
# ordinal import, so it is located by its own byte pattern.  XGATE covers
#   cmp qword ptr [r8], 0 ; mov rsi,r9 ; mov rdi,r8 ; movsxd rbx,edx ; mov r14,rcx ;
#   je <reuse-skip> ; lea eax,[rbx+1] ; cmp eax,[r9] ; jg <grow> ; mov rax,[rdi] ; mov [r14],rax
# i.e. the whole reuse decision in one 24-byte run.  Offsets from the match: the `cmp eax,[r9]`
# (the reuse gate itself) is +0x15, the "return the previous buffer" pair is +0x1a.  XGROWN matches
# the capacity write-back `lea eax,[rbx*2+0x21] ; mov [rsi],eax`.
# Verified 2026-09-25 13:35Z on the installed 16.0.20430.20092 x64 with tools/pat_multi.py:
# XGATE hits=1 at 0x1e9a1a (=> gate 0x1e9a2f, reuse 0x1e9a34), XGROWN hits=1 at 0x1e9aa8.
# The caller-side write: `lea r9,[rdi+0x210]; lea r8,[rdi+0x1f8]; mov edx,[rbp+disp8]; mov rcx,?;
# call [rip+?]` -- the FObtainXmlItemString request through the element-name slot pair.  Verified with
# tools/pat_multi.py to hit exactly one place on 20430.20092 (0x7f0b50), 20326.20144 (0x1c2e94) and
# 20326.20132 (0x1a6f04); +0x30 from the match is the following `call memcpy` where rcx=destination,
# rdx=source and **r8 = 2*n is the number of bytes the caller writes into the block whose capacity is
# the reuse gate's `2*n_prev+33` (STATE SS60-SS61, SS69).  That is the write-site measurement, taken at
# the write itself rather than inferred from the callee.
$SIGW = [ordered]@{
  XREQ = '4c8d8f100200004c8d87f80100008b55????????ff15????????'
}
$XWRITE_OFF = 0x30
$SIGX = [ordered]@{
  # Reuse gate, taken from the `lea eax,[rbx+1] ; cmp eax,[r9] ; jg` triple itself (8 bytes, no register
  # shuffling before it).  The 24-byte prologue run is the tighter form but the installed
  # Mso98win32client.dll on the runner matched only XGROWN with it (run 36151144839:
  # `TRYX Mso98win32client.dll -> XGROWN`), so this shorter one is the primary anchor.
  # Offsets from the match: `cmp eax,[r9]` +3, the "return the previous buffer" pair +8.
  XGATE  = '8d4301413b017f'
  XGROWN = '8d045d210000008906'
}
$XREQ_OFF = 0x3; $XREUSE_OFF = 0x8
function Get-Anchors([string]$path, $table) {
  $out = @{}
  $bytes = [IO.File]::ReadAllBytes($path)
  $pe = [BitConverter]::ToInt32($bytes, 0x3C)
  $opt = $pe + 24
  $imgbase = [BitConverter]::ToInt64($bytes, $opt + 24)
  $nsec = [BitConverter]::ToInt16($bytes, $pe + 6)
  $sh = $opt + [BitConverter]::ToInt16($bytes, $pe + 20)
  $tva = 0; $tpraw = 0
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $sh + $i * 40
    if ([Text.Encoding]::ASCII.GetString($bytes, $o, 8).Trim([char]0) -eq '.text') {
      $tva = [BitConverter]::ToInt32($bytes, $o + 12); $tpraw = [BitConverter]::ToInt32($bytes, $o + 20); break
    }
  }
  if (-not $tpraw) { return $out }
  $latin = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
  foreach ($k in $table.Keys) {
    $h = $table[$k]
    $bts = @(); for ($j = 0; $j -lt $h.Length; $j += 2) {
      $pair = $h.Substring($j, 2)
      if ($pair -eq '??') { $bts += -1 } else { $bts += [Convert]::ToInt32($pair, 16) } }
    # anchor the scan on the leading literal run, then verify byte-by-byte (?? = any byte)
    $lit = ''
    foreach ($v in $bts) { if ($v -lt 0) { break }; $lit += [char]$v }
    $idx = -1; $from = 0
    while ($true) {
      $c = $latin.IndexOf($lit, $from, [StringComparison]::Ordinal)
      if ($c -lt 0) { break }
      $ok = $true
      for ($m = 0; $m -lt $bts.Count; $m++) {
        if ($bts[$m] -ge 0 -and [int][byte]$latin[$c + $m] -ne $bts[$m]) { $ok = $false; break } }
      if ($ok) { $idx = $c; break }
      $from = $c + 1
    }
    if ($idx -lt 0) { continue }   # partial results are fine; the required-key check decides
    $out[$k] = ($tva + ($idx - $tpraw))
  }
  return $out
}

# The div/span commit code is expected in mso.dll, but the shared core has been split across the
# Mso*win32client.dll modules in recent builds, so try each host and keep the one with all anchors.
$hosts = @($mso.FullName)
$msoDir = Split-Path $mso.FullName
$hosts += @(Get-ChildItem $msoDir -Filter 'Mso*win32client.dll' -EA SilentlyContinue | ForEach-Object { $_.FullName })
$rv = @{}; $modTok = ''
foreach ($h in $hosts) {
  $r = Get-Anchors $h $SIG
  ("TRY {0} -> {1}" -f (Split-Path $h -Leaf), (($r.Keys | Sort-Object) -join ',')) | Add-Content $log
  $have = 0
  foreach ($q in $REQUIRED) { if ($r[$q]) { $have++ } }
  if ($have -eq $REQUIRED.Count) { $rv = $r; $modTok = (Split-Path $h -Leaf) -replace '\.dll$',''; break }
}
foreach ($k in $SIG.Keys) { if ($rv[$k]) { ("SIG {0} rva=0x{1:X}" -f $k, $rv[$k]) | Add-Content $log } }
if (-not $modTok) { 'ANCHOR_FAIL' | Add-Content $log; Get-Content $log; exit 1 }

$rvX = @{}; $modTokX = ''
foreach ($hx in @($hosts | Where-Object { $_ -ne $mso.FullName })) {
  $rx = Get-Anchors $hx $SIGX
  ("TRYX {0} -> {1}" -f (Split-Path $hx -Leaf), (($rx.Keys | Sort-Object) -join ',')) | Add-Content $log
  if ($rx['XGATE'] -and $rx['XGROWN']) { $rvX = $rx; $modTokX = (Split-Path $hx -Leaf) -replace '\.dll$',''; break }
}
if ($rvX['XGATE']) {
  ("SIGX {0} XGATE=0x{1:X} REQ=0x{2:X} REUSE=0x{3:X} GROWN=0x{4:X}" -f $modTokX, $rvX['XGATE'],
    ($rvX['XGATE'] + $XREQ_OFF), ($rvX['XGATE'] + $XREUSE_OFF), $rvX['XGROWN']) | Add-Content $log
} else { 'XML_ANCHORS_UNRESOLVED' | Add-Content $log }

# Resolve the caller-side write anchor here (not only in the cdb branch) so the passive arm's
# dump attribution can name the xml-item write frame as well.
$rvW = Get-Anchors $mso.FullName $SIGW
$xwRva = 0
if ($rvW['XREQ']) {
  $xwRva = $rvW['XREQ'] + $XWRITE_OFF
  ("SIGW XREQ=0x{0:X} XWRITE=0x{1:X}" -f $rvW['XREQ'], $xwRva) | Add-Content $log
} else { 'XML_WRITE_ANCHOR_UNRESOLVED' | Add-Content $log }


$cdb = $null
foreach ($c in @('C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe','C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe')) {
  if (Test-Path $c) { $cdb = $c; break } }
if (-not $cdb) {
  foreach ($b in @('C:\Program Files\WindowsApps','C:\Users\runneradmin\AppData\Local\Microsoft\WindowsApps')) {
    if (-not $cdb) { $h = Get-ChildItem $b -Directory -Filter 'Microsoft.WinDbg*' -EA SilentlyContinue |
      ForEach-Object { Get-ChildItem $_.FullName -Recurse -Filter cdb.exe -EA SilentlyContinue | Where-Object { $_.DirectoryName -match 'amd64|x64' } } | Select-Object -First 1
      if ($h) { $cdb = $h.FullName } } }
  if (-not $cdb) { winget install Microsoft.WinDbg --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-Null
    $h = Get-ChildItem 'C:\Program Files\WindowsApps' -Recurse -Filter cdb.exe -EA SilentlyContinue | Where-Object { $_.DirectoryName -match 'amd64|x64' } | Select-Object -First 1
    if ($h) { $cdb = $h.FullName } }
}
if (-not $cdb) { 'NO_CDB' | Add-Content $log; Get-Content $log; exit 1 }
"cdb=$cdb" | Add-Content $log
$priv = 'C:\pptdbg'; New-Item -ItemType Directory -Force -Path $priv | Out-Null
Copy-Item $cdb (Join-Path $priv 'cdb.exe') -Force
Get-ChildItem (Split-Path $cdb) -Filter *.dll -EA SilentlyContinue | Copy-Item -Destination $priv -Force
$cdbExe = Join-Path $priv 'cdb.exe'

$g = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Debuggers' -Recurse -Filter gflags.exe -EA SilentlyContinue |
     Where-Object { $_.DirectoryName -match '\\(x64|amd64)$' } | Select-Object -First 1
if (-not $g) { $g = Get-ChildItem 'C:\Program Files\Windows Kits\10\Debuggers' -Recurse -Filter gflags.exe -EA SilentlyContinue |
     Where-Object { $_.DirectoryName -match '\\(x64|amd64)$' } | Select-Object -First 1 }
if ($g) { & $g.FullName /p /enable $App /full | Out-Null; "gflags=$($g.FullName)" | Add-Content $log }
else { 'GFLAGS_FAIL (page heap not armed; WER dumps still active)' | Add-Content $log }
# WER owns LocalDumps; the IFEO copy is kept too because images differ, and the control below shows
# which one actually produced a dump on this host.  Without that control a dumps=0 reading is
# meaningless.
$exeNoExt = $App -replace '\.EXE$',''
# WER reads LocalDumps values **directly under** `...\LocalDumps\<image.exe>` (and the global
# `...\LocalDumps` key); the previous revision nested a second `LocalDumps` under them, which WER
# ignores -- that is why `DUMP_CHANNEL_CONTROL dumps=0` here was an instrument-side zero.
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' -Force | Out-Null
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps',
                ('HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\' + $App),
                ('HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\' + $exeNoExt),
                ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exeNoExt\LocalDumps"),
                ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$App\LocalDumps"))) {
  New-Item -Path $k -Force | Out-Null
  New-ItemProperty -Path $k -Name DumpFolder -Value (Join-Path $base 'dumps') -PropertyType ExpandString -Force | Out-Null
  New-ItemProperty -Path $k -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $k -Name DumpCount -Value 40 -PropertyType DWord -Force | Out-Null
}
$ctlKey = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\pwsh.exe'
New-Item -Path $ctlKey -Force | Out-Null
New-ItemProperty -Path $ctlKey -Name DumpFolder -Value (Join-Path $base 'dumps') -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $ctlKey -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $ctlKey -Name DumpCount -Value 5 -PropertyType DWord -Force | Out-Null
# Two crash shapes, because a fail-fast and an access violation take different paths through WER.
Start-Process -FilePath 'C:\Program Files\PowerShell\7\pwsh.exe' -ArgumentList '-NoProfile','-Command','[Environment]::FailFast("PC_DUMP_CHANNEL_CONTROL")' -Wait -WindowStyle Hidden -EA SilentlyContinue
Start-Process -FilePath 'C:\Program Files\PowerShell\7\pwsh.exe' -ArgumentList '-NoProfile','-Command','[Runtime.InteropServices.Marshal]::WriteByte([IntPtr]0x10,65)' -Wait -WindowStyle Hidden -EA SilentlyContinue
$cdc = 0
for ($i = 0; $i -lt 30; $i++) {
  $cdc = @(Get-ChildItem (Join-Path $base 'dumps') -Filter *.dmp -EA SilentlyContinue).Count
  if ($cdc) { break }
  Start-Sleep -Seconds 2
}
"DUMP_CHANNEL_CONTROL dumps=$cdc after_poll (a zero here makes every per-case dumps=0 unattributable)" | Add-Content $log
"GlobalFlag=$((Get-ItemProperty $k -Name GlobalFlag -EA SilentlyContinue).GlobalFlag)" | Add-Content $log

if (-not [IO.Path]::IsPathRooted($Dir)) { $Dir = Join-Path $base $Dir }
$exts = @($Ext.Split(',') | ForEach-Object { $_.Trim() })
$files = @(Get-ChildItem $Dir -File -EA SilentlyContinue | Where-Object { $exts -contains $_.Extension } | Sort-Object Name)
if ($NameFilter) { $files = @($files | Where-Object { $_.BaseName -match $NameFilter }) }
"cases=$($files.Count) dir=$Dir pwd=$((Get-Location).Path)" | Add-Content $log
if ($MaxCases -gt 0 -and $files.Count -gt $MaxCases) {
  $files = @($files | Select-Object -First $MaxCases)
}
if ($files.Count -eq 0) { 'NO_CARRIERS (empty corpus: the 0-hit readings below would be meaningless)' | Add-Content $log; Get-Content $log; exit 1 }
$dumpsDir = Join-Path $base 'dumps'
$appRoot = 'HKCU:\SOFTWARE\Microsoft\Office\16.0\' + ($App -replace '\.EXE$','')

function Take-Shot([string]$path) {
  # AGENTS 58: a "no hit" reading is meaningless if the document never opened and rendered, so every
  # case keeps the desktop frame next to its counter line.
  try {
    Add-Type -AssemblyName System.Windows.Forms,System.Drawing -EA SilentlyContinue
    $bnd = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $bmp = New-Object System.Drawing.Bitmap $bnd.Width, $bnd.Height
    $gg = [System.Drawing.Graphics]::FromImage($bmp)
    $gg.CopyFromScreen($bnd.Location, [System.Drawing.Point]::Empty, $bnd.Size)
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $gg.Dispose(); $bmp.Dispose()
    return $true
  } catch { 'SHOT_FAIL ' + $_.Exception.Message | Add-Content $log; return $false }
}

# First-run/onboarding suppression.  Both smoke cases of 2026-09-25 10:50Z ended with
# `Last event: Exit process 0:<pid>, code ffffffff` and a window titled
# "Microsoft PowerPoint" / "Welcome to Microsoft Outlook 2016", i.e. the process handed the document
# exited during the first-run experience while another instance stayed up.  The keys below are the
# documented telemetry/first-run switches; the warm-up that follows is what actually completes the
# one-time state, these only reduce what it wants to show.
$frKeys = @(
  @{k='HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\General'; n='PtarDisable'; v=1},
  @{k='HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\OSM'; n='Enablelogging'; v=0},
  @{k='HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\OSM'; n='EnableFileCollection'; v=0},
  @{k='HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Research'; n='DisableConnectToOffice'; v=1},
  @{k='HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Setup'; n='DisableFirstRunCheck'; v=1},
  @{k='HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Setup'; n='DisableAccountCreation'; v=1},
  @{k='HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Options'; n='DisableReportAProblem'; v=1},
  @{k='HKCU:\SOFTWARE\Microsoft\Office\16.0\common\general'; n='qfeupdate'; v=''},
  @{k='HKCU:\SOFTWARE\Microsoft\Office\16.0\common\general'; n='oemupdate'; v=''}
)
foreach ($fr in $frKeys) {
  New-Item -Path $fr.k -Force -EA SilentlyContinue | Out-Null
  New-ItemProperty -Path $fr.k -Name $fr.n -Value $fr.v -PropertyType DWord -Force -EA SilentlyContinue | Out-Null
}
"FIRST_RUN_KEYS=$($frKeys.Count) written=$(Get-Date -Format HH:mm:ss)" | Add-Content $log

# Warm-up: a fresh install can take a first-run path that relaunches the process, and a relaunched
# office host drops the document argument it was handed.  The smoke round of 2026-09-25 10:39Z saw the
# debugged POWERPNT exit while an instance with a bare "Microsoft PowerPoint" title stayed alive, so
# the app is started once with no document, allowed to reach a window, then closed before any case.
$exe0 = ($App -replace '\.EXE$','')
$wu = Start-Process -FilePath $appPath -PassThru -WindowStyle Hidden -EA SilentlyContinue
$wust = 'no-window'
if ($wu) {
  for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 3
    $t = (@(Get-Process $exe0 -EA SilentlyContinue | ForEach-Object { $_.MainWindowTitle }) -join ' | ')
    if ($t) { $wust = 'window'; break }
  }
  Get-Process $exe0 -EA SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }
  Start-Sleep -Seconds 4
  Get-Process $exe0 -EA SilentlyContinue | Where-Object { $_.StartTime -lt (Get-Date).AddSeconds(-5) } | Stop-Process -Force -EA SilentlyContinue
  Remove-Item ($appRoot + '\Resiliency') -Recurse -Force -EA SilentlyContinue
}
"WARMUP state=$wust titles=$t npp_before=$(@(Get-Process $exe0 -EA SilentlyContinue).Count)" | Add-Content $log

# No-debugger control for the first carrier: the same launch a user would do, without cdb in the
# picture, so "the application does not open this carrier" can be told apart from "cdb changes what
# the application does".
$ctl = @($files | Select-Object -First 1)
foreach ($cf in $ctl) {
  $cp = Start-Process -FilePath $appPath -ArgumentList ('"' + $cf.FullName + '"') -PassThru -WindowStyle Hidden -EA SilentlyContinue
  $cst = 'timeout'
  for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 3
    $cts = (@(Get-Process $exe0 -EA SilentlyContinue | ForEach-Object { $_.MainWindowTitle }) -join ' | ')
    $mods = 0
    try { $mods = @(Get-Process $exe0 -EA SilentlyContinue | Select-Object -First 1 -ExpandProperty Modules).Count } catch {}
    if ($cts -and $cts.IndexOf($cf.BaseName, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $cst = 'titled'; break }
  }
  $flatc = ($cts -replace '\s','')
  $ctm = 0
  if ($flatc -and $flatc.IndexOf($cf.BaseName, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $ctm = 1 }
  ('NODEBUG_CONTROL {0} state={1} npp={2} modules={3} titlematch={4} titles={5}' -f `
    $cf.Name, $cst, (@(Get-Process $exe0 -EA SilentlyContinue).Count), $mods, $ctm, $cts) | Add-Content $log
  Take-Shot (Join-Path $base ('out\shot_' + $Tag + '_NODEBUG_' + $cf.BaseName + '.png')) | Out-Null
  Get-Process $exe0 -EA SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }
  Start-Sleep -Seconds 3
  Get-Process $exe0 -EA SilentlyContinue | Where-Object { $_.StartTime -lt (Get-Date).AddSeconds(-5) } | Stop-Process -Force -EA SilentlyContinue
  Remove-Item ($appRoot + '\Resiliency') -Recurse -Force -EA SilentlyContinue
}


function Read-Dumps([string]$since) {
  # A negative fetched count doubles into a memcpy length of ~2^64, so the fault is self-recording:
  # full page heap + WER LocalDumps capture it without a debugger attached (and a debugger attached
  # changed what POWERPNT did on 2026-09-25 10:39Z - the debugged process exited before parsing).
  # Each dump is then opened read-only by cdb to lift the stack, so attribution happens after the fact.
  $out = @()
  foreach ($d in @(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue | Where-Object { $_.LastWriteTime -gt $since })) {
    $a = Join-Path $base ('out\dump_' + $d.BaseName + '.stack.txt')
    $dc = Join-Path $base ('out\dump_' + $d.BaseName + '.cdb')
    Set-Content -LiteralPath $dc -Value @('.echo ====STACK', 'k 24', '.echo ====EXR', '.cxr', '.echo ====FAULT', '.echo ====END', 'q') -Encoding ASCII
    & $cdbExe -z $d.FullName -cf $dc -y $symGlobal | Out-File $a -Encoding ASCII
    $txt = ''
    if (Test-Path $a) { $txt = Get-Content $a -Raw }
    $m = [regex]::Match($txt, '(?s)====STACK(.*)====EXR')
    $top = ((($m.Value -replace '====STACK|====EXR','') -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -First 6) -join ' || ')
    $sink = 0
    if ($rv['FDS'] -and $txt.IndexOf(('+0x{0:X}' -f $rv['FDS']), [StringComparison]::OrdinalIgnoreCase) -ge 0) { $sink = 1 }
    $cp = 0
    if ($rv['CPY'] -and $txt.IndexOf(('+0x{0:X}' -f $rv['CPY']), [StringComparison]::OrdinalIgnoreCase) -ge 0) { $cp = 1 }
    # The xml-item pair: `mso+0x7F0B80` is the memcpy call inside FProcessOpenXmlTag (XREQ match +0x30)
    # and `mso98win32client+0x1e9a34` is the callee's "hand back the previous buffer" reuse return;
    # either frame in a dump stack means the scratch block was in the faulting path.
    $xwf = 0
    if ($xwRva -and $txt.IndexOf(('+0x{0:X}' -f $xwRva), [StringComparison]::OrdinalIgnoreCase) -ge 0) { $xwf = 1 }
    $xcal = 0
    if ($rvX['XGATE'] -and $txt.IndexOf(('+0x{0:X}' -f ($rvX['XGATE'] + $XREUSE_OFF)), [StringComparison]::OrdinalIgnoreCase) -ge 0) { $xcal = 1 }
    $xmod = ([regex]::Matches($txt, 'mso98win32client')).Count
    ('DUMP {0} mso_sink_frame={1} mso_cpy_frame={2} xmlwrite_frame={3} xmlreuse_frame={4} w32c_frames={5} av={6} top={7}' -f $d.Name, $sink, $cp, $xwf, $xcal, $xmod, `
      ([regex]::Matches($txt, 'Access violation')).Count, $top.Substring(0, [Math]::Min(300, $top.Length))) | Add-Content $log
    $out += $d.Name
  }
  return $out
}
$symGlobal = Join-Path $env:TEMP ('sym_' + $Tag + '_d')
New-Item -ItemType Directory -Force -Path $symGlobal | Out-Null

foreach ($f in $files) {
  Set-Content -Path $f.FullName -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
  $exe = ($App -replace '\.EXE$','')
  # CloseMainWindow first: Stop-Process marks the next launch as a failed startup, and Office then
  # takes the Resiliency path (observed as a "上次启动失败" notification on the desktop), which would
  # make every later case's reading unattributable.
  Get-Process $exe -EA SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }
  Start-Sleep -Seconds 3
  Get-Process $exe -EA SilentlyContinue | Where-Object { $_.StartTime -lt (Get-Date).AddSeconds(-5) } | Stop-Process -Force -EA SilentlyContinue
  Remove-Item ($appRoot + '\Resiliency') -Recurse -Force -EA SilentlyContinue
  Start-Sleep -Seconds 1
  if ($NoCdb) {
    Set-Content -Path $f.FullName -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
    # Single-instance handoff would otherwise let one long-lived instance own every document and the
    # per-case attribution (which file produced which dump) collapses to a single window.
    for ($k = 0; $k -lt 2; $k++) {
      Get-Process $exe -EA SilentlyContinue | ForEach-Object { $null = $_.CloseMainWindow() }
      for ($j = 0; $j -lt 5; $j++) {
        if (-not @(Get-Process $exe -EA SilentlyContinue).Count) { break }
        Start-Sleep -Seconds 2
      }
      if (@(Get-Process $exe -EA SilentlyContinue).Count) {
        Get-Process $exe -EA SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 2
      }
    }
    $dp0 = Get-Date
    $la = if ($exe -eq 'OUTLOOK') { @('/eml', ('"' + $f.FullName + '"')) } else { ('"' + $f.FullName + '"') }
    $null = Start-Process -FilePath $appPath -ArgumentList $la -WindowStyle Hidden -EA SilentlyContinue
    $pst = 'timeout'
    for ($i = 0; $i * 3 -lt $WaitSec; $i++) {
      Start-Sleep -Seconds 3
      $ps = @(Get-Process $exe -EA SilentlyContinue)
      if (-not $ps) { $pst = 'app-exited'; break }
      $pt = (@($ps | ForEach-Object { $_.MainWindowTitle }) -join ' | ')
      if ($pt -and $pt.Replace(' ','').IndexOf($f.BaseName, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $pst = 'titled'; break }
    }
    for ($i = 0; $i -lt 12; $i++) {
      if (@(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue | Where-Object { $_.LastWriteTime -gt $dp0 }).Count) { break }
      Start-Sleep -Seconds 3
    }
    $pdn = @(Read-Dumps $dp0)
    Take-Shot (Join-Path $base ('out\shot_' + $Tag + '_' + $f.BaseName + '.png')) | Out-Null
    ('{0,-26} PASSIVE state={1} dumps={2} names={3}' -f $f.Name, $pst, $pdn.Count, ($pdn -join ',')) | Add-Content $log
    Get-Process $exe -EA SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }
    Start-Sleep -Seconds 3
    Get-Process $exe -EA SilentlyContinue | Where-Object { $_.StartTime -lt (Get-Date).AddSeconds(-5) } | Stop-Process -Force -EA SilentlyContinue
    Remove-Item ($appRoot + '\Resiliency') -Recurse -Force -EA SilentlyContinue
    continue
  }
  $cmdf = Join-Path $base ('out\' + $f.BaseName + '.cdb')
  # First-chance noise on this app is large (C++ EH, WinRT originate error, 0xc004f013 from the JSI
  # worker).  Declaring them notification-only keeps `g` running; the smoke run of 2026-09-25 showed
  # cdb returning from `g` into the tail commands mid-startup (prompt moved to thread 7, a v8jsi
  # SleepConditionVariableSRW wait), after which `q` killed the debuggee before the carrier was read.
  # On top of that the run now arms the breakpoints *after* an `sxe ld:mso.dll` break so no deferred
  # `bu` resolution is needed, and the resume ladder below survives any further stray stop.
  $c = @('.sympath()', ('.echo ====CASE ' + $f.BaseName))
  foreach ($ec in @('sxn e06d7363','sxn e0434352','sxn c004f013','sxn 40080201',
                    'sxn 000006ef','sxn 80000003','sxn c00000fd')) { $c += $ec }
  # WER LocalDumps produced nothing even for a deliberate access violation on the runner image
  # (`DUMP_CHANNEL_CONTROL dumps=0 after_poll` in run 36173048936), so the dump has to be taken by
  # the debugger itself: first-chance AVs stay notification-only (Office raises them internally),
  # a second-chance AV prints the context + stack and writes a full dump next to the case log.
  $c += 'sxn av'
  $c += ('sxd av ".echo AV2;r;k 12;.dump /ma dumpav_' + $f.BaseName + '.dmp;g"')
  $c += 'sxe ld:mso.dll'
  $c += 'g'
  $c += '.echo ====MSO_LOADED'
  $c += ('? ' + $modTok + '+0x' + ('{0:X}' -f $rv['FDS']))
  # Register-only payloads: `r` prints the full context, which is what carries the count (ecx at NEG)
  # and the length handed to memcpy (r8 = 2*count at CPY).  `r rcx rax` was invalid cdb syntax.
  # /1 = stop after the first hit: the controls only need to answer "did this layer run at all",
  # and an unconditional payload would fire once per tag (thousands of debugger round trips a file).
  if ($rv['LEX']) { $c += ("bu /1 {1}+0x{0:X} `".echo LEX;g`"" -f $rv['LEX'], $modTok) }
  if ($rv['TAGS']) { $c += ("bu /1 {1}+0x{0:X} `".echo TAGS;g`"" -f $rv['TAGS'], $modTok) }
  $c += ("bu {1}+0x{0:X} `".echo FDS;g`"" -f $rv['FDS'], $modTok)
  $c += ("bu {1}+0x{0:X} `".echo NEG;r;g`"" -f $rv['NEG'], $modTok)
  $c += ("bu {1}+0x{0:X} `".echo CPY;r;g`"" -f $rv['CPY'], $modTok)
  if ($xwRva) {
    $c += ("bu {1}+0x{0:X} `".echo XWRITE;r;g`"" -f $xwRva, $modTok)
  }
  $c += 'bl'
  $c += 'g'
  # The smoke round of 2026-09-25 10:35Z ended with all three breakpoints bound and enabled
  # (`bl` -> `0 e 00007ffb`25f095e8 ... mso!Ordinal25108+0x148 ".echo FDS;g"`) and `g` answering
  # "No runnable debuggees" from the first stop onward, i.e. the debugged POWERPNT had exited.
  # `.lastevent` on each stop records which event ended the run (exit code vs breakpoint vs exception)
  # so an early exit cannot be read as "the code path was not reached".
  # `q` at the end of the command file terminates the debuggee, so the resume ladder has to be long
  # enough to outlast the whole document open.  Run 36154668572 exhausted 8 lines while WINWORD had
  # already mapped mso (`loaded=1`) but had not parsed the carrier yet (`TAGS=0 LEX=0`, and the process
  # was gone by the sample point: `npp=0`), which made every zero an instrument-side zero.
  for ($i = 0; $i -lt $Stops; $i++) { $c += '.echo ====STOP'; $c += '.lastevent'; $c += 'g' }
  $c += '.echo ====LADDER_END'
  $c += 'bl'
  # The xml-item reuse gate: armed last, and deferred (`bu`) so it resolves whenever that module is
  # mapped.  `dq @r9 l1` reads the stored capacity (a **byte** count, `2*n_prev+33`) while edx is the
  # **character** count being asked for; `dq @rsp+48 l1` is the return address, which names the
  # caller site (4 pushes + sub rsp,0x28 puts the return address at rsp+0x48 here).
  if ($modTokX) {
    $c += '.echo ====XML_ARM'
    $c += ("bu {1}+0x{0:X} `".echo REQ;r;dq @r9 l1;dq @rsp+48 l1;g`"" -f ($rvX['XGATE'] + $XREQ_OFF), $modTokX)
    $c += ("bu {1}+0x{0:X} `".echo REUSE;r;dq @r9 l1;dq @rsp+48 l1;g`"" -f ($rvX['XGATE'] + $XREUSE_OFF), $modTokX)
    $c += ("bu {1}+0x{0:X} `".echo GROWN;r;g`"" -f $rvX['XGROWN'], $modTokX)
    $c += 'bl'
    $c += 'g'
    for ($i = 0; $i -lt $Stops; $i++) { $c += '.echo ====XSTOP'; $c += '.lastevent'; $c += 'g' }
    $c += '.echo ====XML_END'
    $c += 'bl'
  }
  $c += '.echo ====END'
  $c += 'q'
  Set-Content -LiteralPath $cmdf -Value $c -Encoding ASCII
  $t0 = Get-Date
  $stdout = Join-Path $base ('out\' + $f.BaseName + '.log')
  # The shipped default symbol path on the runner is `srv*`; a network symbol probe at every module
  # load is what left cdb sitting before the initial breakpoint.  Point it at an empty local dir and
  # switch the network source off.
  $exe = ($App -replace '\.EXE$','')
  $symLocal = Join-Path $env:TEMP ('sym_' + $Tag)
  New-Item -ItemType Directory -Force -Path $symLocal | Out-Null
  # `.eml` has no Office default association on a fresh install; the registered handler is
  # HKCR:\Outlook.File.eml.15\shell\open\command = OUTLOOK.EXE /eml "%1", so the wave passes that verb
  # explicitly (AGENTS 61: name the application when the association is absent) rather than ShellExecute.
  # Office is single-instance per user: launching the app on a document while another instance owns it
  # hands the file over and the new process exits immediately, which is what produced
  # `loaded=0 npp=0 stops=1 ladder=8` with `WARMUP npp_before=1` in run 36151144839.  Close every
  # instance (gracefully first, so Office does not mark the profile as a failed startup) and wait for
  # the count to reach zero before attaching.
  for ($k = 0; $k -lt 2; $k++) {
    Get-Process $exe -EA SilentlyContinue | ForEach-Object { $null = $_.CloseMainWindow() }
    for ($j = 0; $j -lt 6; $j++) {
      if (-not @(Get-Process $exe -EA SilentlyContinue).Count) { break }
      Start-Sleep -Seconds 2
    }
    if (@(Get-Process $exe -EA SilentlyContinue).Count) {
      Get-Process $exe -EA SilentlyContinue | Stop-Process -Force
      Start-Sleep -Seconds 2
    }
  }
  ('PRELAUNCH instances=' + @(Get-Process $exe -EA SilentlyContinue).Count) | Add-Content $log
  $caseArg = '"' + $f.FullName + '"'
  if ($exe -eq 'OUTLOOK') { $caseArg = '/eml "' + $f.FullName + '"' }
  $cdbArgs = @('-y', $symLocal, '-cf', $cmdf, $appPath, $caseArg)
  $p = Start-Process -FilePath $cdbExe -ArgumentList $cdbArgs -PassThru -WindowStyle Hidden `
       -RedirectStandardOutput $stdout -RedirectStandardError ($stdout + '.err')
  $st = 'timeout'
  for ($i = 0; $i * 3 -lt $WaitSec; $i++) {
    Start-Sleep -Seconds 3
    if (-not (Get-Process -Id $p.Id -EA SilentlyContinue)) { $st = 'cdb-exited'; break }
  }
  $exe = ($App -replace '\.EXE$','')
  # Titles/instance count must be sampled *before* the recycle below, otherwise the window evidence
  # can never be positive (the previous revision read them after Stop-Process: titlematch=0 npp=0 by
  # construction).
  $procs = @(Get-Process $exe -EA SilentlyContinue)
  $titles = (@($procs | ForEach-Object { $_.MainWindowTitle }) -join ' | ')
  $npp = $procs.Count
  Get-Process $exe -EA SilentlyContinue | Where-Object { $_.StartTime -gt $t0.AddSeconds(-3) } | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep -Seconds 1
  Get-Process -Id $p.Id -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  # Screen capture per case (AGENTS 58): a "no hit" reading is meaningless if the document never
  # actually opened and rendered, so the frame is archived next to the counter line.
  Take-Shot (Join-Path $base ('out\shot_' + $Tag + '_' + $f.BaseName + '.png')) | Out-Null
  $txt = ''
  if (Test-Path $stdout) { $txt = Get-Content $stdout -Raw }
  if ($txt -match 'Invalid switch|^usage: cdb') {
    ('CDB_ARGV_FAIL ' + $f.Name + ' :: ' + (($txt -split "`n")[0..2] -join ' / ')) | Add-Content $log
    Get-Content $log
    exit 1
  }
  # `unres` must describe only the mso-side arming, so split the transcript at the xml arm marker.
  $txparts = ($txt -split '====XML_ARM')
  $txtPre = $txparts[0]
  $txtXml = ''
  if ($txparts.Count -gt 1) { $txtXml = ($txparts[1..($txparts.Count-1)] -join '====XML_ARM') }
  $req = ([regex]::Matches($txt, '(?m)^REQ')).Count
  $reuse = ([regex]::Matches($txt, '(?m)^REUSE')).Count
  $grown = ([regex]::Matches($txt, '(?m)^GROWN')).Count
  $xw = ([regex]::Matches($txt, '(?m)^XWRITE')).Count
  $xwbig = 0
  foreach ($mm in [regex]::Matches($txt, '(?m)^r8=([0-9a-fA-F]{16})')) {
    $v = [Convert]::ToUInt64($mm.Groups[1].Value, 16)
    if ($v -ge 200 -and $v -lt 0x80000000) { $xwbig++ }
  }
  $xpairs = @(); $xoob = 0
  foreach ($mk in @('REQ','REUSE')) {
    $ln = $txtXml -split "`n"; $grab = -1
    for ($k = 0; $k -lt $ln.Count; $k++) {
      if ($ln[$k] -notmatch ('^' + $mk + '$')) { continue }
      $n = -1; $cap = -1; $ret = ''
      for ($m = $k; $m -lt [Math]::Min($k + 30, $ln.Count); $m++) {
        if ($n -lt 0 -and $ln[$m] -match 'rdx=([0-9a-fA-F]+)') { $n = [Convert]::ToInt64($Matches[1],16) }
        if ($ln[$m] -match '^[0-9a-fA-F`]+\s+([0-9a-fA-F]{8})`([0-9a-fA-F]{4})') {
          if ($cap -lt 0) { $cap = [Convert]::ToInt64($Matches[1],16) }
          elseif (-not $ret) { $ret = $Matches[1] + $Matches[2] }
        }
        if ($n -ge 0 -and $cap -ge 0 -and $ret) { break }
      }
      if ($n -ge 0 -and $cap -ge 0) {
        $w = 2 * $n + 2
        if ($w -gt $cap) { $xoob++ }
        if ($xpairs.Count -lt 8) { $xpairs += ('{0}(n={1},cap={2},w={3},{4},ret={5})' -f $mk, $n, $cap, $w, $(if ($w -gt $cap) {'OOB'} else {'in'}), $ret) }
      }
    }
  }
  $xs = ($xpairs -join ';')
  if ($xs.Length -gt 190) { $xs = $xs.Substring(0, 190) }
  $fds = ([regex]::Matches($txt, '(?m)^FDS')).Count
  $neg = ([regex]::Matches($txt, '(?m)^NEG')).Count
  $cpy = ([regex]::Matches($txt, '(?m)^CPY')).Count
  $lex = ([regex]::Matches($txt, '(?m)^LEX')).Count
  $tags = ([regex]::Matches($txt, '(?m)^TAGS')).Count
  $dead = ([regex]::Matches($txt, 'No runnable debuggees')).Count
  $lev  = (([regex]::Match($txt, '(?m)^Last event:.*')).Value -replace '\s+', ' ')
  if ($lev.Length -gt 110) { $lev = $lev.Substring(0, 110) }
  $big = ([regex]::Matches($txt, '(?m)^r8=([89ABCDEF][0-9A-F]{15}|[1-9][0-9A-F]{15})')).Count
  $av  = ([regex]::Matches($txt, 'Access violation')).Count
  $av2 = ([regex]::Matches($txt, '(?m)^AV2')).Count
  # Instrument self-reads: ====MSO_LOADED proves the sxe ld: break happened, `mso+0x…` resolution
  # failure would print "Unable to resolve", and ====LADDER_END means the resume ladder was consumed
  # (i.e. the target kept stopping) rather than the case ending because the harness gave up.
  $loaded = ([regex]::Matches($txt, '(?m)^====MSO_LOADED')).Count
  $unres  = ([regex]::Matches($txtPre, 'Unable to resolve')).Count
  $stops  = ([regex]::Matches($txt, '(?m)^====STOP')).Count
  $ladder = ([regex]::Matches($txt, '(?m)^====LADDER_END')).Count
  $bind   = ([regex]::Matches($txt, 'Evaluate expression')).Count
  $flat = ($titles -replace '\s', '')
  $tm = 0
  if ($flat -and $flat.IndexOf($f.BaseName, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $tm = 1 }
  ('{0,-26} state={1,-11} TAGS={2} LEX={3} FDS={4} NEG={5} CPY={6} REQ={7} REUSE={8} GROWN={9} XWRITE={10} xwbig={11} xoob={12} av2={13} r8big={14} av={12} dumps={13} titlematch={14} npp={15} loaded={16} unres={17} stops={18} dead={19} ladder={20} expr={21} xmlpairs={22} titles={23} lastevent={24}' -f `
    $f.Name, $st, $tags, $lex, $fds, $neg, $cpy, $req, $reuse, $grown, $xw, $xwbig, $xoob, $av2, $big, $av, (@(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue | Where-Object { $_.LastWriteTime -gt $t0 }).Count), `
    $tm, $npp, $loaded, $unres, $stops, $dead, $ladder, $bind, $xs, $titles, $lev) | Add-Content $log
  if (-not $loaded -or $unres -or -not $bind) {
    ('INSTRUMENT_NOT_PROVEN ' + $f.Name + ' loaded=' + $loaded + ' unres=' + $unres + ' expr=' + $bind +
     ' :: a zero hit count in this case is not attributable') | Add-Content $log
  }
}
if ($g) { & $g.FullName /p /disable $App | Out-Null }
'dump_total=' + @(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue).Count | Add-Content $log
Get-Content $log
'ALLDONE'
