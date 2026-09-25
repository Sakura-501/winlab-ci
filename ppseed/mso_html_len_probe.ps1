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
      [string]$Ext = '.htm,.html,.mht,.mhtml')
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
function Get-Anchors([string]$path) {
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
  foreach ($k in $SIG.Keys) {
    $h = $SIG[$k]
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
  $r = Get-Anchors $h
  ("TRY {0} -> {1}" -f (Split-Path $h -Leaf), (($r.Keys | Sort-Object) -join ',')) | Add-Content $log
  $have = 0
  foreach ($q in $REQUIRED) { if ($r[$q]) { $have++ } }
  if ($have -eq $REQUIRED.Count) { $rv = $r; $modTok = (Split-Path $h -Leaf) -replace '\.dll$',''; break }
}
foreach ($k in $SIG.Keys) { if ($rv[$k]) { ("SIG {0} rva=0x{1:X}" -f $k, $rv[$k]) | Add-Content $log } }
if (-not $modTok) { 'ANCHOR_FAIL' | Add-Content $log; Get-Content $log; exit 1 }


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
foreach ($k in @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exeNoExt",
                "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\$exeNoExt")) {
  New-Item -Path "$k\LocalDumps" -Force | Out-Null
  New-ItemProperty -Path "$k\LocalDumps" -Name DumpFolder -Value (Join-Path $base 'dumps') -PropertyType ExpandString -Force | Out-Null
  New-ItemProperty -Path "$k\LocalDumps" -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path "$k\LocalDumps" -Name DumpCount -Value 40 -PropertyType DWord -Force | Out-Null
}
$ctlKey = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\pwsh.exe'
New-Item -Path $ctlKey -Force | Out-Null
New-ItemProperty -Path $ctlKey -Name DumpFolder -Value (Join-Path $base 'dumps') -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $ctlKey -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $ctlKey -Name DumpCount -Value 5 -PropertyType DWord -Force | Out-Null
Start-Process -FilePath 'C:\Program Files\PowerShell\7\pwsh.exe' -ArgumentList '-NoProfile','-Command','[Environment]::FailFast("PC_DUMP_CHANNEL_CONTROL")' -Wait -WindowStyle Hidden -EA SilentlyContinue
"DUMP_CHANNEL_CONTROL dumps=" + @(Get-ChildItem (Join-Path $base 'dumps') -Filter *.dmp -EA SilentlyContinue).Count | Add-Content $log
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
  $cmdf = Join-Path $base ('out\' + $f.BaseName + '.cdb')
  # First-chance noise on this app is large (C++ EH, WinRT originate error, 0xc004f013 from the JSI
  # worker).  Declaring them notification-only keeps `g` running; the smoke run of 2026-09-25 showed
  # cdb returning from `g` into the tail commands mid-startup (prompt moved to thread 7, a v8jsi
  # SleepConditionVariableSRW wait), after which `q` killed the debuggee before the carrier was read.
  # On top of that the run now arms the breakpoints *after* an `sxe ld:mso.dll` break so no deferred
  # `bu` resolution is needed, and the resume ladder below survives any further stray stop.
  $c = @('.sympath()', ('.echo ====CASE ' + $f.BaseName))
  foreach ($ec in @('sxn av','sxn e06d7363','sxn e0434352','sxn c004f013','sxn 40080201',
                    'sxn 000006ef','sxn 80000003','sxn c00000fd')) { $c += $ec }
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
  $c += 'bl'
  $c += 'g'
  # The smoke round of 2026-09-25 10:35Z ended with all three breakpoints bound and enabled
  # (`bl` -> `0 e 00007ffb`25f095e8 ... mso!Ordinal25108+0x148 ".echo FDS;g"`) and `g` answering
  # "No runnable debuggees" from the first stop onward, i.e. the debugged POWERPNT had exited.
  # `.lastevent` on each stop records which event ended the run (exit code vs breakpoint vs exception)
  # so an early exit cannot be read as "the code path was not reached".
  for ($i = 0; $i -lt 8; $i++) { $c += '.echo ====STOP'; $c += '.lastevent'; $c += 'g' }
  $c += '.echo ====LADDER_END'
  $c += 'bl'
  $c += '.echo ====END'
  $c += 'q'
  Set-Content -LiteralPath $cmdf -Value $c -Encoding ASCII
  $t0 = Get-Date
  $stdout = Join-Path $base ('out\' + $f.BaseName + '.log')
  # The shipped default symbol path on the runner is `srv*`; a network symbol probe at every module
  # load is what left cdb sitting before the initial breakpoint.  Point it at an empty local dir and
  # switch the network source off.
  $symLocal = Join-Path $env:TEMP ('sym_' + $Tag)
  New-Item -ItemType Directory -Force -Path $symLocal | Out-Null
  # `.eml` has no Office default association on a fresh install; the registered handler is
  # HKCR:\Outlook.File.eml.15\shell\open\command = OUTLOOK.EXE /eml "%1", so the wave passes that verb
  # explicitly (AGENTS 61: name the application when the association is absent) rather than ShellExecute.
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
  # Instrument self-reads: ====MSO_LOADED proves the sxe ld: break happened, `mso+0x…` resolution
  # failure would print "Unable to resolve", and ====LADDER_END means the resume ladder was consumed
  # (i.e. the target kept stopping) rather than the case ending because the harness gave up.
  $loaded = ([regex]::Matches($txt, '(?m)^====MSO_LOADED')).Count
  $unres  = ([regex]::Matches($txt, 'Unable to resolve')).Count
  $stops  = ([regex]::Matches($txt, '(?m)^====STOP')).Count
  $ladder = ([regex]::Matches($txt, '(?m)^====LADDER_END')).Count
  $bind   = ([regex]::Matches($txt, 'Evaluate expression')).Count
  $flat = ($titles -replace '\s', '')
  $tm = 0
  if ($flat -and $flat.IndexOf($f.BaseName, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $tm = 1 }
  ('{0,-26} state={1,-11} TAGS={2} LEX={3} FDS={4} NEG={5} CPY={6} r8big={7} av={8} dumps={9} titlematch={10} npp={11} loaded={12} unres={13} stops={14} dead={15} ladder={16} expr={17} titles={18} lastevent={19}' -f `
    $f.Name, $st, $tags, $lex, $fds, $neg, $cpy, $big, $av, (@(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue | Where-Object { $_.LastWriteTime -gt $t0 }).Count), `
    $tm, $npp, $loaded, $unres, $stops, $dead, $ladder, $bind, $titles, $lev) | Add-Content $log
  if (-not $loaded -or $unres -or -not $bind) {
    ('INSTRUMENT_NOT_PROVEN ' + $f.Name + ' loaded=' + $loaded + ' unres=' + $unres + ' expr=' + $bind +
     ' :: a zero hit count in this case is not attributable') | Add-Content $log
  }
}
if ($g) { & $g.FullName /p /disable $App | Out-Null }
'dump_total=' + @(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue).Count | Add-Content $log
Get-Content $log
'ALLDONE'
