# mso_html_len_probe.ps1 - runner-side measurement of the mso HTML div/span commit length.
#
# Anchors four sites inside the *installed* mso.dll by code signature (no PDB, no symbol server),
# then opens each HTML carrier under cdb with full page heap armed and counts:
#   FDS  ?FCommitDivSpanCore@ @0x1c9b68        - every div/span commit
#   NEG  the `test ecx,ecx / jns` block @0x1c9cd2 - commits whose fetched count is negative
#   CPY  the memcpy argument site @0x1c9d50     - the copy actually issued, with r8 = 2*count
# The interesting reading is NEG>0 and/or a CPY whose r8 is enormous (negative doubled).
# Signature source: office-sep2026-fixsurface-20260913/bin/mso_20326.20144_x64.dll
param([string]$Dir = 'carriers_h',
      [string]$Tag = 'htmllen',
      [string]$Base = '.',
      [string]$App = 'POWERPNT.EXE',
      [int]$WaitSec = 110)
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$root = 'C:\Program Files\Microsoft Office\root\Office16'
$app  = Join-Path $root $App
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
if ($App -notmatch '\.EXE$') { $app = Get-ChildItem $root -Filter $App -EA SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName }
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
}
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
    if ($idx -lt 0) { return $out }
    $out[$k] = ($tva + ($idx - $tpraw))
  }
  return $out
}

# The div/span commit code is expected in mso.dll, but the shared core has been split across the
# Mso*win32client.dll modules in recent builds, so try each host and keep the one with all anchors.
$hosts = @($mso.FullName)
$dir = Split-Path $mso.FullName
$hosts += @(Get-ChildItem $dir -Filter 'Mso*win32client.dll' -EA SilentlyContinue | ForEach-Object { $_.FullName })
$rv = @{}; $modTok = ''
foreach ($h in $hosts) {
  $r = Get-Anchors $h
  ("TRY {0} -> {1}" -f (Split-Path $h -Leaf), (($r.Keys | Sort-Object) -join ',')) | Add-Content $log
  if ($r.Count -eq $SIG.Count) { $rv = $r; $modTok = (Split-Path $h -Leaf) -replace '\.dll$',''; break }
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

$g = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Debuggers' -Recurse -Filter gflags.exe -EA SilentlyContinue | Select-Object -First 1
if ($g) { & $g.FullName /p /enable $App /full | Out-Null }
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

$files = @(Get-ChildItem $Dir -File | Where-Object { $_.Extension -in '.htm','.html','.mht','.mhtml' } | Sort-Object Name)
"cases=$($files.Count)" | Add-Content $log
$dumpsDir = Join-Path $base 'dumps'
foreach ($f in $files) {
  Set-Content -Path $f.FullName -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
  Get-Process ($App -replace '\.EXE$','') -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep -Seconds 2
  $cmdf = Join-Path $base ('out\' + $f.BaseName + '.cdb')
  $c = @('.sympath()', '.echo ====CASE ' + $f.BaseName)
  # Register-only payloads: the NEG anchor starts *at* `neg ecx`, so a hit means the fetched count
  # was negative (ecx = |count|, rax = used); the CPY anchor is the instruction before `call memcpy`
  # with r8 = 2*count.  Avoiding `poi(@rbp+off)` keeps the probe independent of this build's frame layout.
  $c += ("bu {1}+0x{0:X} `".echo FDS; g`"" -f $rv['FDS'], $modTok)
  $c += ("bu {1}+0x{0:X} `".echo NEG; r rcx rax; g`"" -f $rv['NEG'], $modTok)
  $c += ("bu {1}+0x{0:X} `".echo CPY; r r8 rcx; g`"" -f $rv['CPY'], $modTok)
  $c += 'sxn av'
  $c += 'g'
  $c += '.echo ====EXC'; $c += 'r'; $c += 'k 16'; $c += '.echo ====END'; $c += 'q'
  Set-Content -LiteralPath $cmdf -Value $c -Encoding ASCII
  $t0 = Get-Date
  $stdout = Join-Path $base ('out\' + $f.BaseName + '.log')
  $p = Start-Process -FilePath $cdbExe -ArgumentList @('-cf', $cmdf, $app, ('"' + $f.FullName + '"')) -PassThru -WindowStyle Hidden `
       -RedirectStandardOutput $stdout -RedirectStandardError ($stdout + '.err')
  $st = 'timeout'
  for ($i = 0; $i * 3 -lt $WaitSec; $i++) {
    Start-Sleep -Seconds 3
    if (-not (Get-Process -Id $p.Id -EA SilentlyContinue)) { $st = 'cdb-exited'; break }
  }
  $exe = ($App -replace '\.EXE$','')
  Get-Process $exe -EA SilentlyContinue | Where-Object { $_.StartTime -gt $t0.AddSeconds(-3) } | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep -Seconds 1
  Get-Process -Id $p.Id -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  $txt = ''
  if (Test-Path $stdout) { $txt = Get-Content $stdout -Raw }
  $fds = ([regex]::Matches($txt, '(?m)^FDS')).Count
  $neg = ([regex]::Matches($txt, '(?m)^NEG')).Count
  $cpy = ([regex]::Matches($txt, '(?m)^CPY')).Count
  $big = ([regex]::Matches($txt, '(?m)^r8=([89ABCDEF][0-9A-F]{15}|[1-9][0-9A-F]{15})')).Count
  $av  = ([regex]::Matches($txt, 'Access violation')).Count
  $titles = (@(Get-Process $exe -EA SilentlyContinue | ForEach-Object { $_.MainWindowTitle }) -join ' | ')
  ('{0,-26} state={1,-11} FDS={2} NEG={3} CPY={4} r8big={5} av={6} dumps={7} titles={8}' -f `
    $f.Name, $st, $fds, $neg, $cpy, $big, $av, (@(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue | Where-Object { $_.LastWriteTime -gt $t0 }).Count), $titles) | Add-Content $log
}
if ($g) { & $g.FullName /p /disable $App | Out-Null }
'dump_total=' + @(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue).Count | Add-Content $log
Get-Content $log
'ALLDONE'
