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
$mso  = Get-ChildItem $root -Filter mso.dll | Select-Object -First 1
$base = (Resolve-Path $Base).Path
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out'), (Join-Path $base 'dumps') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
"START $(Get-Date -Format HH:mm:ss) app=$App mso=$($mso.VersionInfo.FileVersion) size=$($mso.Length)" | Set-Content $log

$SIG = [ordered]@{
  FDS = '4C894C2420488954241055535657415441554157488D6C24'
  NEG = 'F7D98BD1483BD077E2482BC2'
  CPY = '488D0C48E87742EEFF8B4577018760020000E9CD00000048'
}
$bytes = [IO.File]::ReadAllBytes($mso.FullName)
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
$latin = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
$rv = @{}
foreach ($k in $SIG.Keys) {
  $pat = ''; $h = $SIG[$k]
  for ($j = 0; $j -lt $h.Length; $j += 2) { $pat += [char][Convert]::ToInt32($h.Substring($j, 2), 16) }
  $idx = $latin.IndexOf($pat, [StringComparison]::Ordinal)
  if ($idx -lt 0) { "SIGMISS $k" | Add-Content $log; continue }
  $rv[$k] = $imgbase + $tva + ($idx - $tpraw) - $imgbase     # RVA
  ("SIG {0} rva=0x{1:X}" -f $k, $rv[$k]) | Add-Content $log
}
if ($rv.Count -lt 3) { 'ANCHOR_FAIL' | Add-Content $log; Get-Content $log; exit 1 }

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
  $c += ("bu mso+0x{0:X} `".echo FDS; g`"" -f $rv['FDS'])
  $c += ("bu mso+0x{0:X} `".echo NEG; r rcx; g`"" -f $rv['NEG'])
  $c += ("bu mso+0x{0:X} `".echo CPY; r r8; ? poi(@rbp+0x77); g`"" -f $rv['CPY'])
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
