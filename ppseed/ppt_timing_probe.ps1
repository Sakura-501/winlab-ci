# ppt_timing_probe.ps1 - runner-side measurement of the PowerPoint slide-timing validator.
#
# For each .pptx carrier: anchor the validator family inside the *installed* ppcore.dll by code
# signature (build-independent), then open the deck twice under cdb - once as a document, once as an
# auto-starting show (/s) - and count the entry hits of:
#   FVAL   ?FValidateSlideTiming@@YA_NAEAVSlideBase@@_N@Z      (arg2 in dl = collectForRemoval)
#   TVCTOR ??0ValidateEffectsTraversal@@QEAA@_N@Z              (arg2 in dl)
#   DROP   ?RemoveInvalidEffects@ValidateEffectsTraversal@@QEAAXXZ
#   ONT    ?OnTraverseEffect@ValidateEffectsTraversal@@...
# Full page heap + WER local dumps stay armed so an AV is captured as a dump as well.
#
# Skeletons reused: ppcore-oracle-20260925/runner/ppt_sweep.ps1 (page heap / WER / MOTW / state poll)
# and excel-textimport-tabcol-oobwrite-20260925/tools/find_anchor.ps1 (Latin-1 IndexOf signature scan).
param([string]$Dir = 'carriers_t',
      [string]$Tag = 'ppttime',
      [string]$Base = '.',
      [int]$WaitSec = 110,
      [switch]$Show)
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$base = (Resolve-Path $Base).Path
$pp   = 'C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE'
$pcd  = 'C:\Program Files\Microsoft Office\root\Office16\ppcore.dll'
$cdb  = @('C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe',
          'C:\Program Files (x86)\Windows Kits\10\Debuggers\amd64\cdb.exe') | Where-Object { Test-Path $_ } | Select-Object -First 1
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out'), (Join-Path $base 'dumps') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_probe.txt')
"START $(Get-Date -Format HH:mm:ss) cdb=$cdb" | Set-Content $log
if (-not $cdb) { 'NO_CDB' | Add-Content $log; exit 1 }
"ppcore=$( (Get-Item $pcd).VersionInfo.FileVersion ) pp=$( (Get-Item $pp).VersionInfo.FileVersion ) session=$((Get-Process -Id $PID).SessionId)" | Add-Content $log

# ---- signature anchors (x64) ----
$SIG = [ordered]@{
  FVAL   = '48895C2418885424105556574154415541564157488DAC24'
  TVCTOR = '4533C9C6411801488D05A6D459014C894908488901448AC2'
  DROP   = '4883C120E9E7E576009090909090909090909090488BC448'
  ONT    = '40555356574154415541564157488BEC4883EC584C8BFA4C'
}
$bytes = [IO.File]::ReadAllBytes($pcd)
$peOff = [BitConverter]::ToInt32($bytes, 0x3C)
$imgBase = [BitConverter]::ToInt64($bytes, $peOff + 24 + 24)     # PE32+ ImageBase at opt+24
$secOff = $peOff + 24 + [BitConverter]::ToInt16($bytes, $peOff + 20)
$textVa = 0; $textRaw = 0
for ($i = 0; $i -lt [BitConverter]::ToInt16($bytes, $peOff + 6); $i++) {
  $o = $secOff + $i * 40
  $nm = [Text.Encoding]::ASCII.GetString($bytes, $o, 8).Trim([char]0)
  if ($nm -eq '.text') { $textVa = [BitConverter]::ToInt32($bytes, $o + 12); $textRaw = [BitConverter]::ToInt32($bytes, $o + 20); break }
}
$latin = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
$rv = @{}
foreach ($k in $SIG.Keys) {
  $pat = ''
  for ($j = 0; $j -lt $SIG[$k].Length; $j += 2) { $pat += [char][Convert]::ToInt32($SIG[$k].Substring($j, 2), 16) }
  $idx = $latin.IndexOf($pat, [StringComparison]::Ordinal)
  if ($idx -lt 0) { "SIGMISS $k" | Add-Content $log; continue }
  $rv[$k] = $textVa + ($idx - $textRaw)
  ("SIG {0} fileoff=0x{1:X} rva=0x{2:X}" -f $k, $idx, $rv[$k]) | Add-Content $log
}
if ($rv.Count -lt 2) { 'ANCHOR_FAIL' | Add-Content $log; exit 1 }

# ---- page heap + WER dumps ----
$g = @('C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe') + @((Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Debuggers' -Recurse -Filter gflags.exe -EA SilentlyContinue | ForEach-Object FullName)) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($g) { & $g /p /enable POWERPNT.EXE /full | Out-Null } else { 'NO_GFLAGS' | Add-Content $log }
$gf = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\POWERPNT.EXE' -Name GlobalFlag -EA SilentlyContinue).GlobalFlag
"gflags_applied GlobalFlag=$gf" | Add-Content $log
$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows Error Reporting\LocalDumps\POWERPNT.EXE'
New-Item -Path $k -Force | Out-Null
New-ItemProperty -Path $k -Name DumpFolder -Value (Join-Path $base 'dumps') -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $k -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $k -Name DumpCount -Value 40 -PropertyType DWord -Force | Out-Null

$dumpsDir = Join-Path $base 'dumps'
$files = @(Get-ChildItem $Dir -File -Filter *.pptx | Sort-Object Name)
"cases=$($files.Count)" | Add-Content $log
foreach ($f in $files) {
  Set-Content -Path $f.FullName -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
  $modes = @('open')
  if ($Show) { $modes += 'show' }
  foreach ($m in $modes) {
    $cmdf = Join-Path $base ('out\' + $f.BaseName + '_' + $m + '.cdb')
    $c = @('.sympath()')
    $c += ".echo ====CASE $($f.BaseName) $m"
    foreach ($kk in @('FVAL', 'TVCTOR', 'DROP', 'ONT')) {
      if ($rv[$kk]) {
        $blk = if ($kk -eq 'FVAL' -or $kk -eq 'TVCTOR') { ('.echo {0}; r dl; g' -f $kk) } else { ('.echo {0}; g' -f $kk) }
        $c += ('bp ppcore+0x{0:X} "{1}"' -f $rv[$kk], $blk)
      }
    }
    $c += 'sxn av'
    $c += 'g'
    $c += '.echo ====EXC'
    $c += 'r'
    $c += 'k 20'
    $c += '.echo ====END'
    $c += 'q'
    Set-Content -LiteralPath $cmdf -Value $c -Encoding ASCII
    $before = @(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue | ForEach-Object Name)
    $t0 = Get-Date
    $stdout = Join-Path $base ('out\' + $f.BaseName + '_' + $m + '.log')
    $args = @('-cf', $cmdf, $pp)
    if ($m -eq 'show') { $args += '/s' }
    $args += ('"' + $f.FullName + '"')
    $p = Start-Process -FilePath $cdb -ArgumentList $args -PassThru -WindowStyle Hidden `
         -RedirectStandardOutput $stdout -RedirectStandardError ($stdout + '.err')
    $st = 'timeout'
    for ($i = 0; $i * 3 -lt $WaitSec; $i++) {
      Start-Sleep -Seconds 3
      if (-not (Get-Process -Id $p.Id -EA SilentlyContinue)) { $st = 'cdb-exited'; break }
    }
    Get-Process POWERPNT -EA SilentlyContinue | Where-Object { $_.StartTime -gt $t0.AddSeconds(-2) } | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep -Seconds 1
    Get-Process -Id $p.Id -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    $txt = ''
    if (Test-Path $stdout) { $txt = Get-Content $stdout -Raw }
    $cnt = @{}
    foreach ($kk in @('FVAL', 'TVCTOR', 'DROP', 'ONT')) { $cnt[$kk] = ([regex]::Matches($txt, "(?m)^$kk")).Count }
    $dl0 = ([regex]::Matches($txt, "(?m)^(FVAL|TVCTOR)\r?\ndl=00")).Count
    $av = ([regex]::Matches($txt, 'Access violation')).Count
    $newd = @(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue | Where-Object { $_.LastWriteTime -gt $t0 } | ForEach-Object { $_.Name })
    ('{0,-24} mode={1,-5} state={2,-11} FVAL={3} TVCTOR={4} DROP={5} ONT={6} dl0={7} av={8} dumps={9}' -f `
        $f.Name, $m, $st, $cnt['FVAL'], $cnt['TVCTOR'], $cnt['DROP'], $cnt['ONT'], $dl0, $av, ($newd -join ',')) | Add-Content $log
  }
}
if ($g) { & $g /p /disable POWERPNT.EXE | Out-Null }
$gf2 = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\POWERPNT.EXE' -Name GlobalFlag -EA SilentlyContinue).GlobalFlag
"gflags_disabled GlobalFlag=$gf2" | Add-Content $log
'dump_total=' + @(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue).Count | Add-Content $log
Get-Content $log
'ALLDONE'
