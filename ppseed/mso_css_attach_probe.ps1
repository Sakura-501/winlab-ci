# mso_css_attach_probe.ps1 - measure the CSS/classifier count sites inside a *running* Outlook or Word.
#
# Why attach instead of launch-under-debugger: the two product-path waves already proved the
# difference.  Without cdb, `Start-Process OUTLOOK.EXE <file>` yields `npp=1 modules=146
# titles=Microsoft Outlook` (the app really runs); with `cdb -o OUTLOOK.EXE <file>` every case reads
# `loaded=0 dead=1` - the launched process hands the document to another instance and exits before
# mso.dll is even mapped, so no anchor can bind.  Here the app is started first, its window is
# confirmed, cdb is attached to that live process, and only then is the carrier opened (ShellExecute
# of the file, i.e. the double-click path), so the open lands inside the debugged instance.
#
# Sites (20092 x64 mso.dll, all four signatures occur exactly once in the installed file):
#   FDS 0x3E95E8 ?FCommitDivSpanCore@ prologue        NEG 0x3E975A negative clamp      CPY 0x3E97D0 copy
#   CSSALLOC 0x7F92E5 (capacity = 2*(n+2))  CSSCOPY 0x7F930C (copy = 2*n, movsxd)  CSSRET 0x7F92CE
#   CSN  0x1E957  mso!FClassifyRgwch's own out-param store (shared by six consumers)
param([string]$Base = '.', [string]$CarrierDir = 'carriers_dc', [string]$App = 'OUTLOOK.EXE',
      [string]$Tag = 'attach', [int]$Limit = 16, [int]$CaseSeconds = 25)
$ErrorActionPreference = 'Continue'
$base = (Resolve-Path $Base).Path
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out'), (Join-Path $base 'dumps') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
function Say([string]$s) { ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $s) | Add-Content $log; $s }
function Count-Marker([string]$txt, [string]$pat) { return @([regex]::Matches($txt, $pat)).Count }

$msoCand = @(
  'C:\Program Files\Common Files\Microsoft Shared\Office16\mso.dll',
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso.dll')
$SIG = [ordered]@{
  FDS      = '4C894C2420488954241055535657415441554157488D6C24'
  NEG      = 'F7D98BD1483BD077E2482BC2'
  CPY      = '488D0C48E8????????8B45??018760020000'
  CSSALLOC = '8B45F883C0024863C84803C9'
  CSSCOPY  = '4C6345F84D03C0488D4802488B55F0E8'
  CSSRET   = '488B8FF0810000E8????????85C07507'
  CSN      = '4D2BEEB80000008049D1FDB9FFFFFFFF4903C5483BC10F876003000044896F18'
}
# offsets from the end of each signature to the instruction whose registers are interesting
$SIGOFF = @{ CSSALLOC = 12; CSSCOPY = 15; CSSRET = 12; CSN = 28 }
function Get-Anchors([string]$path, $table) {
  $out = @{}
  $bytes = [IO.File]::ReadAllBytes($path)
  $pe = [BitConverter]::ToInt32($bytes, 0x3C)
  $nsec = [BitConverter]::ToInt16($bytes, $pe + 6)
  $sh = $pe + 24 + [BitConverter]::ToInt16($bytes, $pe + 20)
  $tva = 0; $tpraw = 0
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $sh + $i * 40
    if ([Text.Encoding]::ASCII.GetString($bytes, $o, 8).Trim([char]0) -eq '.text') {
      $tva = [BitConverter]::ToInt32($bytes, $o + 12); $tpraw = [BitConverter]::ToInt32($bytes, $o + 20); break } }
  if (-not $tpraw) { return $out }
  $latin = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
  foreach ($k in $table.Keys) {
    $h = $table[$k]
    $bts = @(); for ($j = 0; $j -lt $h.Length; $j += 2) {
      $pair = $h.Substring($j, 2)
      if ($pair -eq '??') { $bts += -1 } else { $bts += [Convert]::ToInt32($pair, 16) } }
    $lit = ''
    foreach ($v in $bts) { if ($v -lt 0) { break }; $lit += [char]$v }
    $found = -1; $from = 0; $all = 0
    while ($true) {
      $c = $latin.IndexOf($lit, $from, [StringComparison]::Ordinal)
      if ($c -lt 0) { break }
      $ok = $true
      for ($m = 0; $m -lt $bts.Count; $m++) {
        if ($bts[$m] -ge 0 -and [int][byte]$latin[$c + $m] -ne $bts[$m]) { $ok = $false; break } }
      if ($ok) { $all++; if ($found -lt 0) { $found = $c } }
      $from = $c + 1 }
    if ($all -ne 1) { Say ("SIGX {0} occurrences={1}" -f $k, $all); continue }
    $out[$k] = $tva + ($found - $tpraw) + $(if ($SIGOFF.ContainsKey($k)) { $SIGOFF[$k] } else { 0 })
  }
  return $out
}
$rv = @{}; $msoFile = ''
foreach ($c in ($msoCand | Where-Object { Test-Path $_ })) {
  $it = Get-Item $c
  $r = Get-Anchors $c $SIG
  Say ("TRY {0} v={1} size={2} got={3}" -f $it.FullName, $it.VersionInfo.FileVersion, $it.Length, (($r.Keys | Sort-Object) -join ','))
  if ($r.Count -ge 4) { $rv = $r; $msoFile = $it.Name; break } }
if (-not $msoFile) { Say 'ANCHOR_FAIL'; exit 1 }
Say ("ANCHORS {0} {1}" -f $msoFile, ((($rv.Keys | Sort-Object) | ForEach-Object { $_ + '=0x' + ('{0:X}' -f $rv[$_]) }) -join ' '))

$cdb = $null
foreach ($p in @('C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe','C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe')) {
  if (Test-Path $p) { $cdb = $p; break } }
if (-not $cdb) {
  $h = Get-ChildItem 'C:\Program Files\WindowsApps' -Recurse -Filter cdb.exe -EA SilentlyContinue |
       Where-Object { $_.DirectoryName -match 'amd64|x64' } | Select-Object -First 1
  if ($h) { $cdb = $h.FullName } }
if (-not $cdb) { Say 'NO_CDB'; exit 1 }
$priv = 'C:\dsdbg'; New-Item -ItemType Directory -Force -Path $priv | Out-Null
Copy-Item $cdb (Join-Path $priv 'cdb.exe') -Force
Get-ChildItem (Split-Path $cdb) -Filter *.dll -EA SilentlyContinue | Copy-Item -Destination $priv -Force
$cdbExe = Join-Path $priv 'cdb.exe'

$exe0 = $App -replace '\.EXE$',''
$appPath = "C:\Program Files\Microsoft Office\root\Office16\$App"
if (-not (Test-Path $appPath)) { Say "APP_MISSING $appPath"; exit 1 }
$g = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Debuggers' -Recurse -Filter gflags.exe -EA SilentlyContinue |
     Where-Object { $_.DirectoryName -match '\\(x64|amd64)$' } | Select-Object -First 1
if ($g) { & $g.FullName /p /enable $App /full | Out-Null; Say "gflags /enable $App /full" }
$dumpsDir = Join-Path $base 'dumps'
$wer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
New-Item -Path $wer -Force | Out-Null
New-ItemProperty -Path $wer -Name DumpFolder -PropertyType ExpandString -Value $dumpsDir -Force | Out-Null
New-ItemProperty -Path $wer -Name DumpType -PropertyType DWord -Value 2 -Force | Out-Null
$env:PATH = 'C:\Program Files\Microsoft Office\root\Office16;' + $env:PATH

Get-Process $exe0 -EA SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }
Start-Sleep -Seconds 3
Get-Process $exe0 -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
$w = Start-Process -FilePath $appPath -PassThru -EA SilentlyContinue
$state = 'timeout'
for ($i = 0; $i -lt 25; $i++) {
  Start-Sleep -Seconds 3
  $t = (@(Get-Process $exe0 -EA SilentlyContinue | ForEach-Object { $_.MainWindowTitle }) -join ' | ')
  if ($t) { $state = 'window'; break } }
$pid0 = 0; $mods0 = 0
$p0 = @(Get-Process $exe0 -EA SilentlyContinue | Sort-Object StartTime | Select-Object -First 1)
if ($p0.Count) { $pid0 = $p0[0].Id; try { $mods0 = @($p0[0].Modules).Count } catch {} }
Say ("PRELAUNCH state={0} pid={1} modules={2} titles={3}" -f $state, $pid0, $mods0, `
     ((@(Get-Process $exe0 -EA SilentlyContinue | ForEach-Object { $_.MainWindowTitle }) -join ' | ')))
if (-not $pid0) { Say 'NO_APP_PROCESS'; exit 1 }

$cm = Join-Path $base ('out\cmds_' + $Tag + '.txt')
$tr = Join-Path $base ('out\trans_' + $Tag + '.txt')
$cmds = @()
$msoTok = 'mso'
foreach ($c in $msoCand) { if ((Test-Path $c) -and ((Get-Item $c).Length -gt 1MB) -and $rv.Count -ge 4) { $msoTok = (Get-Item $c).BaseName; break } }
if ($rv['CSSALLOC']) { $cmds += ('bp {0}+0x{1:X} "r $t0=@$t0+1; .printf \"A cap=%I64d\\n\", @rcx; g"' -f $msoTok, $rv['CSSALLOC']) }
if ($rv['CSSCOPY'])  { $cmds += ('bp {0}+0x{1:X} "r $t1=@$t1+1; .printf \"C copy=%I64d n=%x dst=%p\\n\", @r8, dword ptr [rbp-8], @rcx; g"' -f $msoTok, $rv['CSSCOPY']) }
if ($rv['CSSRET'])   { $cmds += ('bp {0}+0x{1:X} "r $t2=@$t2+1; .printf \"R ret=%x\\n\", @ax; g"' -f $msoTok, $rv['CSSRET']) }
if ($rv['CPY'])      { $cmds += ('bp {0}+0x{1:X} "r $t3=@$t3+1; .printf \"D copy=%I64d dst=%p dpo=%x\\n\", @r8, @rcx, (@rcx&0xfff); g"' -f $msoTok, $rv['CPY']) }
if ($rv['CSN'])      { $cmds += ('bp {0}+0x{1:X} "r $t4=@$t4+1; .printf \"N n=%x\\n\", @r13d; g"' -f $msoTok, $rv['CSN']) }
if ($rv['NEG'])      { $cmds += ('bp {0}+0x{1:X} "r $t5=@$t5+1; g"' -f $msoTok, $rv['NEG']) }
$cmds += 'bl'
$cmds += '.echo ====BREAKPOINTS_SET'
$cmds += 'g'
Set-Content -LiteralPath $cm -Value ($cmds -join "`n") -Encoding ascii
Say ("CMDSWritten lines={0}" -f $cmds.Count)

if (Test-Path $tr) { Remove-Item $tr -Force }
$cdbp = Start-Process -FilePath $cdbExe -ArgumentList @('-p', "$pid0", '-cf', $cm, '-T', 'attach') `
        -PassThru -WindowStyle Hidden -RedirectStandardError $tr -EA SilentlyContinue
$armed = $false
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Seconds 2
  $t0 = ''
  if (Test-Path $tr) { $t0 = Get-Content $tr -Raw -EA SilentlyContinue }
  if ($t0 -and $t0.IndexOf('====BREAKPOINTS_SET') -ge 0) { $armed = $true; break } }
Say ("ATTACH armed={0} cdb_alive={1} bl_lines={2}" -f $armed, `
     (@(Get-Process -Id $cdbp.Id -EA SilentlyContinue).Count), `
     $(if (Test-Path $tr) { @(Select-String -Path $tr -Pattern '^\s+\d+ [eu] ' -EA SilentlyContinue).Count } else { 0 }))

$files = @(Get-ChildItem (Join-Path $base $CarrierDir) -Filter *.eml -EA SilentlyContinue | Select-Object -First $Limit)
if (-not $files.Count) { $files = @(Get-ChildItem (Join-Path $base $CarrierDir) -Filter *.htm* -EA SilentlyContinue | Select-Object -First $Limit) }
Say ("CARRIERS={0} dir={1}" -f $files.Count, $CarrierDir)
$prev = 0
foreach ($f in $files) {
  # Mark-of-the-Web before the open, so the carrier arrives the way an internet-delivered file does.
  Set-Content -Path $f.FullName -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII -EA SilentlyContinue
  $streams = (@(Get-Item $f.FullName -Stream * -EA SilentlyContinue | ForEach-Object { $_.Stream }) -join ',')
  $before = 0
  if (Test-Path $tr) { $before = (Get-Item $tr).Length }
  $null = Start-Process -FilePath $f.FullName -PassThru -EA SilentlyContinue
  $titles = ''
  for ($i = 0; $i -lt [Math]::Max(1, [int]($CaseSeconds / 3)); $i++) {
    Start-Sleep -Seconds 3
    $txt = ''
    if (Test-Path $tr) { $txt = Get-Content $tr -Raw -EA SilentlyContinue }
    $titles = (@(Get-Process $exe0 -EA SilentlyContinue | ForEach-Object { $_.MainWindowTitle }) -join ' | ')
    if ($txt.Length -gt $before) { break } }
  $txt = ''
  if (Test-Path $tr) { $txt = Get-Content $tr -Raw -EA SilentlyContinue }
  $seg = ''
  if ($before -lt $txt.Length) { $seg = $txt.Substring($before) }
  Say ("CASE={0} streams={1} grew={2} A={3} C={4} R={5} D={6} N={7} AV2={8} titles={9}" -f `
       $f.Name, $streams, ($txt.Length - $before), (Count-Marker $seg '(?m)^A '), (Count-Marker $seg '(?m)^C '), `
       (Count-Marker $seg '(?m)^R '), (Count-Marker $seg '(?m)^D '), (Count-Marker $seg '(?m)^N '), `
       (Count-Marker $seg '(?m)^AV2'), $titles)
  foreach ($m in @([regex]::Matches($seg, '(?m)^C copy=(\-?\d+) n=([0-9a-fA-F]{1,8}) dst=(\S+)'))) {
    $n = [Convert]::ToUInt32($m.Groups[2].Value, 16)
    if ($n -gt 2147483647) { $n -= 4294967296 }
    Say ("  CPYROW copy={0} n={1} dst={2}" -f $m.Groups[1].Value, $n, $m.Groups[3].Value) }
  foreach ($m in @([regex]::Matches($seg, '(?m)^N n=([0-9a-fA-F]{1,8})'))) {
    $n = [Convert]::ToUInt32($m.Groups[1].Value, 16)
    if ($n -gt 2147483647) { $n -= 4294967296 }
    Say ("  NROW n={0}" -f $n) }
  foreach ($m in @([regex]::Matches($seg, '(?m)^D copy=(\-?\d+) dst=(\S+) dpo=([0-9a-fA-F]{1,3})'))) {
    Say ("  DROW copy={0} dst={1} dpo={2}" -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value) }
}
$dmp = @(Get-ChildItem $dumpsDir -Filter *.dmp -EA SilentlyContinue | Where-Object { $_.LastWriteTime -gt $w.StartTime })
Say ("DUMPS={0} names={1}" -f $dmp.Count, (($dmp | ForEach-Object { $_.Name }) -join ','))
$allTxt = ''
if (Test-Path $tr) { $allTxt = Get-Content $tr -Raw -EA SilentlyContinue }
Say ("TOTALS A={0} C={1} R={2} D={3} N={4} AV2={5}" -f (Count-Marker $allTxt '(?m)^A '), (Count-Marker $allTxt '(?m)^C '), `
     (Count-Marker $allTxt '(?m)^R '), (Count-Marker $allTxt '(?m)^D '), (Count-Marker $allTxt '(?m)^N '), (Count-Marker $allTxt '(?m)^AV2'))
Get-Process -Id $cdbp.Id -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Get-Process $exe0 -EA SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }
Say 'ALLDONE'
