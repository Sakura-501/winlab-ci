# mso_css_a64_vm_probe.ps1 - ARM64-view CSS anchors on the Windows on ARM test machine.
#
# Why the VM and not the runner: the runner's WINWORD never reached a titled window for these carriers
# (run 36399200281: every case `loaded=0 dead=1`, and its no-debugger control also `state=timeout
# titlematch=0`), while this machine runs the same build 16.0.20430.20092 with Word/Outlook windows proven
# by earlier waves.  The installed mso.dll here is the ARM64-primary view of the ARM64X package
# (45,794,072 B, sha256 gated below), whose `.text` is ARM64 code, so the anchors are the ARM64 twins of
# the x64 sites (STATE mso-html-import-20260923 SS111):
#   A6PROD 0x8EAE0 -> the classifier's `str w10, [x20, #0x18]` at +0x20 (the signed element count in x10)
#   A6ALLOC 0x8EE8C `add w8,w21,#2 ; sbfiz x0,x8,#1,#0x20 ; movz w1,#0 ; bl alloc` -> x0 = capacity bytes
#   A6COPY 0x8EEA8  `sbfiz x2,x21,#1,#0x20 ; mov x1,x22 ; add x0,x0,#2 ; bl memcpy` -> x2 = length bytes
# Each signature is unique in that file (verified on the archived copy: 1 hit for all four).
# Launch/teardown/screenshot mechanics are taken from findings/.../tools/wd_htm_cdb.ps1 (MOTW before open,
# Resiliency cleared, `/x` so the debugged instance owns the document, title match required before reading).
param([string]$CaseDir = 'C:\csspoc\c', [string]$LogDir = 'C:\csspoc\out',
      [string]$Master = 'C:\csspoc\out\master.txt', [int]$Tmo = 100, [int]$Cap = 8, [int]$First = 0,
      [string]$App = 'WINWORD.EXE', [string]$ExtraArgs = '/x', [string]$Ext = '.htm')
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
New-Item -ItemType Directory -Force -Path $LogDir, (Join-Path $LogDir 'shots') | Out-Null
$want = '3a934b9393e1e407987422eb73ef664a9e2fdc61598d43600ec5ee620b145c46'
$off = 'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\MSO.DLL'
if (-not (Test-Path $off)) { 'MSO_MISSING ' + $off | Set-Content $Master; exit 1 }
$have = (Get-FileHash -LiteralPath $off -Algorithm SHA256).Hash.ToLower()
$ver = (Get-Item $off).VersionInfo.FileVersion
("START {0:HH:mm:ss} app={1} mso={2} ver={3} sha_ok={4} session={5} case={6} tmo={7} cap={8}" -f `
  (Get-Date), $App, $off, $ver, ($have -eq $want), (Get-Process -Id $PID).SessionId, $CaseDir, $Tmo, $Cap) | Set-Content $Master -Encoding UTF8
if ($have -ne $want) { 'SHA_GATE_FAIL ' + $have | Add-Content $Master; exit 1 }

$SIG = [ordered]@{ A6PROD = 'E81B40F9680208CB0AFD41930800B0D24901088B'
                   A6ALLOC = 'A80A0011007D7F9301008052'; A6COPY = 'A27E7F93E10316AA00080091' }
$SIGOFF = @{ A6PROD = 0x20; A6ALLOC = 0; A6COPY = 0 }
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
      $tva = [BitConverter]::ToInt32($bytes, $o + 12); $tpraw = [BitConverter]::ToInt32($bytes, $o + 20); break } }
  if (-not $tpraw) { return $out }
  $latin = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
  foreach ($k in $table.Keys) {
    $h = $table[$k]
    $bts = @(); for ($j = 0; $j -lt $h.Length; $j += 2) { $bts += [Convert]::ToInt32($h.Substring($j, 2), 16) }
    $lit = ''
    foreach ($v in $bts) { $lit += [char]$v }
    $all = @(); $from = 0
    while ($true) {
      $c = $latin.IndexOf($lit, $from, [StringComparison]::Ordinal)
      if ($c -lt 0) { break }
      $all += $c; $from = $c + 1 }
    if (-not $all.Count) { continue }
    $out[$k] = ($tva + (($all | Select-Object -First 1) - $tpraw)) + $SIGOFF[$k]
    $out[$k + '_N'] = $all.Count }
  return $out
}
$rv = Get-Anchors $off $SIG
('ANCHORS prod={0} alloc={1} copy={2} n={3}/{4}/{5}' -f $rv['A6PROD'], $rv['A6ALLOC'], $rv['A6COPY'],
  $rv['A6PROD_N'], $rv['A6ALLOC_N'], $rv['A6COPY_N']) | Add-Content $Master
if (-not ($rv['A6PROD'] -and $rv['A6ALLOC'] -and $rv['A6COPY'])) { 'ANCHOR_FAIL' | Add-Content $Master; exit 1 }

$cdb = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\cdb.exe'
if (-not (Test-Path $cdb)) { 'NO_CDB' | Add-Content $Master; exit 1 }
$appPath = Join-Path 'C:\Program Files\Microsoft Office\root\Office16' $App
if (-not (Test-Path $appPath)) { 'NO_APP ' + $appPath | Add-Content $Master; exit 1 }

$all = @(Get-ChildItem -LiteralPath $CaseDir -File | Where-Object { $_.Extension -eq $Ext } | Sort-Object Name)
$files = $all | Select-Object -Skip $First -First $Cap
('found={0} cases={1}' -f $all.Count, $files.Count) | Add-Content $Master
if (-not $files.Count) { 'NO_CARRIERS' | Add-Content $Master; exit 1 }
$pre = @(Get-Process ($App.Split('.')[0]) -EA SilentlyContinue | ForEach-Object { $_.Id })

foreach ($f in $files) {
  $name = $f.BaseName
  Get-Process ($App.Split('.')[0]) -EA SilentlyContinue | Where-Object { $pre -notcontains $_.Id } | Stop-Process -Force -EA SilentlyContinue
  Remove-Item 'HKCU:\SOFTWARE\Microsoft\Office\16.0\word\Resiliency' -Recurse -Force -EA SilentlyContinue
  Start-Sleep -Milliseconds 400
  Set-Content -LiteralPath $f.FullName -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
  $streams = (@(Get-Item -LiteralPath $f.FullName -Stream * | ForEach-Object { $_.Stream })) -join ','
  $cmdf = Join-Path $LogDir ($name + '.cdb')
  $avh = 'sxd av ".echo AV2; r pc; k 14; .dump /ma ' + (Join-Path $LogDir ('dump_' + $name + '.dmp')) + '; g"'
  $c = @('.sympath()', 'sxn e06d7363', 'sxn e0434352', 'sxn c00000fd', 'sxn 80000003', $avh,
         'sxe ld:mso.dll', '.echo ====MSO_LOADED', 'g', '.echo ====WAIT', '? mso', 'lm m mso',
         'u mso+0x{0:X} L4' -f $rv['A6PROD'], 'u mso+0x{0:X} L4' -f $rv['A6ALLOC'], 'u mso+0x{0:X} L4' -f $rv['A6COPY'],
         ('bp /c 800 mso+0x{0:X} "r $t0=@$t0+1; .echo A6PD; r x10 x20; g"' -f $rv['A6PROD']),
         ('bp /c 800 mso+0x{0:X} "r $t1=@$t1+1; .echo A6AL; r x0 x21; g"' -f $rv['A6ALLOC']),
         ('bp /c 800 mso+0x{0:X} "r $t2=@$t2+1; .echo A6CP; r x2 x0 x1; g"' -f $rv['A6COPY']),
         'bl', '.echo ====BP_SET')
  for ($i = 0; $i -lt 200; $i++) { $c += '.echo ====STOP'; $c += 'g' }
  $c += '.printf "COUNTERS pd=%d al=%d cp=%d\n", @$t0, @$t1, @$t2'
  $c += 'q'
  Set-Content -LiteralPath $cmdf -Value ($c -join "`n") -Encoding ASCII
  $argl = @('-cf', $cmdf, ('"' + $appPath + '"'))
  if ($ExtraArgs) { $argl += $ExtraArgs }
  $argl += ('"' + $f.FullName + '"')
  $cp = Start-Process -FilePath $cdb -ArgumentList $argl -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $LogDir ($name + '.stdout.txt')) -RedirectStandardError (Join-Path $LogDir ($name + '.stderr.txt'))
  $t0 = Get-Date; $opened = 0; $title = ''; $last = ''; $av = 0; $secs = 0
  while (((Get-Date) - $t0).TotalSeconds -lt $Tmo) {
    Start-Sleep -Milliseconds 1500
    $secs = [int]((Get-Date) - $t0).TotalSeconds
    $txt = ''
    $sp = Join-Path $LogDir ($name + '.stdout.txt')
    if (Test-Path -LiteralPath $sp) { $txt = Get-Content -LiteralPath $sp -Raw }
    $av = ([regex]::Matches($txt, '(?m)^AV2')).Count
    $le = [regex]::Matches($txt, 'Last event: ([^\r\n]+)')
    if ($le.Count) { $last = $le[$le.Count - 1].Groups[1].Value.Trim() }
    $tt = @(Get-Process ($App.Split('.')[0]) -EA SilentlyContinue | Where-Object { $pre -notcontains $_.Id } | ForEach-Object { $_.MainWindowTitle } | Where-Object { $_ })
    $title = ($tt | Where-Object { $_ -like ('*' + $f.BaseName + '*') }) | Select-Object -First 1
    if ($title) {
      $opened = 1
      try {
        Add-Type -AssemblyName System.Windows.Forms, System.Drawing
        $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
        $g = [System.Windows.Forms.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.X, $b.Y, 0, 0, $bmp.Size)
        $bmp.Save((Join-Path $LogDir ('shots\' + $name + '.png'))); $g.Dispose(); $bmp.Dispose()
      } catch { }
      break }
    if ($av -gt 0) { break }
    if ($last -match 'Exit process') { break }
    if (-not (Get-Process -Id $cp.Id -EA SilentlyContinue)) { break }
  }
  $txt = ''
  $sp = Join-Path $LogDir ($name + '.stdout.txt')
  if (Test-Path -LiteralPath $sp) { $txt = Get-Content -LiteralPath $sp -Raw }
  $cn = [regex]::Match($txt, 'COUNTERS pd=(\d+) al=(\d+) cp=(\d+)')
  $npd = 0; $nal = 0; $ncp = 0
  if ($cn.Success) { $npd = [int]$cn.Groups[1].Value; $nal = [int]$cn.Groups[2].Value; $ncp = [int]$cn.Groups[3].Value }
  # the value of the signed count comes from the A6PD stops; negatives are computed here, not in cdb
  $pdv = @([regex]::Matches($txt, '(?m)^A6PD\r?\nx10=([0-9a-fA-F]{8})') | ForEach-Object { [Convert]::ToUInt32($_.Groups[1].Value, 16) })
  $pmin = 0; $pneg = 0; $pm1 = 0
  if ($pdv.Count) {
    $sv = @($pdv | ForEach-Object { if ($_ -gt 0x7FFFFFFF) { [int64]$_ - 4294967296 } else { [int64]$_ } })
    $pmin = ($sv | Measure-Object -Minimum).Minimum
    $pneg = @($sv | Where-Object { $_ -lt 0 }).Count
    $pm1 = @($sv | Where-Object { $_ -eq -1 }).Count }
  $alv = @([regex]::Matches($txt, '(?m)^A6AL\r?\nx0=([0-9a-fA-F]{16})') | ForEach-Object { [Convert]::ToUInt64($_.Groups[1].Value, 16) })
  $cpv = @([regex]::Matches($txt, '(?m)^A6CP\r?\nx2=([0-9a-fA-F]{16})') | ForEach-Object { [Convert]::ToUInt64($_.Groups[1].Value, 16) })
  $npair = [Math]::Min($alv.Count, $cpv.Count); $nover = 0; $ntop = 0; $worst = [int64]0
  for ($q = 0; $q -lt $npair; $q++) {
    if ($cpv[$q] -ge 0x8000000000000000) { $ntop++ }
    if ($cpv[$q] -gt $alv[$q]) { $nover++; $dd = [int64]($cpv[$q] - $alv[$q]); if ($dd -gt $worst) { $worst = $dd } } }
  $loaded = ([regex]::Match($txt, '(?m)^====MSO_LOADED')).Success
  $bpset = ([regex]::Match($txt, '(?m)^====BP_SET')).Success
  $stops = @([regex]::Matches($txt, '(?m)^====STOP')).Count
  $dead = @([regex]::Matches($txt, 'No runnable debuggees')).Count
  $unres = @([regex]::Matches($txt, 'could not be resolved')).Count
  $dmp = @(Get-ChildItem $LogDir -Filter ('dump_' + $name + '*.dmp') -EA SilentlyContinue).Count
  $alSamp = (($alv | Select-Object -First 6 | ForEach-Object { '0x{0:X}' -f $_ }) -join ',')
  $cpSamp = (($cpv | Select-Object -First 6 | ForEach-Object { '0x{0:X}' -f $_ }) -join ',')
  $pdSamp = (($pdv | Select-Object -First 10 | ForEach-Object { '0x{0:X}' -f $_ }) -join ',')
  ('CASE={0} size={1} streams={2} secs={3} opened={4} titlematch={5} loaded={6} bpset={7} stops={8} dead={9} unres={10} av2={11} dumps={12} pd={13} al={14} cp={15} pairs={16} copy_gt_alloc={17} copy_topbit={18} worst_excess={19} pd_neg={20} pd_minus1={21} pd_min={22} lastevent={23} title={24}' -f `
    $f.Name, $f.Length, $streams, $secs, $opened, [bool]$title, $loaded, $bpset, $stops, $dead, $unres, $av, $dmp, `
    $npd, $nal, $ncp, $npair, $nover, $ntop, $worst, $pneg, $pm1, $pmin, $last, $title) | Add-Content $Master
  ('SAMPLE case={0} pd={1} al={2} cp={3}' -f $f.Name, $pdSamp, $alSamp, $cpSamp) | Add-Content $Master
  $u = (($txt -split "`n" | Where-Object { $_ -match '^\s*[0-9a-f]{8}`[0-9a-f]{4}\s+[a-z]' }) -join ' // ')
  if ($u.Length -gt 500) { $u = $u.Substring(0, 500) }
  ('ANCHOR_DISASM case={0} {1}' -f $f.Name, $u) | Add-Content $Master
  Get-Process ($App.Split('.')[0]) -EA SilentlyContinue | Where-Object { $pre -notcontains $_.Id } | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep -Milliseconds 400
  Get-Process -Id $cp.Id -ErrorAction SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
}
('SUMMARY cases={0} opened={1} av={2} dumps={3}' -f $files.Count,
  (@(Get-Content -LiteralPath $Master | Select-String 'opened=1')).Count,
  (@(Get-Content -LiteralPath $Master | Select-String 'av2=[1-9]')).Count,
  (@(Get-ChildItem $LogDir -Filter 'dump_*.dmp' -EA SilentlyContinue)).Count) | Add-Content $Master
'DONE' | Add-Content $Master
