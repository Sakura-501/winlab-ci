# mso_divspan_anchor.ps1 - measure the mso div/span commit length path with the *in-process*
# importer harness (gbx.exe msohtml), so coverage does not depend on an Office UI instance.
#
# Anchors are resolved from the installed mso.dll by code signature (no PDB, no symbol server).
#   FDS  ?FCommitDivSpanCore@ prologue        -- every div/span commit
#   NEG  the `neg ecx / mov edx,ecx / cmp rdx,rax / ja / sub rax,rdx` block
#                                            -- commits whose fetched count came out negative
#   CPY  `lea rcx,[rax+rcx*2] ; call memcpy`  -- the copy actually issued, r8 = 2*count
# Positive control for the anchors themselves: FDS>0 while the harness reports handle=>0.
param([string]$Base = '.', [string]$Corpus = 'corpus\html.txt', [string]$Records = '946',
      [string]$Tag = 'dsanchor', [string]$FlagValues = '0x20001D1,0x0,0x804,0x1000000',
      [int]$Stops = 700)
$ErrorActionPreference = 'Continue'
$base = (Resolve-Path $Base).Path
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out'), (Join-Path $base 'dumps') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
function Say([string]$s) { ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $s) | Add-Content $log; $s }

# ---- mso.dll location (same candidate set as mso_html_len_probe.ps1) ----
$msoCand = @(
  'C:\Program Files\Common Files\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso.dll')
$mso = $null
foreach ($c in $msoCand) { $t = Get-Item $c -EA SilentlyContinue; if ($t) { $mso = $t; break } }
if (-not $mso) {
  $mso = Get-ChildItem 'C:\Program Files\Microsoft Office\root' -Recurse -Filter 'mso.dll' -EA SilentlyContinue |
         Sort-Object Length -Descending | Select-Object -First 1
}
if (-not $mso) { Say 'MSO_NOT_FOUND'; exit 1 }
Say ("START mso={0} size={1} path={2}" -f $mso.VersionInfo.FileVersion, $mso.Length, $mso.FullName)

$SIG = [ordered]@{
  FDS = '4C894C2420488954241055535657415441554157488D6C24'
  NEG = 'F7D98BD1483BD077E2482BC2'
  CPY = '488D0C48E8????????8B45??018760020000'
}
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
    while ($true) {
      $c = $latin.IndexOf($lit, $from, [StringComparison]::Ordinal)
      if ($c -lt 0) { break }
      $ok = $true
      for ($m = 0; $m -lt $bts.Count; $m++) {
        if ($bts[$m] -ge 0 -and [int][byte]$latin[$c + $m] -ne $bts[$m]) { $ok = $false; break } }
      if ($ok) { $idx = $c; break }
      $from = $c + 1
    }
    if ($idx -lt 0) { continue }
    $out[$k] = ($tva + ($idx - $tpraw))
  }
  return $out
}
$rv = Get-Anchors $mso.FullName $SIG
foreach ($k in $SIG.Keys) { if ($rv[$k]) { Say ("SIG {0} rva=0x{1:X}" -f $k, $rv[$k]) } else { Say ("SIG {0} MISSING" -f $k) } }
foreach ($q in @('FDS','NEG','CPY')) { if (-not $rv[$q]) { Say "ANCHOR_$q`_MISSING"; exit 1 } }

# ---- cdb ----
$cdb = $null
foreach ($c in @('C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe','C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe')) {
  if (Test-Path $c) { $cdb = $c; break } }
if (-not $cdb) {
  $h = Get-ChildItem 'C:\Program Files\WindowsApps' -Recurse -Filter cdb.exe -EA SilentlyContinue |
       Where-Object { $_.DirectoryName -match 'amd64|x64' } | Select-Object -First 1
  if ($h) { $cdb = $h.FullName } }
if (-not $cdb) {
  winget install Microsoft.WinDbg --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-Null
  $h = Get-ChildItem 'C:\Program Files\WindowsApps' -Recurse -Filter cdb.exe -EA SilentlyContinue |
       Where-Object { $_.DirectoryName -match 'amd64|x64' } | Select-Object -First 1
  if ($h) { $cdb = $h.FullName } }
if (-not $cdb) { Say 'NO_CDB'; exit 1 }
Say "cdb=$cdb"
$priv = 'C:\dsdbg'; New-Item -ItemType Directory -Force -Path $priv | Out-Null
Copy-Item $cdb (Join-Path $priv 'cdb.exe') -Force
Get-ChildItem (Split-Path $cdb) -Filter *.dll -EA SilentlyContinue | Copy-Item -Destination $priv -Force
$cdbExe = Join-Path $priv 'cdb.exe'

# ---- IFEO page heap for the harness (gflags is used when present, registry otherwise) ----
$g = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Debuggers' -Recurse -Filter gflags.exe -EA SilentlyContinue |
     Where-Object { $_.DirectoryName -match '\\(x64|amd64)$' } | Select-Object -First 1
if ($g) { & $g.FullName /p /enable gbx.exe /full | Out-Null; Say "gflags=$($g.FullName) /enable gbx.exe /full" }
else {
  $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\gbx.exe'
  New-Item -Path $ifeo -Force | Out-Null
  New-ItemProperty -Path $ifeo -Name GlobalFlag -PropertyType DWord -Value 0x02000000 -Force | Out-Null
  New-ItemProperty -Path $ifeo -Name PageHeapFlags -PropertyType DWord -Value 3 -Force | Out-Null
  Say 'gflags missing, IFEO keys written directly'
}

# ---- selftest that the arming actually faults (harness mode-free check via the shim's own line) ----
$env:PATH = 'C:\Program Files\Microsoft Office\root\Office16;' + $env:PATH
$gbx = Join-Path $base 'bin\gbx.exe'
if (-not (Test-Path $gbx)) { Say "GBX_MISSING $gbx"; exit 1 }
$probe = & $gbx msohtml $Corpus 3 0 none norel noskip slot=17 2>&1 | Out-String
$armedLine = (($probe -split "`n" | Where-Object { $_ -match 'ARM |pageheap_bit|verifier_dll' }) -join ' / ').Trim()
Say "PREARM_PROBE $armedLine"
if ($probe -notmatch 'handle=([1-9])') { Say 'PREARM_NO_CALLBACKS (instrument would be blind)' }

$vals = @($FlagValues.Split(',') | ForEach-Object { $_.Trim() })
foreach ($v in $vals) {
  $cm = Join-Path $base ('out\cmds_' + $Tag + '_' + ($v -replace '[^0-9a-fA-F]','') + '.txt')
  $tr = Join-Path $base ('out\trans_' + $Tag + '_' + ($v -replace '[^0-9a-fA-F]','') + '.txt')
  $c = @()
  $c += 'sxd av ".echo AV2;r ip; k 12; .dump /ma C:\dsdbg\dav.dmp;g"'
  $c += ('bu mso+0x{0:X} ".echo FDS;g"' -f $rv['FDS'])
  $c += ('bu mso+0x{0:X} ".echo NEG;r r8 rax rcx rdx;g"' -f $rv['NEG'])
  $c += ('bu mso+0x{0:X} ".echo CPY;r r8 rcx rdx;g"' -f $rv['CPY'])
  $c += '.echo ====LOADED'
  for ($i = 0; $i -lt $Stops; $i++) { $c += '.echo ====STOP'; $c += 'g' }
  Set-Content -Path $cm -Value ($c -join "`n") -Encoding ascii
  $env:GBFLAGS = $v
  $p = Start-Process -FilePath $cdbExe -ArgumentList @('-cf', $cm, '-o', $gbx, 'msohtml', (Join-Path $base $Corpus),
                    $Records, '0', 'none', 'norel', 'noskip', 'slot=17') -NoNewWindow -PassThru -RedirectStandardOutput $tr
  $p.WaitForExit()
  $txt = Get-Content $tr -Raw -EA SilentlyContinue
  if (-not $txt) { $txt = '' }
  $fds = ([regex]::Matches($txt, '(?m)^FDS')).Count
  $neg = ([regex]::Matches($txt, '(?m)^NEG')).Count
  $cpy = ([regex]::Matches($txt, '(?m)^CPY')).Count
  $r8s = @([regex]::Matches($txt, '(?m)^r8=([0-9a-fA-F]{16})') | ForEach-Object { $_.Groups[1].Value })
  $giant = @($r8s | Where-Object { $_ -like 'ffff*' })
  $av2 = ([regex]::Matches($txt, '(?m)^AV2')).Count
  $hand = ([regex]::Match($txt, 'handle=(\d+)')).Groups[1].Value
  $recs = ([regex]::Match($txt, 'recs=(\d+)')).Groups[1].Value
  $faultline = (($txt -split "`n" | Where-Object { $_ -match 'MSOHTML faults|MSOHTML totals|\[g\] AV-' }) -join ' | ')
  Say ("ARM={0} fds={1} neg={2} cpy={3} r8_captured={4} r8_ffff={5} av2={6} handle={7} recs={8}" -f `
        $v, $fds, $neg, $cpy, $r8s.Count, $giant.Count, $av2, $hand, $recs)
  Say ("ARM={0} faultlines={1}" -f $v, $faultline.Substring(0, [Math]::Min(700, $faultline.Length)))
  if ($r8s.Count) {
    $top = ($r8s | Group-Object | Sort-Object Count -Descending | Select-Object -First 6 |
            ForEach-Object { $_.Name + 'x' + $_.Count }) -join ' '
    Say ("ARM={0} r8_top={1}" -f $v, $top)
  }
  ($r8s | Where-Object { $_ -like 'ffff*' } | Select-Object -First 5) | ForEach-Object { Say ("ARM={0} GIANT_r8={1}" -f $v, $_) }
}
Say 'ALLDONE'
