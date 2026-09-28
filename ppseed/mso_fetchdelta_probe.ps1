# mso_fetchdelta_probe.ps1 - measure the *domain* of the count that PwchFetchToIhtks hands to the mso
# div/span committer, using the in-process importer harness (gbx.exe msohtml).
#
# Why this site instead of only the consumer anchors: the committer's copy length is
#   movsxd r8, dword ptr [<count slot>] ; add r8,r8   -> 2*(int64)(int32)count
# while its allocation branch clamps |count| first (STATE SS92/SS93). The value itself is produced in
# Mso98win32client.dll by
#   48 2B 4B 40   sub  rcx, qword ptr [rbx+0x38]      ; rcx = [LBS+0x38] - [LBS+0x40]   (end - cursor)
#   48 D1 F9      sar  rcx, 1                          ; sign-preserving /2  -> the character count
#   89 7D B8      mov  dword ptr [rbp-0x48], edi
#   E8 ?? ?? ??   call SafeCastHelper<int,__int64,3>::CastThrow   ; int32 range only, not sign
# The window guard just before it bounds the *cursor* against [LBS+0x28] (cache start), while the
# subtraction uses [LBS+0x38] (data end), so the pair is not the same quantity. This script breaks on
# the `sar` (rcx still holds the raw byte difference) and counts how often that difference is negative.
#
# Anchor is a byte signature with a wild call displacement, so it survives servicing drift; the 14 fixed
# bytes were measured unique inside Mso98win32client.dll (1 hit) and absent from mso/GFX/wwlib.
param([string]$Base = '.', [string]$Corpus = 'corpus\html.txt', [string]$Records = '946',
      [string]$Tag = 'fdprobe', [string]$FlagValues = '0x20001D1',
      [string]$Slots = '17', [int]$Stops = 700, [int]$SampleFirst = 6)
$ErrorActionPreference = 'Continue'
$base = (Resolve-Path $Base).Path
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out'), (Join-Path $base 'dumps') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
function Say([string]$s) { ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $s) | Add-Content $log; $s }

$hostCand = @(
  'C:\Program Files\Microsoft Office\root\Office16\Mso98win32client.dll',
  'C:\Program Files\Common Files\Microsoft Shared\Office16\Mso98win32client.dll',
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\Mso98win32client.dll')
# pattern starts at the `sub`; the breakpoint belongs on the following `sar rcx,1` (+4 bytes)
$SIG = [ordered]@{ DELTA = '482B4B4048D1F9897DB8E8????????' }
# +4 = the `sar rcx,1` (rcx still holds the raw byte difference); +13 = the CastThrow call site
# (rcx already holds the character count that is stored through the caller's int*, i.e. the value the
# committer later doubles for memcpy).
$SIGOFF = @{ DELTA = 4 }
$DUMPOFF = 10
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
$rv = @{}; $modFile = ''; $modTok = ''
foreach ($h in ($hostCand | Where-Object { Test-Path $_ })) {
  $r = Get-Anchors $h $SIG
  $it = Get-Item $h
  $have = 0; if ($r['DELTA']) { $have = 1 }
  Say ("TRY {0} v={1} size={2} hits={3}/1 delta=0x{4:X} n={5} all={6}" -f $it.Name, $it.VersionInfo.FileVersion, `
        $it.Length, $have, $r['DELTA'], $r['DELTA_N'], $r['DELTA_ALL'])
  if ($have -eq 1) { $rv = $r; $modFile = $it.Name; $modTok = $it.BaseName; break }
}
if (-not $modTok) { Say 'ANCHOR_FAIL_NO_HOST'; exit 1 }
Say ("HOST selected: {0} token={1} DELTA=0x{2:X} (signature hits in file={3})" -f $modFile, $modTok, $rv['DELTA'], $rv['DELTA_N'])

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

$g = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\Debuggers' -Recurse -Filter gflags.exe -EA SilentlyContinue |
     Where-Object { $_.DirectoryName -match '\\(x64|amd64)$' } | Select-Object -First 1
if ($g) { & $g.FullName /p /enable gbx.exe /full | Out-Null; Say "gflags=$($g.FullName) /enable gbx.exe /full" }
else {
  $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\gbx.exe'
  New-Item -Path $ifeo -Force | Out-Null
  New-ItemProperty -Path $ifeo -Name GlobalFlag -PropertyType DWord -Value 0x02000000 -Force | Out-Null
  New-ItemProperty -Path $ifeo -Name PageHeapFlags -PropertyType DWord -Value 3 -Force | Out-Null
  Say 'gflags missing, IFEO written directly'
}
$env:PATH = 'C:\Program Files\Microsoft Office\root\Office16;' + $env:PATH
$gbx = Join-Path $base 'bin\gbx.exe'
if (-not (Test-Path $gbx)) { Say "GBX_MISSING $gbx"; exit 1 }
$probe = & $gbx msohtml $Corpus 3 0 none norel noskip slot=17 2>&1 | Out-String
Say ("PREARM_PROBE {0}" -f (($probe -split "`n" | Where-Object { $_ -match 'ARM |MSOHTML totals|handle=' }) -join ' / ').Trim())

$vals = @($FlagValues.Split(',') | ForEach-Object { $_.Trim() })
$slotL = @($Slots.Split(',') | ForEach-Object { $_.Trim() })
foreach ($v in $vals) {
foreach ($sl in $slotL) {
  $suffix = ($v -replace '[^0-9a-fA-F]','') + '_s' + $sl
  $cm = Join-Path $base ('out\cmds_' + $Tag + '_' + $suffix + '.txt')
  $tr = Join-Path $base ('out\trans_' + $Tag + '_' + $suffix + '.txt')
  $tmpl = @'
sxd av ".echo AV2;r;k 14;.dump /ma C:\dsdbg\fd_av.dmp;g"
sxe ld:<MODFILE>
.echo ====WAITLOAD
g
.echo ====LOADED_STOP
? <MODTOK>
lm m <MODTOK>
u <MODTOK>+0x<DELTA> L4
bp <MODTOK>+0x<DELTA> "r $t0=@$t0+1; .echo DLTX; r rcx; dq @rbx+0x28 L4; g"
bl
.echo ====BREAKPOINTS_SET
STOPS
.printf "COUNTERS calls=%d\n", @$t0
q
'@
  $body = $tmpl.Replace('<DELTA>', ('{0:X}' -f $rv['DELTA'])).Replace('<MODFILE>', $modFile).Replace('<MODTOK>', $modTok)
  $body = $body.Replace('<DUMP>', ('{0:X}' -f ($rv['DELTA'] + $DUMPOFF - 4)))
  $ladder = @()
  for ($i = 0; $i -lt $Stops; $i++) { $ladder += '.echo ====STOP'; $ladder += 'g' }
  $c2 = @()
  foreach ($ln in @($body -split "`n")) {
    if ($ln.Trim() -eq 'STOPS') { $c2 += $ladder } else { $c2 += ($ln -replace "`r",'') } }
  Set-Content -Path $cm -Value ($c2 -join "`n") -Encoding ascii
  $env:GBFLAGS = $v
  $p = Start-Process -FilePath $cdbExe -ArgumentList @('-cf', $cm, '-o', $gbx, 'msohtml', (Join-Path $base $Corpus),
                    $Records, '0', 'none', 'norel', 'noskip', ('slot=' + $sl)) -NoNewWindow -PassThru -RedirectStandardOutput $tr
  $p.WaitForExit()
  $txt = ''
  if (Test-Path $tr) { $txt = Get-Content $tr -Raw -EA SilentlyContinue }
  if (-not $txt) { $txt = '' }
  $cnt = [regex]::Match($txt, 'COUNTERS calls=(\d+)')
  $ccalls = $cnt.Groups[1].Value
  # every hit's rcx is in the transcript (the debugger prints the register; the sign/zero/min are
  # computed here so nothing depends on cdb expression syntax inside a breakpoint command).
  # only the rcx line that follows a DLTX marker belongs to the delta site
  $rx = @([regex]::Matches($txt, '(?m)^DLTX\r?\nrcx=([0-9a-fA-F]{16})') | ForEach-Object { [Convert]::ToUInt64($_.Groups[1].Value, 16) })
  $cneg = 0; $czero = 0; $cmin = 'na'
  foreach ($u in $rx) {
    if ($u -ge 0x8000000000000000) { $cneg++ }
    if ($u -eq 0) { $czero++ }
    $signed = if ($u -ge 0x8000000000000000) { [int64]($u - [uint64]::MaxValue - 1) } else { [int64]$u }
    if ($cmin -eq 'na' -or $signed -lt [int64]$cmin) { $cmin = $signed }
  }
  $cdump = $rx.Count
  # LBS field window at the same stop: +0x28 (window-limit field the guard reads), +0x30, +0x38 (the position
  # the subtraction uses), +0x40 (the end of data). `dq` prints two qwords per line with the address first, so
  # the five/ six backtick tokens after each rcx= line are read positionally.
  $blocks = @([regex]::Matches($txt, '(?m)^DLTX\r?\nrcx=([0-9a-fA-F]{16})((?:\r?\n[^\r\n]*){0,2})'))
  $npos = 0; $posgt = 0; $maxpast = [int64]0; $gapmin = [int64]0x7FFFFFFFFFFFFFFF
  foreach ($m in $blocks) {
    $toks = @([regex]::Matches($m.Groups[2].Value, '([0-9a-fA-F]{8})`([0-9a-fA-F]{8})') | ForEach-Object { [Convert]::ToUInt64($_.Groups[1].Value + $_.Groups[2].Value, 16) })
    if ($toks.Count -lt 5) { continue }
    $pos = $toks[3]; $endv = $toks[4]; $limitf = $toks[0]
    $npos++
    if ($pos -gt $endv) { $posgt++; $past = [int64]($pos - $endv); if ($past -gt $maxpast) { $maxpast = $past } }
    $g = [int64]($endv - $pos)
    if ($g -lt $gapmin) { $gapmin = $g }
  }
  if ($gapmin -eq 0x7FFFFFFFFFFFFFFF) { $gapmin = -1 }
  $negLines = @([regex]::Matches($txt, '(?m)^NEGDELTA')).Count
  $sampLines = @([regex]::Matches($txt, '(?m)^SAMPLE')).Count
  $av2 = @([regex]::Matches($txt, '(?m)^AV2')).Count
  $rcxs = @([regex]::Matches($txt, '(?m)^rcx=([0-9a-fA-F]{16})') | ForEach-Object { $_.Groups[1].Value })
  $negr8 = @($rcxs | Where-Object { $_ -like '8*' -or $_ -like '9*' -or $_ -like 'a*' -or $_ -like 'b*' -or $_ -like 'c*' -or $_ -like 'd*' -or $_ -like 'e*' -or $_ -like 'f*' })
  $loaded = ([regex]::Match($txt, '(?m)^====LOADED_STOP')).Success
  $bpset = ([regex]::Match($txt, '(?m)^====BREAKPOINTS_SET')).Success
  $unres = @([regex]::Matches($txt, 'could not be resolved')).Count
  $blTxt = (($txt -split "`n" | Where-Object { $_ -match '^\s+\d+ [eu]' }) -join ' // ').Trim()
  if ($blTxt.Length -gt 700) { $blTxt = $blTxt.Substring(0,700) }
  $uTxt = (($txt -split "`n" | Where-Object { $_ -match '^00000' }) -join ' // ').Trim()
  if ($uTxt.Length -gt 600) { $uTxt = $uTxt.Substring(0,600) }
  $cmt = @([regex]::Matches($txt, 'commit=(\d+)') | ForEach-Object { [int64]$_.Groups[1].Value })
  $cbs = @([regex]::Matches($txt, 'cbs=(\d+)') | ForEach-Object { [int64]$_.Groups[1].Value })
  $cmtmax = 0; if ($cmt.Count) { $cmtmax = ($cmt | Measure-Object -Maximum).Maximum }
  $cbsmax = 0; if ($cbs.Count) { $cbsmax = ($cbs | Measure-Object -Maximum).Maximum }
  $fault = (($txt -split "`n" | Where-Object { $_ -match 'MSOHTML totals|\[g\] AV-' }) -join ' | ')
  if ($fault.Length -gt 700) { $fault = $fault.Substring(0,700) }
  $samp = (($txt -split "`n" | Where-Object { $_ -match '^(SAMPLE|rcx=|rbx=|[0-9a-f]{8}`)' }) -join "`n")
  if ($samp.Length -gt 6000) { $samp = $samp.Substring(0, 6000) }
  Say ("ARM={0} slot={14} host={1} loaded_stop={2} bpset={3} deferred={4} hits={5} neg={6} zero={7} rcx_lines={8} rcx_min={9} av2={10} commit_max={11} cbs_max={12} fld={15} pos_gt_end={16} max_past_end={17} min_end_minus_pos={18}" -f `
        $v, $modFile, $loaded, $bpset, $unres, $ccalls, $cneg, $czero, $cdump, $rcxs.Count, $negr8.Count, $av2, $cmtmax, $cbsmax, $sl, $npos, $posgt, $maxpast, $gapmin)
  Say ("ARM={0} bl_list={1}" -f $v, $blTxt)
  Say ("ARM={0} anchor_disasm={1}" -f $v, $uTxt)
  Say ("ARM={0} faultlines={1}" -f $v, $fault)
  Say ("ARM={0} sample_lines=`n{1}" -f $v, $samp)
}
}
Say 'ALLDONE'
