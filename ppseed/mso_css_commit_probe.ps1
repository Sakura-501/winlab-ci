# mso_css_commit_probe.ps1 - measure, at instruction level, whether mso's CSS table importer ever hands
# memcpy more bytes than it allocated.  Anchors are byte signatures inside the *installed* mso.dll.
#
# ?FImportStyleSheet@@YAHPEAUCPD@@PEAUCSSTK@@@Z (mso 16.0.20430.20092 x64 view, rva 0x7F9250) takes the
# int* out-param of ?FClassifyRgwch@@ into [rbp-8] (= n), then
#   7f92e5  mov eax,[rbp-8] ; add eax,2 ; movsxd rcx,eax ; add rcx,rcx      -> alloc size 2*(n+2)
#   7f930c  movsxd r8,[rbp-8] ; add r8,r8 ; lea rcx,[rax+2] ; mov rdx,[rbp-0x10] ; call memcpy
#                                                                          -> copy length 2*n
# The "+2" that keeps the allocation positive for small negative n is a 32-bit add that the copy
# expression never repeats, so the two expressions of the same signed value are not the same quantity.
# Every (alloc,memcpy) pair is dumped so the host counts copy>alloc and the sign cases directly -
# that pairing is the memory-safety observation, and it does not depend on any cdb expression.
# ALLOC and COPY signatures each match exactly once in the installed mso.dll (0 in Mso98win32client.dll
# and GFX.dll of the same build); the host-side pairing replaces the breakpoint-condition syntax that
# cdb rejects inside a bp command string.
param([string]$Base = '.', [string]$Corpus = 'corpus\html.txt', [string]$Records = '946',
      [string]$Tag = 'cssprobe', [string]$FlagValues = '0x20001D1',
      [string]$Slots = '17', [int]$Stops = 700, [int]$SampleFirst = 6)
$ErrorActionPreference = 'Continue'
$base = (Resolve-Path $Base).Path
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out'), (Join-Path $base 'dumps') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
function Say([string]$s) { ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $s) | Add-Content $log; $s }

$hostCand = @(
  'C:\Program Files\Common Files\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso.dll')
# pattern starts at the `sub`; the breakpoint belongs on the following `sar rcx,1` (+4 bytes)
$SIG = [ordered]@{ ALLOC = '8B45F883C0024863C84803C9'; COPY = '4C6345F84D03C0488D4802488B55F0E8' }
# +4 = the `sar rcx,1` (rcx still holds the raw byte difference); +13 = the CastThrow call site
# (rcx already holds the character count that is stored through the caller's int*, i.e. the value the
# committer later doubles for memcpy).
$SIGOFF = @{ ALLOC = 0; COPY = 0 }
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
  $have = 0; if ($r['ALLOC'] -and $r['COPY']) { $have = 2 }
  Say ("TRY {0} v={1} size={2} hits={3}/2 alloc=0x{4:X} copy=0x{5:X}" -f $it.Name, $it.VersionInfo.FileVersion, `
        $it.Length, $have, $r['ALLOC'], $r['COPY'])
  if ($have -eq 2) { $rv = $r; $modFile = $it.Name; $modTok = $it.BaseName; break }
}
if (-not $modTok) { Say 'ANCHOR_FAIL_NO_HOST'; exit 1 }
Say ("HOST selected: {0} token={1} ALLOC=0x{2:X} COPY=0x{3:X}" -f $modFile, $modTok, $rv['ALLOC'], $rv['COPY'])

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
u <MODTOK>+0x<ALLOC> L6
u <MODTOK>+0x<COPY> L6
bp /c 30000 <MODTOK>+0x<ALLOC> "r $t0=@$t0+1; .echo SZAL; r rcx; g"
bp /c 30000 <MODTOK>+0x<COPY> "r $t1=@$t1+1; .echo SZCP; r r8 rcx; g"
bl
.echo ====BREAKPOINTS_SET
STOPS
.printf "COUNTERS alloc=%d copy=%d\n", @$t0, @$t1
q
'@
  $body = $tmpl.Replace('<ALLOC>', ('{0:X}' -f $rv['ALLOC'])).Replace('<COPY>', ('{0:X}' -f $rv['COPY'])).Replace('<MODFILE>', $modFile).Replace('<MODTOK>', $modTok)
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
  $cnt = [regex]::Match($txt, 'COUNTERS alloc=(\d+) copy=(\d+)')
  $ccalls = $cnt.Groups[1].Value + '/' + $cnt.Groups[2].Value
  $al = @([regex]::Matches($txt, '(?m)^SZAL\r?\nrcx=([0-9a-fA-F]{16})') | ForEach-Object { [Convert]::ToUInt64($_.Groups[1].Value, 16) })
  $cp = @([regex]::Matches($txt, '(?m)^SZCP\r?\nr8=([0-9a-fA-F]{16})') | ForEach-Object { [Convert]::ToUInt64($_.Groups[1].Value, 16) })
  $npair = [Math]::Min($al.Count, $cp.Count); $over = 0; $neglen = 0; $worst = [int64]0
  for ($q = 0; $q -lt $npair; $q++) {
    if ($cp[$q] -ge 0x8000000000000000) { $neglen++ }
    if ($cp[$q] -gt $al[$q]) { $over++; $d = [int64]($cp[$q] - $al[$q]); if ($d -gt $worst) { $worst = $d } }
  }
  # every hit's rcx is in the transcript (the debugger prints the register; the sign/zero/min are
  # computed here so nothing depends on cdb expression syntax inside a breakpoint command).
  # only the rcx line that follows a DLTX marker belongs to the delta site

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
  $samp = (($txt -split "`n" | Where-Object { $_ -match '^(SZAL|SZCP|rcx=|r8=)' }) -join "`n")
  if ($samp.Length -gt 6000) { $samp = $samp.Substring(0, 6000) }
  Say ("ARM={0} slot={13} host={1} loaded_stop={2} bpset={3} deferred={4} alloc_copy={5} pairs={6} copy_gt_alloc={7} copy_topbit={8} worst_excess={9} av2={10} commit_max={11} cbs_max={12}" -f `
        $v, $modFile, $loaded, $bpset, $unres, $ccalls, $npair, $over, $neglen, $worst, $av2, $cmtmax, $cbsmax, $sl)
  Say ("ARM={0} bl_list={1}" -f $v, $blTxt)
  Say ("ARM={0} anchor_disasm={1}" -f $v, $uTxt)
  Say ("ARM={0} faultlines={1}" -f $v, $fault)
  Say ("ARM={0} sample_lines=`n{1}" -f $v, $samp)
}
}
Say 'ALLDONE'
