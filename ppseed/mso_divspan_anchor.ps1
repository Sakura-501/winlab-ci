# mso_divspan_anchor.ps1 - measure mso's div/span commit length path with the *in-process*
# importer harness (gbx.exe msohtml), so coverage does not depend on an Office UI instance.
#
# The sink shape is on disk in findings/MSRC/M365-Insider/mso-html-import-20260923/STATE.md SS92
# (x64, instruction level) and SS93 (ARM64 slice of the same in-service build): the realloc branch
# clamps the fetched count, the copy length comes from the raw signed value doubled.
#   FDS  ?FCommitDivSpanCore@ prologue          -- every div/span commit
#   NEG  neg ecx / mov edx,ecx / cmp rdx,rax / ja / sub rax,rdx
#                                              -- commits whose fetched count came out negative
#   CPY  lea rcx,[rax+rcx*2] ; call memcpy      -- the copy issued, r8 = 2*count (sign-extended)
#
# Two things earlier runs of this script proved from their own cdb transcripts, and both are
# encoded here:
#   * cdb will not bind `bu/bp <name>+<rva>` while that image is absent ("contains symbols not
#     qualified with module name" / "adding deferred bp"), and `sxe ld:mso` prefix-matched
#     mso20win32client.dll -- so the load filter uses the exact file name, and after that stop the
#     script prints `? mod`, `lm m mod` and `u mod+rva L3` before setting the anchors, so every
#     later count carries proof of where it was bound.
#   * the commit path runs over a million times per stage (harness reports commit_max=1.27e6), so
#     per-hit register dumps are bounded with `bp /c N` and the totals live in debugger variables
#     printed once at the end.
param([string]$Base = '.', [string]$Corpus = 'corpus\html.txt', [string]$Records = '946',
      [string]$Tag = 'dsanchor', [string]$FlagValues = '0x20001D1,0x0',
      # The importer entry is chosen by slot index.  Run 36386599477 proved the anchors bind
      # (bl -> mso!Ordinal25108+0x148, deferred=0) while slot=17 never entered FCommitDivSpanCore
      # over 946+273+25 records, so the driver slot itself is now the swept variable.
      [string]$Slots = '17',
      [int]$Stops = 700)
$ErrorActionPreference = 'Continue'
$base = (Resolve-Path $Base).Path
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out'), (Join-Path $base 'dumps') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
function Say([string]$s) { ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $s) | Add-Content $log; $s }

$hostCand = @(
  'C:\Program Files\Common Files\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso98win32client.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso40uiwin32client.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso20win32client.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso30win32client.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso50win32client.dll',
  'C:\Program Files\Common Files\Microsoft Shared\Office16\mso98win32client.dll')
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
$rv = @{}; $modFile = ''; $modTok = ''
foreach ($h in ($hostCand | Where-Object { Test-Path $_ })) {
  $r = Get-Anchors $h $SIG
  $have = @(@('FDS','NEG','CPY') | Where-Object { $r[$_] }).Count
  $it = Get-Item $h
  $extra = ''
  if ($have) { $extra = (@('FDS','NEG','CPY') | Where-Object { $r[$_] } | ForEach-Object { $_ + '=0x' + ('{0:X}' -f $r[$_]) }) -join ',' }
  Say ("TRY {0} v={1} size={2} hits={3}/3 {4}" -f $it.Name, $it.VersionInfo.FileVersion, $it.Length, $have, $extra)
  if ($have -eq 3) { $rv = $r; $modFile = $it.Name; $modTok = $it.BaseName; break }
}
if (-not $modTok) { Say 'ANCHOR_FAIL_NO_HOST'; exit 1 }
Say ("HOST selected: {0} token={1} FDS=0x{2:X} NEG=0x{3:X} CPY=0x{4:X}" -f $modFile, $modTok, $rv['FDS'], $rv['NEG'], $rv['CPY'])

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
sxd av ".echo AV2;r;k 12;.dump /ma C:\dsdbg\dav_av.dmp;g"
sxe ld:<MODFILE>
.echo ====WAITLOAD
g
.echo ====LOADED_STOP
? <MODTOK>
lm m <MODTOK>
u <MODTOK>+0x<FDS> L3
bp <MODTOK>+0x<FDS> "r $t0=@$t0+1; g"
bp /c 1 <MODTOK>+0x<FDS> ".echo FDS_SAMPLE; g"
bp <MODTOK>+0x<NEG> "r $t1=@$t1+1; g"
bp /c 200 <MODTOK>+0x<NEG> ".echo NEG_HIT; r rcx rax rdx r8; g"
bp <MODTOK>+0x<CPY> "r $t2=@$t2+1; g"
bp /c 3 <MODTOK>+0x<CPY> ".echo CPY_SAMPLE; r r8 rcx rdx; g"
bl
.echo ====BREAKPOINTS_SET
STOPS
.printf "COUNTERS fds=%d neg=%d cpy=%d\n", @$t0, @$t1, @$t2
q
'@
  $body = $tmpl.Replace('<FDS>', ('{0:X}' -f $rv['FDS'])).Replace('<NEG>', ('{0:X}' -f $rv['NEG']))
  $body = $body.Replace('<CPY>', ('{0:X}' -f $rv['CPY'])).Replace('<MODFILE>', $modFile).Replace('<MODTOK>', $modTok)
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
  $cnt = [regex]::Match($txt, 'COUNTERS fds=(\d+) neg=(\d+) cpy=(\d+)')
  $cfds = $cnt.Groups[1].Value; $cneg = $cnt.Groups[2].Value; $ccpy = $cnt.Groups[3].Value
  $negHits = @([regex]::Matches($txt, '(?m)^NEG_HIT')).Count
  $cpyHits = @([regex]::Matches($txt, '(?m)^CPY_SAMPLE')).Count
  $av2 = @([regex]::Matches($txt, '(?m)^AV2')).Count
  $r8s = @([regex]::Matches($txt, '(?m)^r8=([0-9a-fA-F]{16})') | ForEach-Object { $_.Groups[1].Value })
  $giant = @($r8s | Where-Object { $_ -like 'ffff*' })
  $loaded = ([regex]::Match($txt, '(?m)^====LOADED_STOP')).Success
  $bpset = ([regex]::Match($txt, '(?m)^====BREAKPOINTS_SET')).Success
  $unres = @([regex]::Matches($txt, 'could not be resolved')).Count
  $blTxt = (($txt -split "`n" | Where-Object { $_ -match '^\s+\d+ [eu]' }) -join ' // ').Trim()
  if ($blTxt.Length -gt 700) { $blTxt = $blTxt.Substring(0,700) }
  $uTxt = (($txt -split "`n" | Where-Object { $_ -match '^00000' }) -join ' // ').Trim()
  if ($uTxt.Length -gt 500) { $uTxt = $uTxt.Substring(0,500) }
  $cmt = @([regex]::Matches($txt, 'commit=(\d+)') | ForEach-Object { [int64]$_.Groups[1].Value })
  $cbs = @([regex]::Matches($txt, 'cbs=(\d+)') | ForEach-Object { [int64]$_.Groups[1].Value })
  $cmtmax = 0; if ($cmt.Count) { $cmtmax = ($cmt | Measure-Object -Maximum).Maximum }
  $cbsmax = 0; if ($cbs.Count) { $cbsmax = ($cbs | Measure-Object -Maximum).Maximum }
  $fault = (($txt -split "`n" | Where-Object { $_ -match 'MSOHTML totals|\[g\] AV-' }) -join ' | ')
  if ($fault.Length -gt 700) { $fault = $fault.Substring(0,700) }
  $samp = (($txt -split "`n" | Where-Object { $_ -match '^(NEG_HIT|r8=|rcx=|rax=|rdx=)' }) -join "`n")
  if ($samp.Length -gt 4000) { $samp = $samp.Substring(0, 4000) }
  Say ("ARM={0} slot={15} host={1} loaded_stop={2} bpset={3} deferred={4} fds={5} neg={6} cpy={7} neg_hit_lines={8} cpy_sample_lines={9} r8_captured={10} r8_ffff={11} av2={12} commit_max={13} cbs_max={14}" -f `
        $v, $modFile, $loaded, $bpset, $unres, $cfds, $cneg, $ccpy, $negHits, $cpyHits, $r8s.Count, $giant.Count, $av2, $cmtmax, $cbsmax, $sl)
  Say ("ARM={0} bl_list={1}" -f $v, $blTxt)
  if ([int64]$cfds -gt 0) { Say ("REACHED slot={0} ARM={1} fds={2} neg={3} cpy={4}" -f $sl, $v, $cfds, $cneg, $ccpy) }
  Say ("ARM={0} anchor_disasm={1}" -f $v, $uTxt)
  Say ("ARM={0} faultlines={1}" -f $v, $fault)
  Say ("ARM={0} sample_lines=`n{1}" -f $v, $samp)
}
}
Say 'ALLDONE'
