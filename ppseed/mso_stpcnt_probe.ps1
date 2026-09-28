# mso_stpcnt_probe.ps1 - measure the count that mso's div/span commit actually receives.
#
# Why this anchor and not the previous one:  mso!FCommitDivSpanCore gets its append length from
# Mso98win32client!PwchLexStopBuffering, whose body (20092 x64, rva 0x40B250, decompiled from the
# PDB-named IDB) is
#     sub_18040B4BC(a1, a2, 1, a3)
#     mov  eax, [rbx+0B8h]           ; rva 0x40B26E  -- the count field
#     and  dword [rbx+7Ch], -3
#     mov  qword [rbx+98h], 0
#     mov  qword [rbx+88h], 0
#     mov  [rdi], eax                ; rva 0x40B28E  -- ★ the caller's out-param (mso's a5)
#     mov  rax, [rbx+0B0h]           ;               -- the buffer mso memcpy's from
#     ret
# The sweep in mso_fetchdelta_probe.ps1 watched (LBS+0x60 - LBS+0x68)>>1 inside PwchFetchToIhtks,
# which is the token-*name* length feeding IhtkLookupNameNcHtkmd -- a different quantity from the
# field that reaches the copy.  This script watches the field that reaches the copy.
#
# Breakpoint is placed on the `mov [rdi], eax`, so eax = the exact value mso will use as a5 and rbx
# = the LBS.  Every hit prints the value; a bounded second bp dumps the LBS+0xA0..0xC8 window so
# the capacity field next to the buffer pointer can be identified from real data rather than by
# assumption.  Under full page heap the buffer's own start page offset is also evidence: a
# page-heap allocation ends flush against its guard page, so (buf & 0xFFF) + size == 0x1000.
param([string]$Base = '.', [string]$Corpus = 'corpus\html.txt', [string]$Records = '889',
      [string]$Tag = 'stpcnt', [string]$FlagValues = '0x20001D1,0x0',
      [string]$Slots = '17', [int]$Stops = 700, [int]$WindowSamples = 1200)
$ErrorActionPreference = 'Continue'
$base = (Resolve-Path $Base).Path
New-Item -ItemType Directory -Force -Path (Join-Path $base 'out'), (Join-Path $base 'dumps') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
function Say([string]$s) { ("{0} {1}" -f (Get-Date -Format HH:mm:ss), $s) | Add-Content $log; $s }

# 28 bytes ending at the function's ret; unique exactly once in the archived 20092 client DLL.
$STORESIG = '880000000000008907488B83B0000000 488B5C24304883C4205FC3'.Replace(' ','')
$STOREOFF = 8          # `mov [rdi], eax` sits 8 bytes into the signature
$hostCand = @(
  'C:\Program Files\Common Files\Microsoft Shared\Office16\mso98win32client.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso98win32client.dll',
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\mso98win32client.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso40uiwin32client.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso20win32client.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso30win32client.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso50win32client.dll')
function Get-SigRva([string]$path, [string]$sig) {
  $bytes = [IO.File]::ReadAllBytes($path)
  $pe = [BitConverter]::ToInt32($bytes, 0x3C)
  $nsec = [BitConverter]::ToInt16($bytes, $pe + 6)
  $sh = $pe + 24 + [BitConverter]::ToInt16($bytes, $pe + 20)
  $tva = 0; $tpraw = 0
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $sh + $i * 40
    if ([Text.Encoding]::ASCII.GetString($bytes, $o, 8).Trim([char]0) -eq '.text') {
      $tva = [BitConverter]::ToInt32($bytes, $o + 12); $tpraw = [BitConverter]::ToInt32($bytes, $o + 20); break } }
  if (-not $tpraw) { return @() }
  $bts = @(); for ($j = 0; $j -lt $sig.Length; $j += 2) { $bts += [Convert]::ToInt32($sig.Substring($j, 2), 16) }
  $lit = ''
  foreach ($v in $bts) { $lit += [char]$v }
  $latin = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
  $all = @(); $from = 0
  while ($true) {
    $c = $latin.IndexOf($lit, $from, [StringComparison]::Ordinal)
    if ($c -lt 0) { break }
    $all += ('{0},{1}' -f ($tva + ($c - $tpraw)), $c)
    $from = $c + 1 }
  return $all
}
$rv = @{}; $modFile = ''; $modTok = ''
foreach ($h in ($hostCand | Where-Object { Test-Path $_ })) {
  $all = @(Get-SigRva $h $STORESIG)
  $it = Get-Item $h
  Say ("TRY {0} v={1} size={2} sig_hits={3} rvas={4}" -f $it.Name, $it.VersionInfo.FileVersion, $it.Length, $all.Count,
        (($all | ForEach-Object { (($_ -split ',')[0] | ForEach-Object { '0x{0:X}' -f ([int]$_ + $STOREOFF) }) }) -join ' '))
  if ($all.Count -eq 1) { $rv['STOP'] = [int](($all[0] -split ',')[0]) + $STOREOFF; $modFile = $it.Name; $modTok = $it.BaseName; break } }
if (-not $modTok) { Say 'ANCHOR_FAIL_NO_HOST'; exit 1 }
Say ("HOST selected: {0} token={1} STORE=0x{2:X}" -f $modFile, $modTok, $rv['STOP'])

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
sxd av ".echo AV2;r;k 12;.dump /ma C:\dsdbg\stpcnt_av.dmp;g"
sxe ld:<MODFILE>
.echo ====WAITLOAD
g
.echo ====LOADED_STOP
? <MODTOK>
lm m <MODTOK>
u <MODTOK>+0x<STORE> L4
bp <MODTOK>+0x<STORE> "r $t0=@$t0+1; r $t1=@$t1+(@eax/1024); .printf \"CNT %x %d\\n\", @eax, @eax; g"
bp /c <WINS> <MODTOK>+0x<STORE> ".printf \"WIN cnt=%x buf=%p f98=%p fa0=%p fa8=%p fb0=%p fc0=%p fc8=%p rdi=%p rbx=%p\\n\", @eax, poi(@rbx+0xb0), poi(@rbx+0x98), poi(@rbx+0xa0), poi(@rbx+0xa8), poi(@rbx+0xb0), poi(@rbx+0xc0), poi(@rbx+0xc8), @rdi, @rbx; g"
bl
.echo ====BREAKPOINTS_SET
STOPS
.printf "COUNTERS store_hits=%d kb_sum=%d\n", @$t0, @$t1
q
'@
  $body = $tmpl.Replace('<STORE>', ('{0:X}' -f $rv['STOP'])).Replace('<WINS>', "$WindowSamples").
          Replace('<MODFILE>', $modFile).Replace('<MODTOK>', $modTok)
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
  $cnt = [regex]::Match($txt, 'COUNTERS store_hits=(\d+) kb_sum=(\d+)')
  $hits = $cnt.Groups[1].Value; $kbs = $cnt.Groups[2].Value
  $vals2 = @([regex]::Matches($txt, '(?m)^CNT ([0-9a-fA-F]{8}) ') | ForEach-Object { [int64]([Convert]::ToUInt32($_.Groups[1].Value, 16)) })
  $neg = @($vals2 | Where-Object { $_ -lt 0 -or $_ -gt 2147483647 }).Count
  $mx = 0; $mn = 0
  if ($vals2.Count) { $mx = ($vals2 | Measure-Object -Maximum).Maximum; $mn = ($vals2 | Measure-Object -Minimum).Minimum }
  $rows = @()
  foreach ($m in [regex]::Matches($txt, '(?m)^WIN cnt=([0-9a-fA-F]{8}) buf=([0-9a-fA-F`]+) .*?fa8=([0-9a-fA-F`]+) fb0=([0-9a-fA-F`]+) fc0=([0-9a-fA-F`]+) fc8=([0-9a-fA-F`]+)')) {
    $u = [Convert]::ToUInt32($m.Groups[1].Value, 16)
    $s = if ($u -gt 2147483647) { [int64]$u - 4294967296 } else { [int64]$u }
    $buf = [Convert]::ToUInt64(($m.Groups[2].Value -replace '`',''), 16)
    $po = [int]($buf -band 0xFFF); $tg = 0x1000 - $po
    $copyBytes = $s * 2
    $rows += ('cnt={0} copy_bytes={1} buf=0x{2:x} po={3} to_guard={4} fa8=0x{5:x} fc0=0x{6:x} fc8=0x{7:x}' -f `
              $s, $copyBytes, $buf, $po, $tg, `
              ($m.Groups[3].Value -replace '`','').PadLeft(16,'0'), ($m.Groups[4].Value -replace '`','').PadLeft(16,'0'), `
              ($m.Groups[5].Value -replace '`','').PadLeft(16,'0'))
  }
  $av2 = @([regex]::Matches($txt, '(?m)^AV2')).Count
  $loaded = ([regex]::Match($txt, '(?m)^====LOADED_STOP')).Success
  $bpset = ([regex]::Match($txt, '(?m)^====BREAKPOINTS_SET')).Success
  $unres = @([regex]::Matches($txt, 'could not be resolved|deferred')).Count
  $blTxt = (($txt -split "`n" | Where-Object { $_ -match '^\s+\d+ [eu]' }) -join ' // ').Trim()
  if ($blTxt.Length -gt 700) { $blTxt = $blTxt.Substring(0,700) }
  $uTxt = (($txt -split "`n" | Where-Object { $_ -match '^00000' }) -join ' // ').Trim()
  if ($uTxt.Length -gt 400) { $uTxt = $uTxt.Substring(0,400) }
  $fault = (($txt -split "`n" | Where-Object { $_ -match 'MSOHTML totals|\[g\] AV-' }) -join ' | ')
  if ($fault.Length -gt 700) { $fault = $fault.Substring(0,700) }
  Say ("ARM={0} host={1} STORE=0x{2:X} loaded_stop={3} bpset={4} deferred={5} store_hits={6} cnt_lines={7} neg={8} cnt_min={9} cnt_max={10} kb_sum={11} av2={12} window_blocks={13}" -f `
        $v, $modFile, $rv['STOP'], $loaded, $bpset, $unres, $hits, $vals2.Count, $neg, $mn, $mx, $kbs, $av2, $rows.Count)
  Say ("ARM={0} bl_list={1}" -f $v, $blTxt)
  Say ("ARM={0} anchor_disasm={1}" -f $v, $uTxt)
  Say ("ARM={0} faultlines={1}" -f $v, $fault)
  $take = $rows
  if ($take.Count -gt 60) { $take = @($take[0..29]) + @($take[-30..-1]) }
  Say ("ARM={0} window_rows=`n{1}" -f $v, ($take -join "`n"))
  $cvals = @($vals2 | Group-Object | ForEach-Object { '{0}x{1}' -f $_.Name, $_.Count } | Sort-Object)
  $hist = ($cvals -join ' ')
  if ($hist.Length -gt 3000) { $hist = $hist.Substring(0,3000) }
  Say ("ARM={0} cnt_hist={1}" -f $v, $hist)
}
}
Say 'ALLDONE'
