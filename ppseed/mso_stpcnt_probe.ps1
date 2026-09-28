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
$STORESIG = '88000000000000008907488B83B0000000488B5C24304883C4205FC3'
$STOREOFF = 8          # `mov [rdi], eax` sits 8 bytes into the signature
# Two more arms, both measuring the same unclamped field: SetLexPos/GetLexPos build their memcpy
# length as 2*[LBS+0x5C] + 0xE0 while the destination block is the fixed AllocateEx(0x40E0) snapshot
# that FLexMarkPos creates (0xE0 + 2*8192 = 0x40E0 exactly), and neither site tests that length.
$ARMS = [ordered]@{
  STOP = @{ sig = $STORESIG; off = 8 }
  SLP  = @{ sig = '4C63435C4E8D0445E0000000488BD3488BCF'; off = 18 }   # SetLexPos: call memcpy
  GLP  = @{ sig = '4C63465C488BD6488BCB4E8D0445E0000000'; off = 18 }   # GetLexPos: call memcpy
}
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
  $found = @{}; $desc = @()
  foreach ($k in $ARMS.Keys) {
    $all = @(Get-SigRva $h $ARMS[$k].sig)
    $rvas = (($all | ForEach-Object { '0x{0:X}' -f ([int](($_ -split ',')[0]) + $ARMS[$k].off) }) -join ' ')
    $desc += ('{0}[{1}]{2}' -f $k, $all.Count, $rvas)
    if ($all.Count -eq 1) { $found[$k] = [int](($all[0] -split ',')[0]) + $ARMS[$k].off } }
  $it = Get-Item $h
  Say ("TRY {0} v={1} size={2} {3}" -f $it.Name, $it.VersionInfo.FileVersion, $it.Length, ($desc -join ' '))
  if ($found.ContainsKey('STOP')) { $rv = $found; $modFile = $it.Name; $modTok = $it.BaseName; break } }
if (-not $modTok) { Say 'ANCHOR_FAIL_NO_HOST'; exit 1 }
Say ("HOST selected: {0} token={1} arms={2}" -f $modFile, $modTok,
     ((@($rv.Keys | Sort-Object) | ForEach-Object { '{0}=0x{1:X}' -f $_, $rv[$_] }) -join ' '))

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
bp <MODTOK>+0x<STORE> "r $t0=@$t0+1; .printf \"CNT %x %d\\n\", @eax, @eax; g"
bp /c <WINS> <MODTOK>+0x<STORE> ".echo STOPK; .printf \"RET ra=%p rva_mso=\n\"; dpq @rsp L6; .printf \"WIN cnt=%x buf=%p p58=%p p98=%p pa0=%p pa8=%p pb8=%p pc0=%p pc8=%p p70=%p p78=%p rbx=%p\\n\", @eax, poi(@rbx+0xb0), poi(@rbx+0x58), poi(@rbx+0x98), poi(@rbx+0xa0), poi(@rbx+0xa8), poi(@rbx+0xb8), poi(@rbx+0xc0), poi(@rbx+0xc8), poi(@rbx+0x70), poi(@rbx+0x78), @rbx; g"
SNAPBPS
bl
.echo ====BREAKPOINTS_SET
STOPS
.printf "COUNTERS store_hits=%d slp=%d glp=%d\n", @$t0, @$t1, @$t2
q
'@
  $snap = @()
  if ($rv['SLP']) {
    $snap += ('bp {0}+0x{1:X} "r $t1=@$t1+1; .printf \"SLP n=%x len=%I64d dst=%p dpo=%x src=%p\\n\", poi(@rbx+0x5c), @r8, @rcx, (@rcx&0xfff), @rdx; g"' -f $modTok, $rv['SLP']) }
  if ($rv['GLP']) {
    $snap += ('bp {0}+0x{1:X} "r $t2=@$t2+1; .printf \"GLP n=%x len=%I64d dst=%p dpo=%x src=%p\\n\", poi(@rsi+0x5c), @r8, @rcx, (@rcx&0xfff), @rdx; g"' -f $modTok, $rv['GLP']) }
  if (-not $snap.Count) { $snap += '.echo NO_SNAP_ARMS' }
  $body = $tmpl.Replace('<STORE>', ('{0:X}' -f $rv['STOP'])).Replace('<WINS>', "$WindowSamples").
          Replace('<MODFILE>', $modFile).Replace('<MODTOK>', $modTok)
  $ladder = @()
  for ($i = 0; $i -lt $Stops; $i++) { $ladder += '.echo ====STOP'; $ladder += 'g' }
  $c2 = @()
  foreach ($ln in @($body -split "`n")) {
    if ($ln.Trim() -eq 'STOPS') { $c2 += $ladder }
    elseif ($ln.Trim() -eq 'SNAPBPS') { $c2 += $snap }
    else { $c2 += ($ln -replace "`r",'') } }
  Set-Content -Path $cm -Value ($c2 -join "`n") -Encoding ascii
  $env:GBFLAGS = $v
  $p = Start-Process -FilePath $cdbExe -ArgumentList @('-cf', $cm, '-o', $gbx, 'msohtml', (Join-Path $base $Corpus),
                    $Records, '0', 'none', 'norel', 'noskip', ('slot=' + $sl)) -NoNewWindow -PassThru -RedirectStandardOutput $tr
  $p.WaitForExit()
  $txt = ''
  if (Test-Path $tr) { $txt = Get-Content $tr -Raw -EA SilentlyContinue }
  if (-not $txt) { $txt = '' }
  $cnt = [regex]::Match($txt, 'COUNTERS store_hits=(\d+) slp=(\d+) glp=(\d+)')
  $hits = $cnt.Groups[1].Value; $nSlp = $cnt.Groups[2].Value; $nGlp = $cnt.Groups[3].Value
  $vals2 = @([regex]::Matches($txt, '(?m)^CNT ([0-9a-fA-F]{1,8}) ') | ForEach-Object { [int64]([Convert]::ToUInt32($_.Groups[1].Value, 16)) })
  $neg = @($vals2 | Where-Object { $_ -lt 0 -or $_ -gt 2147483647 }).Count
  $mx = 0; $mn = 0
  if ($vals2.Count) { $mx = ($vals2 | Measure-Object -Maximum).Maximum; $mn = ($vals2 | Measure-Object -Minimum).Minimum }
  $snapRows = @()
  foreach ($arm in @('SLP','GLP')) {
    $lens = @(); $ns = @()
    foreach ($m in [regex]::Matches($txt, "(?m)^$arm n=([0-9a-fA-F]+) len=(-?\d+) dst=([0-9a-fA-F``]+) dpo=([0-9a-fA-F]+)")) {
      $nv = [Convert]::ToUInt32($m.Groups[1].Value, 16)
      $nS = if ($nv -gt 2147483647) { [int64]$nv - 4294967296 } else { [int64]$nv }
      $lv = [int64]$m.Groups[2].Value
      $lens += $lv; $ns += $nS
      if ($lv -gt 0x40E0 -or $lv -lt 0) {
        $snapRows += ('{0} n={1} len={2} over_0x40E0_by={3} dst={4} dpo={5}' -f $arm, $nS, $lv, ($lv - 0x40E0), $m.Groups[3].Value, $m.Groups[4].Value) } }
    $lmx = 0; $ln0 = 0
    if ($lens.Count) { $lmx = ($lens | Measure-Object -Maximum).Maximum; $ln0 = @($lens | Where-Object { $_ -lt 0 }).Count }
    $nm = 0; if ($ns.Count) { $nm = ($ns | Measure-Object -Maximum).Maximum }
    Say ("{0} hits={1} len_max={2} len_neg={3} n_max={4} over_list={5}" -f $arm, $lens.Count, $lmx, $ln0, $nm, $snapRows.Count)
  }
  $rows = @()
  $rx = '(?m)^WIN cnt=(?<cnt>[0-9a-fA-F]{1,8}) buf=(?<buf>[0-9a-fA-F`]+) p58=(?<p58>[0-9a-fA-F`]+) p98=(?<p98>[0-9a-fA-F`]+) pa0=(?<pa0>[0-9a-fA-F`]+) pa8=(?<pa8>[0-9a-fA-F`]+) pb8=(?<pb8>[0-9a-fA-F`]+) pc0=(?<pc0>[0-9a-fA-F`]+) pc8=(?<pc8>[0-9a-fA-F`]+) p70=(?<p70>[0-9a-fA-F`]+) rbx=(?<rbx>[0-9a-fA-F`]+)'
  function Q([string]$v) { [Convert]::ToUInt64(($v -replace '`',''), 16) }
  foreach ($m in [regex]::Matches($txt, $rx)) {
    $g = $m.Groups
    $u = [Convert]::ToUInt32($g['cnt'].Value, 16)
    $s = if ($u -gt 2147483647) { [int64]$u - 4294967296 } else { [int64]$u }
    $buf = Q $g['buf'].Value
    $p58 = Q $g['p58'].Value
    $pb8 = Q $g['pb8'].Value
    $po  = [int]($buf -band 0xFFF); $tg = 0x1000 - $po
    $cap = [int64](($pb8 -shr 32) -band 0xFFFFFFFF)      # LBS+0xBC: sub_18040BBC4's capacity field
    $f5c = [int64](($p58 -shr 32) -band 0xFFFFFFFF)      # LBS+0x5C: SetLexPos/GetLexPos use 2*n+224 into a 0x40E0 block
    $szmod = $tg -band 0xFFF                             # page heap: size % 0x1000 == this
    $rows += ('cnt={0} copy_bytes={1} cap={2} f5c={3} snap_bytes_if_f5c={4} buf={5:x} po={6} to_guard={7} size_mod={8} 2cap_mod={9} p98={10:x} pa0={11:x} pa8={12:x} pc0={13:x} pc8={14:x} p70={15:x} rbx={16:x}' -f `
              $s, ($s * 2), $cap, $f5c, (2 * $f5c + 224), $buf, $po, $tg, $szmod, (($cap * 2) -band 0xFFF), `
              (Q $g['p98'].Value), (Q $g['pa0'].Value), (Q $g['pa8'].Value), (Q $g['pc0'].Value), `
              (Q $g['pc8'].Value), (Q $g['p70'].Value), (Q $g['rbx'].Value))
  }
  $stopk = @()
  $blocks = @($txt -split '(?m)^STOPK')
  $stackRows = @()
  foreach ($b in $blocks) {
    $fr = @(($b -split "`n" | Where-Object { $_ -match '^[0-9a-fA-F]{16}`?[0-9a-fA-F]{0,8}`?\s+[0-9a-fA-F]{16}' }))
    if ($fr.Count) { $stackRows += ($fr[0..([Math]::Min(7, $fr.Count-1))] -join "`n") }
  }
  if ($stackRows.Count -gt 4) { $stackRows = @($stackRows[0..3]) }
  foreach ($sr in $stackRows) { Say ("ARM={0} stopk_stack=`n{1}" -f $v, $sr) }
  Say ("ARM={0} stopk_blocks={1}" -f $v, $stopk.Count)
  foreach ($sk in $stopk) { Say ("ARM={0} stopk=`n{1}" -f $v, $sk) }
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
  Say ("ARM={0} host={1} STORE=0x{2:X} loaded_stop={3} bpset={4} deferred={5} store_hits={6} cnt_lines={7} neg={8} cnt_min={9} cnt_max={10} slp_counters={11} glp_counters={12} av2={13} window_blocks={14}" -f `
        $v, $modFile, $rv['STOP'], $loaded, $bpset, $unres, $hits, $vals2.Count, $neg, $mn, $mx, $nSlp, $nGlp, $av2, $rows.Count)
  Say ("ARM={0} bl_list={1}" -f $v, $blTxt)
  Say ("ARM={0} anchor_disasm={1}" -f $v, $uTxt)
  Say ("ARM={0} faultlines={1}" -f $v, $fault)
  $ov = $snapRows
  if ($ov.Count -gt 40) { $ov = @($ov[0..39]) }
  Say ("ARM={0} snap_over_rows=`n{1}" -f $v, ($ov -join "`n"))
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
