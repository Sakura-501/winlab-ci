# mso_classify_neg_probe.ps1 - measure the element count that mso!FClassifyRgwch stores through its
# out-param, at the store itself (shared by all six consumers of that out-param), plus the three writes
# that immediately follow it in the same function.
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
      [string]$Tag = 'clsneg', [string]$FlagValues = '0x20001D1,0x0',
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
# 33-byte prefix of the run sub r13,r14 / sar r13,1 / range-only guard / mov [rdi+18h],r13d ; unique in
# the archived 20092 x64 mso.dll (occurs exactly once).  Offsets inside the located run:
#   +28 mov [rdi+0x18], r13d   (the out-param store; r13d = the signed element count)
#   +60 call [rip+..]          (allocator; rcx = 2*(n+1) as a sign-extended 64-bit size)
#   +84 call memcpy            (rcx = buffer, rdx = token start, r8 = 2*n sign-extended)
#   +93 mov word ptr [rcx+rdx*2], r13w   (terminator word written at index n)
$ARMS = [ordered]@{
  CSN  = @{ sig = '4D2BEEB80000008049D1FDB9FFFFFFFF4903C5483BC10F876003000044896F18'; off = 28 }  # +28 = mov [rdi+0x18], r13d
}
$hostCand = @(
  'C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Common Files\Microsoft Shared\OFFICE16\mso.dll',
  'C:\Program Files\Microsoft Office\root\Office16\mso40uiwin32client.dll')
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
  if ($found.ContainsKey('CSN')) { $rv = $found; $modFile = $it.Name; $modTok = $it.BaseName; break } }
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
sxd av ".echo AV2;r;k 12;.dump /ma C:\dsdbg\clsneg_av.dmp;g"
sxe ld:<MODFILE>
.echo ====WAITLOAD
g
.echo ====LOADED_STOP
? <MODTOK>
lm m <MODTOK>
u <MODTOK>+0x<STORE> L8
bp <MODTOK>+0x<STORE> "r $t0=@$t0+1; .printf \"CSN %x\\n\", @r13d; g"
bp <MODTOK>+0x<ALLOC> "r $t1=@$t1+1; .printf \"ALC %I64d\\n\", @rcx; g"
bp /c <WINS> <MODTOK>+0x<COPY> ".printf \"CPY dst=%p dpo=%x src=%p len=%I64d\\n\", @rcx, (@rcx&0xfff), @rdx, @r8; g"
bp /c <WINS> <MODTOK>+0x<TERM> ".printf \"TRM buf=%p idx=%I64d addr=%p n=%x\\n\", @rcx, @rdx, (@rcx+@rdx*2), poi(@rdi+0x18); g"
bl
.echo ====BREAKPOINTS_SET
STOPS
.printf "COUNTERS store_hits=%d alloc_hits=%d\n", @$t0, @$t1
q
'@
  $body = $tmpl.Replace('<STORE>', ('{0:X}' -f $rv['CSN'])).Replace('<ALLOC>', ('{0:X}' -f ($rv['CSN'] + 32))).
          Replace('<COPY>', ('{0:X}' -f ($rv['CSN'] + 56))).Replace('<TERM>', ('{0:X}' -f ($rv['CSN'] + 65))).
          Replace('<WINS>', "$WindowSamples").
          Replace('<MODFILE>', $modFile).Replace('<MODTOK>', $modTok)
  $ladder = @()
  for ($i = 0; $i -lt $Stops; $i++) { $ladder += '.echo ====STOP'; $ladder += 'g' }
  $c2 = @()
  foreach ($ln in @($body -split "`n")) {
    if ($ln.Trim() -eq 'STOPS') { $c2 += $ladder }
    else { $c2 += ($ln -replace "`r",'') } }
  Set-Content -Path $cm -Value ($c2 -join "`n") -Encoding ascii
  $env:GBFLAGS = $v
  $p = Start-Process -FilePath $cdbExe -ArgumentList @('-cf', $cm, '-o', $gbx, 'msohtml', (Join-Path $base $Corpus),
                    $Records, '0', 'none', 'norel', 'noskip', ('slot=' + $sl)) -NoNewWindow -PassThru -RedirectStandardOutput $tr
  $p.WaitForExit()
  $txt = ''
  if (Test-Path $tr) { $txt = Get-Content $tr -Raw -EA SilentlyContinue }
  if (-not $txt) { $txt = '' }
  $cnt = [regex]::Match($txt, 'COUNTERS store_hits=(\d+) alloc_hits=(\d+)')
  $hits = $cnt.Groups[1].Value; $nAlloc = $cnt.Groups[2].Value
  $ns = @([regex]::Matches($txt, '(?m)^CSN ([0-9a-fA-F]{1,8})') | ForEach-Object { [int64]([Convert]::ToUInt32($_.Groups[1].Value, 16)) })
  $neg = @($ns | Where-Object { $_ -lt 0 }).Count
  $nmx = 0; $nmn = 0
  if ($ns.Count) { $nmx = ($ns | Measure-Object -Maximum).Maximum; $nmn = ($ns | Measure-Object -Minimum).Minimum }
  $als = @([regex]::Match($txt, '(?m)^ALC (-?\d+)$') | ForEach-Object { 0 })
  $allv = @([regex]::Matches($txt, '(?m)^ALC (-?\d+)') | ForEach-Object { [int64]$_.Groups[1].Value })
  $almx = 0; $almin = 0; $alneg = @($allv | Where-Object { $_ -lt 0 -or $_ -gt 0x7FFFFFFF }).Count
  if ($allv.Count) { $almx = ($allv | Measure-Object -Maximum).Maximum; $almin = ($allv | Measure-Object -Minimum).Minimum }
  $cpyRows = @([regex]::Matches($txt, '(?m)^CPY dst=(\S+) dpo=([0-9a-fA-F]+) src=(\S+) len=(-?\d+)') | ForEach-Object {
      'dst={0} dpo={1} len={2} len_minus_dpo_avail={3}' -f $_.Groups[1].Value, $_.Groups[2].Value, $_.Groups[4].Value, ([int64]$_.Groups[4].Value - (0x1000 - [Convert]::ToInt32($_.Groups[2].Value, 16))) })
  $trmRows = @([regex]::Matches($txt, '(?m)^TRM buf=(\S+) idx=(-?\d+) addr=(\S+) n=([0-9a-fA-F]{1,8})') | ForEach-Object {
      $nv = [Convert]::ToUInt32($_.Groups[4].Value, 16)
      $nS = if ($nv -gt 2147483647) { [int64]$nv - 4294967296 } else { [int64]$nv }
      'idx={0} n={1} buf={2} word_addr={3} below_buf={4}' -f $_.Groups[2].Value, $nS, $_.Groups[1].Value, $_.Groups[3].Value, ([int64]$_.Groups[2].Value -lt 0) })
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
  Say ("ARM={0} host={1} CSN=0x{2:X} loaded_stop={3} bpset={4} deferred={5} store_hits={6} csn_lines={7} n_neg={8} n_min={9} n_max={10} alloc_hits={11} alcneg={12} av2={13} cpy_rows={14}" -f `
        $v, $modFile, $rv['CSN'], $loaded, $bpset, $unres, $hits, $ns.Count, $neg, $nmn, $nmx, $nAlloc, $alneg, $av2, $cpyRows.Count)
  Say ("ARM={0} bl_list={1}" -f $v, $blTxt)
  Say ("ARM={0} anchor_disasm={1}" -f $v, $uTxt)
  Say ("ARM={0} faultlines={1}" -f $v, $fault)
  $cr = $cpyRows
  if ($cr.Count -gt 40) { $cr = @($cr[0..19]) + @($cr[-20..-1]) }
  Say ("ARM={0} cpy_rows=`n{1}" -f $v, ($cr -join "`n"))
  $tr2 = $trmRows
  if ($tr2.Count -gt 40) { $tr2 = @($tr2[0..19]) + @($tr2[-20..-1]) }
  Say ("ARM={0} trm_rows=`n{1}" -f $v, ($tr2 -join "`n"))
  Say ("ARM={0} alloc_min={1} alloc_max={2} alloc_lines={3}" -f $v, $almin, $almx, $allv.Count)
  $cvals = @($ns | Group-Object | ForEach-Object { '{0}x{1}' -f $_.Name, $_.Count } | Sort-Object)
  $hist = ($cvals -join ' ')
  if ($hist.Length -gt 3000) { $hist = $hist.Substring(0,3000) }
  Say ("ARM={0} n_hist={1}" -f $v, $hist)
}
}
Say 'ALLDONE'
