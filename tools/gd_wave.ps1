$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:CRTF_MODS = 'all'
$env:CRTF_GUARD = '1'
$env:CRTF_RESCAN = '25'
foreach ($m in @('11', '41', '43', '5')) {
    $env:CRTF_RUN = $m
    $cor = if ($m -eq '43') { 'ess43.txt' } elseif ($m -eq '41') { 'attr5.txt' } else { 'tnef2.txt' }
    Copy-Item 'C:\Users\nonoge\Documents\olkb\sav\h_benign.msg' 'C:\crtf\base1.msg' -Force
    $env:CRTF_BASEMSG = 'C:\crtf\base1.msg'
    $o = & C:\crtf\crtfbench55_x64.exe "C:\crtf\$cor" 2 256 52 240000 2>&1
    $o | Set-Content -Encoding utf8 "C:\crtf\gd_m$m.txt"
    $s = @($o | Select-String '!!!AV|!!!EXC|TPROG|TNEFCASES|ATTRCASES|ESS43|GUARDSTAT|HOOKSTAT|WATCHDOG' | Select-Object -Last 10 | ForEach-Object { $_.Line })
    Write-Output ("=== mode " + $m + " corpus=" + $cor + " lines=" + $o.Count + " exit=" + $LASTEXITCODE)
    Write-Output ($s -join "`n")
    $a = @($o | Select-String 'CODE:|TGTBYTES:|RAX=' | Select-Object -First 3 | ForEach-Object { $_.Line })
    if ($a.Count) { Write-Output ($a -join "`n") }
}
