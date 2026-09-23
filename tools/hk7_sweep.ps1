$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:CRTF_MODS = 'all'
$env:CRTF_RESCAN = '20'
foreach ($m in @('12','5','41','43')) {
    $env:CRTF_RUN = $m
    $cor = if ($m -eq '43') { 'ess43.txt' } elseif ($m -eq '41') { 'attr5.txt' } else { 'tnef2.txt' }
    Copy-Item 'C:\Users\nonoge\Documents\olkb\sav\h_benign.msg' 'C:\crtf\base1.msg' -Force
    $env:CRTF_BASEMSG = 'C:\crtf\base1.msg'
    $o = & C:\crtf\crtfbench53_x64.exe "C:\crtf\$cor" 2 256 52 120000 2>&1
    $out = "C:\crtf\hk7_m$m.txt"
    $o | Set-Content -Encoding utf8 $out
    Write-Output ("=== mode $m corpus=$cor lines=" + $o.Count)
    $s = @($o | Select-String 'TPROG|TNEFCASES|ATTRCASES|ESS43|TNEXPORTS|HOOKSTAT|EXC' | Select-Object -Last 6 | ForEach-Object { $_.Line })
    Write-Output ($s -join "`n")
    $d = @($o | Select-String 'DUPFREE ' | ForEach-Object { $_.Line } | Select-Object -First 8)
    Write-Output ("DUP=" + $d.Count + " SITES=" + @($o | Select-String 'DUPSITE').Count)
    Write-Output ($d -join "`n")
}
