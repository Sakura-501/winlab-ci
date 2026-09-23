$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:CRTF_MODS = 'all'
$env:CRTF_RESCAN = '0'
$env:CRTF_RUN = '11'
$env:CRTF_NMAX = '60'
foreach ($f in @('0','1','2','4','5','9')) {
    Copy-Item 'C:\Users\nonoge\Documents\olkb\sav\h_benign.msg' 'C:\crtf\base1.msg' -Force
    $env:CRTF_BASEMSG = 'C:\crtf\base1.msg'
    $o = & C:\crtf\crtfbench53_x64.exe C:\crtf\tnef2.txt $f 256 52 30000 2>&1
    $pick = @($o | Select-String -Pattern 'TBASEMSG|TPROG|TNEF|EXC|DUPFREE' | Select-Object -Last 4)
    Write-Output ("flags=" + $f + " :: " + (($pick | ForEach-Object { $_.Line }) -join ' | '))
}
