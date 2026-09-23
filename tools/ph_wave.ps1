$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ifco = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\crtfbench53_x64.exe'
$undo = @()
function ARM([string]$mode) {
    if ($mode -eq 'on') {
        if (-not (Test-Path $ifco)) { New-Item -Path $ifco -Force | Out-Null }
        Set-ItemProperty -Path $ifco -Name GlobalFlag -Value 0x200 -Type DWord
        $undo += "Remove-Item -Path '$ifco' -Recurse -Force"
    } else {
        if (Test-Path $ifco) { Remove-Item -Path $ifco -Recurse -Force }
    }
}
function SHOW([string]$tag) {
    $g = (Get-ItemProperty -Path $ifco -Name GlobalFlag -ErrorAction SilentlyContinue).GlobalFlag
    Write-Output ("[$tag] IFEO GlobalFlag=" + $g)
}
ARM 'off'; ARM 'on'; SHOW 'armed'

Write-Output '--- POSITIVE CONTROL (in-bounds write must pass, +0x100 write must fault)'
Copy-Item 'C:\Users\nonoge\Documents\olkb\sav\h_benign.msg' 'C:\crtf\base1.msg' -Force
$env:CRTF_BASEMSG = 'C:\crtf\base1.msg'
$env:CRTF_MODS = 'all'; $env:CRTF_RESCAN = '0'; $env:CRTF_RUN = ''
$e = & C:\crtf\crtfbench53_x64.exe selftest 2>&1
Write-Output ($e -join "`n")
Write-Output ('control_exit=' + $LASTEXITCODE)

$env:CRTF_MODS = 'all'; $env:CRTF_RESCAN = '25'
foreach ($m in @('11', '41', '43', '5')) {
    $env:CRTF_RUN = $m
    $cor = if ($m -eq '43') { 'ess43.txt' } elseif ($m -eq '41') { 'attr5.txt' } else { 'tnef2.txt' }
    Copy-Item 'C:\Users\nonoge\Documents\olkb\sav\h_benign.msg' 'C:\crtf\base1.msg' -Force
    $env:CRTF_BASEMSG = 'C:\crtf\base1.msg'
    $o = & C:\crtf\crtfbench53_x64.exe "C:\crtf\$cor" 2 256 52 180000 2>&1
    $o | Set-Content -Encoding utf8 "C:\crtf\ph_m$m.txt"
    $s = @($o | Select-String 'EXC|AV |TPROG|TNEFCASES|ATTRCASES|ESS43|HOOKSTAT|WATCHDOG' | Select-Object -Last 8 | ForEach-Object { $_.Line })
    Write-Output ("=== mode " + $m + " lines=" + $o.Count)
    Write-Output ($s -join "`n")
}
SHOW 'before-undo'
foreach ($u in $undo) { Write-Output ('UNDO: ' + $u) }
