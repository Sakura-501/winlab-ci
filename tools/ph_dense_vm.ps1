$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\crtfbench56_x64.exe'
if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
New-ItemProperty -Path $k -Name GlobalFlag -Value 0x02000000 -PropertyType DWord -Force | Out-Null
Write-Output ('reg_GlobalFlag=' + (Get-ItemProperty $k).GlobalFlag)
$exe = 'C:\crtf\crtfbench56_x64.exe'
Write-Output '--- POSITIVE CONTROL (writes 1 byte past a 0x100 process-heap block)'
Remove-Item C:\crtf\ph_ctl.txt -Force -EA SilentlyContinue
$c = & $exe selftest 2>&1
Write-Output ('control_exit=0x{0:X8}' -f $LASTEXITCODE)
Write-Output (($c | ForEach-Object { "$_" }) -join "`n")
Copy-Item 'C:\Users\nonoge\Documents\olkb\sav\h_benign.msg' 'C:\crtf\base1.msg' -Force
$env:CRTF_BASEMSG = 'C:\crtf\base1.msg'
$env:CRTF_MODS = 'all'
$env:CRTF_RESCAN = '200'
$env:CRTF_GUARD = '0'
$env:CRTF_RUN = '11'
$o = & $exe C:\crtf\dense.txt 2 256 52 300000 2>&1
$o | Set-Content -Encoding utf8 C:\crtf\ph_dense.txt
Write-Output ('dense lines=' + $o.Count + ' exit=0x{0:X8}' -f $LASTEXITCODE)
(($o | Select-String '!!!AV|!!!EXC|TPROG|TNEFCASES|HOOKSTAT|WATCHDOG' | Select-Object -Last 10 | ForEach-Object { $_.Line }) -join "`n") | Write-Output
$a = @($o | Select-String 'CODE:|TGTBYTES:|RAX=' | Select-Object -First 3 | ForEach-Object { $_.Line })
if ($a.Count) { Write-Output ($a -join "`n") }
Remove-Item $k -Recurse -Force -EA SilentlyContinue
Write-Output ('key_removed=' + (-not (Test-Path $k)))
