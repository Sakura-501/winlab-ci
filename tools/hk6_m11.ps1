$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:CRTF_MODS = 'all'
$env:CRTF_RESCAN = '1'
$env:CRTF_RUN = '11'
Remove-Item Env:\CRTF_NMAX -ErrorAction SilentlyContinue
Copy-Item 'C:\Users\nonoge\Documents\olkb\sav\h_benign.msg' 'C:\crtf\base1.msg' -Force
$env:CRTF_BASEMSG = 'C:\crtf\base1.msg'
$o = & C:\crtf\crtfbench53_x64.exe C:\crtf\tnef2.txt 2 256 52 120000 2>&1
$o | Set-Content -Encoding utf8 C:\crtf\hk6_m11.txt
Write-Output ('total_lines=' + $o.Count)
Write-Output ('TBASEMSG: ' + (($o | Select-String 'TBASEMSG') | ForEach-Object { $_.Line }))
Write-Output ('summary: ' + (($o | Select-String 'TNEFCASES|TPROG' | Select-Object -Last 2) | ForEach-Object { $_.Line }))
Write-Output ('HOOKSTAT: ' + (($o | Select-String 'HOOKSTAT') | ForEach-Object { $_.Line }))
Write-Output ('DUP lines=' + @($o | Select-String 'DUPFREE').Count + '  SITE lines:')
$o | Select-String 'DUPFREE|DUPSITE' | ForEach-Object { $_.Line } | Select-Object -First 25
$u = @($o | Select-String 'UNTSITE' | ForEach-Object { $_.Line } | Sort-Object -Unique | Select-Object -First 15)
Write-Output ('UNTSITE distinct: ' + ($u -join ' ; '))
$e = @($o | Select-String 'EXC|AV ' | Select-Object -First 4 | ForEach-Object { $_.Line })
Write-Output ('EXC: ' + ($e -join ' ; '))
