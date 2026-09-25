param([string]$Dir = 'carriers',
       [string]$Tag = 'pptrec',
       [string]$Base = '.',
       [int]$WaitSec = 70)
# ppt_sweep.ps1 - POWERPNT + full page heap + WER local dumps over mutated .ppt record headers + WER local dumps over a carrier directory (screening net).
# Runner-only host: no co-tenant Office instance exists, so the PID<->window attribution stays valid (the VM case that broke this on 2026-09-25 was a shared desktop).
# Skeleton: findings/MSRC/M365-Insider/sprm-deleteproperty-memmove-wrap-20260921/tools/pht_sweep.ps1
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$exe = 'C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE'
$base = (Resolve-Path $Base).Path
$dumps = (Join-Path $base 'dumps')
New-Item -ItemType Directory -Force -Path $dumps, (Join-Path $base 'out') | Out-Null
$log = Join-Path $base ('out\' + $Tag + '_log.txt')
Set-Content -Path $log -Value ('session=' + (Get-Process -Id $PID).SessionId) -Encoding ASCII
'pptver=' + (Get-Item $exe).VersionInfo.FileVersion | Add-Content $log

# page heap on, and read the flag back (a stale flag starves the next round)
$g=Get-Command gflags.exe -EA SilentlyContinue; if(-not $g){ foreach($c in @('C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe','C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\gflags.exe')){ if(Test-Path $c){ $g=Get-Item $c; break } } }; if(-not $g){ 'NO_GFLAGS' | Add-Content $log }
else { & $g.FullName /p /enable POWERPNT.EXE /full | Out-Null }
$gf = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\POWERPNT.EXE' -Name GlobalFlag -EA SilentlyContinue).GlobalFlag
('gflags_applied GlobalFlag=' + $gf) | Add-Content $log

$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\POWERPNT.EXE\LocalDumps'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name DumpFolder -Value $dumps -Type ExpandString
Set-ItemProperty -Path $k -Name DumpType -Value 2 -Type DWord
Set-ItemProperty -Path $k -Name DumpCount -Value 40 -Type DWord

# MOTW before opening (AGENTS 62): real delivery condition
$files = @(Get-ChildItem $Dir -File | Where-Object { $_.Extension -in '.ppt' } | Sort-Object Name)
'cases=' + $files.Count | Add-Content $log
foreach ($f in $files) {
    Set-Content -Path $f.FullName -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII
    $z = @(Get-Content $f.FullName -Stream Zone.Identifier -EA SilentlyContinue) -join ';'
    $before = @(Get-ChildItem $dumps -Filter *.dmp -EA SilentlyContinue | ForEach-Object { $_.Name })
    $t0 = Get-Date
    $state = 'timeout'; $title = ''
    try {
        $p = Start-Process -FilePath $exe -ArgumentList @(('"' + $f.FullName + '"'), ('"' + $f.FullName + '"')) -PassThru
    } catch {
        ('{0,-30} LAUNCH_FAIL {1}' -f $f.Name, $_.Exception.Message) | Add-Content $log
        continue
    }
    for ($i = 0; $i * 2 -lt $WaitSec; $i++) {
        Start-Sleep -Seconds 2
        $q = Get-Process -Id $p.Id -EA SilentlyContinue
        if (-not $q) { $state = 'exited'; break }
        $title = $q.MainWindowTitle
        if ($title -and ($title -like ('*' + $f.BaseName + '*'))) { $state = 'opened'; break }
        $now = @(Get-ChildItem $dumps -Filter *.dmp -EA SilentlyContinue | ForEach-Object { $_.Name })
        if ($now.Count -gt $before.Count) { $state = 'dump'; break }
    }
    $d = @(Get-ChildItem $dumps -Filter *.dmp -EA SilentlyContinue | Where-Object { $_.LastWriteTime -gt $t0 } | ForEach-Object { $_.Name + ':' + $_.Length })
    ('{0,-30} state={1,-8} title={2} dumps={3} motw={4}' -f $f.Name, $state, $title, ($d -join ','), $z) | Add-Content $log
    ('SUMMARY {0} state={1} dumps={2}' -f $f.Name, $state, $d.Count) | Add-Content (Join-Path $base ('out\' + $Tag + '_index.txt'))
    Get-Process -Id $p.Id -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
}
if($g){ & $g.FullName /p /disable POWERPNT.EXE | Out-Null }
$gf2 = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\POWERPNT.EXE' -Name GlobalFlag -EA SilentlyContinue).GlobalFlag
('gflags_disabled GlobalFlag=' + $gf2) | Add-Content $log
'dump_total=' + @(Get-ChildItem $dumps -Filter *.dmp -EA SilentlyContinue).Count | Add-Content $log
'ALLDONE'
