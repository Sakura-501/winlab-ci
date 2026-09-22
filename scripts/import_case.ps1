param([string]$File, [int]$WaitSec = 25, [string]$Tag = 'case')
# One /eml import attempt: launch OUTLOOK on a single-tenant runner, poll until OUTLMIME is mapped
# (that is the proof the MIME/TNEF importer ran), and report exit vs alive vs AV.
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$exe = 'C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE'
Get-Process OUTLOOK -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 300
$p = Start-Process -FilePath $exe -ArgumentList @('/eml', '"' + $File + '"') -PassThru
$loaded = 0; $alive = 0; $av = 0; $to = 0; $code = '-'
$deadline = (Get-Date).AddSeconds($WaitSec)
$seenOlk = 0
while ((Get-Date) -lt $deadline) {
    $q = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
    if (-not $q) { break }
    if (-not $seenOlk) {
        try {
            foreach ($m in $q.Modules) {
                if ($m.ModuleName -match 'OUTLMIME|OLMAPI32') { $loaded = 1; $seenOlk = 1; break }
            }
        } catch { }
    }
    Start-Sleep -Milliseconds 400
}
if ($p.WaitForExit(1)) {
    $code = '0x{0:X8}' -f ($p.ExitCode -band [int]0xFFFFFFFF)
    if ($code -eq '0xC0000005' -or $code -eq '0xC0000409' -or $code -eq '0x80000003') { $av = 1 }
    $alive = 0
} else {
    $alive = 1
    $code = 'alive'
    if ((Get-Date) -ge $deadline) { $to = 1 }
    Get-Process -Id $p.Id -ErrorAction SilentlyContinue | Stop-Process -Force
}
Get-Process OUTLOOK -ErrorAction SilentlyContinue | Stop-Process -Force
$line = "$Tag file=$([IO.Path]::GetFileName($File)) mime_loaded=$loaded alive=$alive av=$av code=$code timeout=$to"
Set-Content -Path out\last_case.txt -Value $line
Write-Output $line
