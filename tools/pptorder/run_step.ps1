$ErrorActionPreference='Continue'
New-Item -ItemType Directory -Force -Path C:\pptorder\out | Out-Null
Copy-Item tools\pptorder\cdb_cmd.txt C:\pptorder\cdb_cmd.txt -Force
Copy-Item carriers\timing_sample2.pptx C:\pptorder\timing_sample2.pptx -Force
$c = Get-ChildItem 'C:\Program Files\WindowsApps' -Directory -Filter 'Microsoft.WinDbg*' -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem $_.FullName -Recurse -Filter cdb.exe -ErrorAction SilentlyContinue | Where-Object {$_.DirectoryName -match 'amd64'} } | Select-Object -First 1
if (-not $c) {
  winget install Microsoft.WinDbg --accept-source-agreements --accept-package-agreements --disable-interactivity
  $c = Get-ChildItem 'C:\Program Files\WindowsApps' -Directory -Filter 'Microsoft.WinDbg*' -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem $_.FullName -Recurse -Filter cdb.exe -ErrorAction SilentlyContinue | Where-Object {$_.DirectoryName -match 'amd64'} } | Select-Object -First 1
}
if (-not $c) { throw "cdb not found" }
New-Item -ItemType Directory -Force -Path C:\pptorder\dbg | Out-Null
Copy-Item $c.FullName C:\pptorder\dbg\cdb.exe
Get-ChildItem $c.DirectoryName -Filter *.dll | Copy-Item -Destination C:\pptorder\dbg\ -Force
Start-Process -FilePath 'C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE' -WindowStyle Hidden
Start-Sleep -Seconds 45
$pp = Get-Process POWERPNT -ErrorAction SilentlyContinue | Select-Object -First 1
$p = Start-Process -FilePath C:\pptorder\dbg\cdb.exe -ArgumentList '-p',$pp.Id,'-logo','C:\pptorder\out\cdb_order.log','-cf','C:\pptorder\cdb_cmd.txt' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 30
$job = Start-Process -FilePath powers.exe -ArgumentList '-Command','New-Object -ComObject PowerPoint.Application | Out-Null; $app=[Runtime.InteropServices.Marshal]::GetActiveObject(\"PowerPoint.Application\"); $app.Presentations.Open(\"C:\pptorder\timing_sample2.pptx\",$true,$false,$false) | Out-Null' -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 60
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
(Get-Process POWERPNT -ErrorAction SilentlyContinue).MainWindowTitle | Out-File C:\pptorder\out\title.txt
