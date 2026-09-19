$ErrorActionPreference='Continue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
$root='C:\Program Files\Microsoft Office\root\Office16'
$work='C:\emfwork'
$cdb="$work\dbg\cdb.exe"
function Log($m){ $m | Tee-Object -FilePath "$work\out\r14.txt" -Append }
New-Item -ItemType Directory -Force -Path "$work\out" | Out-Null
Remove-Item "$work\out\r14.txt" -Force -ErrorAction SilentlyContinue
Log "start $(Get-Date -Format o)"

# ---- phase 0: generate runtime-resolved breakpoint config ----
python "$work\tools\mkbps14.py" | Out-Null
Log "bps file: $((Get-Content "$work\dbgcmd14.txt" -ErrorAction SilentlyContinue) -join ' ;; ')"

# ---- phase A: build canvas docx with evil EMF (no cdb) ----
Get-Process WINWORD,cdb -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 3
$w=New-Object -ComObject Word.Application
$w.Visible=$false; $w.DisplayAlerts=0
$d=$w.Documents.Add()
try{
  $cv=$d.Shapes.AddCanvas(100,100,400,300)
  $pic=$cv.CanvasItems.AddPicture("$work\evil.emf")
  Log "canvas addpic ok"
}catch{ Log "canvas build fail: $($_.Exception.Message)" }
try{
  $d.SaveAs2("$work\canvas_evil.docx",16)
  Log "canvas saved $((Get-Item "$work\canvas_evil.docx" -ErrorAction SilentlyContinue).Length)"
}catch{ Log "save fail: $($_.Exception.Message)" }
$d.Close(0)
$w.Quit()
Start-Sleep -Seconds 3

# ---- phase A2: icon-mode OLE docx, then patch its cached EMF with evil ----
try{
  $w=New-Object -ComObject Word.Application
  $w.Visible=$false; $w.DisplayAlerts=0
  $d=$w.Documents.Add()
  $ole=$d.OLEObjects.Add($true,$false,[Type]::Missing,"$work\seed.txt",$true,"C:\Windows\System32\shell32.dll",0,'Seed Icon')
  Log "ole icon added"
  $d.SaveAs2("$work\oleicon_src.docx",16)
  $d.Close(0); $w.Quit()
  Start-Sleep -Seconds 2
  Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
  $zin=[System.IO.Compression.ZipFile]::OpenRead("$work\oleicon_src.docx")
  $emfs=@($zin.Entries | Where-Object { $_.FullName -like '*.emf' })
  $zin.Dispose()
  Log "oleicon emf parts: $($emfs.Count)"
  if($emfs.Count -gt 0){
    $evil=[System.IO.File]::ReadAllBytes("$work\evil.emf")
    $zin=[System.IO.Compression.ZipFile]::Open("$work\oleicon_src.docx",'Update')
    foreach($e in @($zin.Entries | Where-Object { $_.FullName -like '*.emf' })){
      $fn=$e.FullName
      $e.Delete()
      $ne=$zin.CreateEntry($fn)
      $s=$ne.Open(); $s.Write($evil,0,$evil.Length); $s.Close()
    }
    $zin.Dispose()
    Copy-Item "$work\oleicon_src.docx" "$work\oleicon_evil.docx" -Force
    Log "oleicon_evil packed $((Get-Item "$work\oleicon_evil.docx").Length)"
  }
}catch{ Log "phase A2 fail: $($_.Exception.Message)" }

# ---- phase B: cdb-launched Word opens canvas docx (restore path) ----
function ProbeWithCdb($exe,$args_,$tag,$actionBody,$waitOpen=60){
  Get-Process WINWORD,POWERPNT,cdb -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 4
  Remove-Item 'HKCU:\Software\Microsoft\Office\16.0\Word\Resiliency' -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item 'HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Resiliency' -Recurse -Force -ErrorAction SilentlyContinue
  $log="$work\out\r14_$tag.log"
  Start-Process -FilePath $cdb -ArgumentList "-G","-logo","`"$log`"","-cf","`"$work\dbgcmd14.txt`"","`"$exe`"","/w",($args_ -join ' ') -WindowStyle Hidden | Out-Null
  Start-Sleep -Seconds $waitOpen
  if($actionBody){
    $ab = "$work\act_$tag.ps1"
    Set-Content -Path $ab -Value $actionBody -Encoding UTF8
    $r = & powershell -NoProfile -ExecutionPolicy Bypass -File $ab 2>&1
    Log "[$tag] action: $($r | Out-String)"
    Start-Sleep -Seconds 30
  }
  $c=Get-Content $log -ErrorAction SilentlyContinue
  $hits=@{}
  foreach($ln in $c){ if($ln -match '^===HIT_|^===AV==='){ $hits[$ln]=1+$hits[$ln] } }
  $unres=($c | Select-String -SimpleMatch 'Unable to resolve').Count
  $alive=(Get-Process WINWORD,POWERPNT -ErrorAction SilentlyContinue).Count
  Log "[$tag] unres=$unres alive=$alive hits=$(($hits.GetEnumerator()|ForEach-Object{"$($_.Key)=$($_.Value)"}) -join ', ')"
  # register dumps for fread/icon hits
  for($i=0;$i -lt $c.Count;$i++){
    if($c[$i] -match '^===HIT_(mso_fread|wwlib_icon_cb)'){ Log ("  " + ($c[$i..[Math]::Min($i+3,$c.Count-1)] -join ' | ')) }
  }
  Get-Process cdb -ErrorAction SilentlyContinue | Stop-Process -Force
  Get-Process WINWORD,POWERPNT -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 3
}

# B1: reopen canvas docx (DG blip restore)
ProbeWithCdb "$root\WINWORD.EXE" @("$work\canvas_evil.docx") 'canvas_reopen' $null 70
# B2: icon-mode OLE docx reopen
ProbeWithCdb "$root\WINWORD.EXE" @("$work\oleicon_evil.docx") 'icon_reopen' $null 70
# B3: canvas addpic under live cdb (same-process COM via child script that uses New-Object? no: action attaches to running Word through UIAutomation-free COM by pid)
$act = @'
$ErrorActionPreference='Continue'
$w=[Runtime.InteropServices.Marshal]::GetActiveObject('Word.Application')
$w.DisplayAlerts=0
$d=$w.Documents.Add()
$cv=$d.Shapes.AddCanvas(100,100,400,300)
$pic=$cv.CanvasItems.AddPicture('C:\emfwork\evil.emf')
"addpic ok"
try{ $d.SaveAs2('C:\emfwork\canvas_live.docx',16); "saved" }catch{ "save: $($_.Exception.Message)" }
'@
ProbeWithCdb "$root\WINWORD.EXE" @('/n') 'canvas_live' $act 40
Log "done $(Get-Date -Format o)"
