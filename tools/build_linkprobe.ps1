$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$proj = Join-Path $root "linkprobe"
$out  = Join-Path $root "out"

$sdk = $env:ANDROID_HOME
if (-not $sdk) { $sdk = $env:ANDROID_SDK_ROOT }
Write-Host "ANDROID_HOME=$sdk"

$bt = Get-ChildItem (Join-Path $sdk "build-tools") -Directory | Sort-Object Name -Descending | Select-Object -First 1
$plat = Get-ChildItem (Join-Path $sdk "platforms") -Directory | Sort-Object Name -Descending | Select-Object -First 1
$btDir = $bt.FullName
$androidJar = Join-Path $plat.FullName "android.jar"
Write-Host "build-tools=$btDir"
Write-Host "platform=$plat ($androidJar)"
if (-not (Test-Path $androidJar)) { Write-Host "MISSING android.jar"; exit 2 }

$aapt2 = Join-Path $btDir "aapt2.exe"
$aapt  = Join-Path $btDir "aapt.exe"
$d8    = Join-Path $btDir "d8.bat"
$zipalign = Join-Path $btDir "zipalign.exe"
$apksigner = Join-Path $btDir "apksigner.bat"
$javac = Join-Path $env:JAVA_HOME "bin\javac.exe"
$keytool = Join-Path $env:JAVA_HOME "bin\keytool.exe"
Write-Host "javac=$javac exists=$(Test-Path $javac)  aapt2=$($aapt2) exists=$(Test-Path $aapt2)"

Remove-Item $out -Recurse -Force -EA 0
New-Item -ItemType Directory -Path $out | Out-Null
$classes = Join-Path $out "classes"
New-Item -ItemType Directory -Path $classes | Out-Null

# 1. link manifest into a base apk
$baseApk = Join-Path $out "base.apk"
& $aapt2 link -I $androidJar --manifest (Join-Path $proj "AndroidManifest.xml") -o $baseApk --auto-add-overlay
if ($LASTEXITCODE -ne 0) { Write-Host "aapt2 link failed"; exit 3 }
Write-Host "linked base.apk $((Get-Item $baseApk).Length) bytes"

# 2. compile java
& $javac -source 11 -target 11 -nowarn -classpath $androidJar -d $classes (Join-Path $proj "src\com\example\linkprobe\ProbeActivity.java")
if ($LASTEXITCODE -ne 0) { Write-Host "javac failed"; exit 4 }

# 3. dex
& $d8 --lib $androidJar --min-api 24 --output $out (Join-Path $classes "com\example\linkprobe\ProbeActivity.class")
if ($LASTEXITCODE -ne 0) { Write-Host "d8 failed"; exit 5 }
$dex = Join-Path $out "classes.dex"
if (-not (Test-Path $dex)) { Write-Host "no classes.dex"; exit 6 }
Write-Host "classes.dex $((Get-Item $dex).Length) bytes"

# 4. put dex at apk root
$unaligned = Join-Path $out "unaligned.apk"
Copy-Item $baseApk $unaligned -Force
Push-Location $out
& $aapt add $unaligned classes.dex
Pop-Location
if ($LASTEXITCODE -ne 0) { Write-Host "aapt add failed"; exit 7 }

# 5. align
$unsigned = Join-Path $out "unsigned.apk"
& $zipalign -f 4 $unaligned $unsigned
if ($LASTEXITCODE -ne 0) { Write-Host "zipalign failed"; exit 8 }

# 6. self-signed debug key + sign
$ks = Join-Path $out "probe.keystore"
& $keytool -genkeypair -v -keystore $ks -storepass android -keypass android -alias probe `
    -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=LinkProbe, OU=Dev, O=Example, L=NA, S=NA, C=US" | Out-Null
$final = Join-Path $root "linkprobe.apk"
& $apksigner sign --ks $ks --ks-pass pass:android --key-pass pass:android --out $final $unsigned
if ($LASTEXITCODE -ne 0) { Write-Host "apksigner failed"; exit 9 }

& $apksigner verify --print-certs $final
& $aapt dump badging $final | Select-String -Pattern "package: name|launchable-activity|sdkVersion|targetSdkVersion"
Write-Host "ARTIFACT $final $((Get-Item $final).Length) bytes"
Get-FileHash $final -Algorithm SHA256 | ForEach-Object { "SHA256=$($_.Hash)" }
