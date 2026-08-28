<#
.SYNOPSIS
  Improved leakscan PowerShell installer with verification and options.

.DESCRIPTION
  Downloads a release from GitHub Releases and installs the leakscan binary
  to %USERPROFILE%\.leakscan\bin by default. Supports pinned tags, dry-run,
  uninstall, checksum verification, optional cosign verification, and best-effort
  PATH update. Run with -Help for options.
#>
param(
  [string]$Repo = "zeexz/leakscan",
  [string]$Tag = "latest",
  [string]$InstallDir = "$env:USERPROFILE\.leakscan\bin",
  [switch]$DryRun,
  [switch]$Uninstall,
  [switch]$NoPath,
  [switch]$VerifyCosign,
  [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

function Write-Info([string]$m) { if (-not $Quiet) { Write-Host "[info] $m" -ForegroundColor Cyan } }
function Write-Step([string]$m) { if (-not $Quiet) { Write-Host "  → $m" -ForegroundColor DarkGray } }
function Write-Ok([string]$m) { if (-not $Quiet) { Write-Host "[ok] $m" -ForegroundColor Green } }
function Write-Warn([string]$m) { Write-Host "[warn] $m" -ForegroundColor Yellow }
function Write-Err([string]$m) { Write-Host "[error] $m" -ForegroundColor Red; exit 1 }

function Get-Architecture() {
  $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
  switch ($arch) {
    'X64' { 'amd64' }
    'Arm64' { 'arm64' }
    'X86' { '386' }
    default { Write-Err "Unsupported arch: $arch" }
  }
}

function Get-LatestRelease([string]$Repo, [string]$Tag) {
  if ($Tag -eq 'latest') {
    $url = "https://api.github.com/repos/$Repo/releases/latest"
  } else {
    $url = "https://api.github.com/repos/$Repo/releases/tags/$Tag"
  }
  $headers = @{ 'Accept' = 'application/vnd.github.v3+json' }
  if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
  try { Invoke-RestMethod -Uri $url -Headers $headers -UseBasicParsing } catch { Write-Err "Failed to fetch release metadata: $_" }
}

function Find-Asset($release, $os, $arch) {
  # prefer matching os+arch in name, otherwise any asset with 'leakscan' in name
  foreach ($a in $release.assets) {
    if ($a.name -match "$os" -and $a.name -match "$arch" -and $a.name -match '\.(zip|tar.gz|exe)$') { return $a }
  }
  foreach ($a in $release.assets) { if ($a.name -match 'leakscan' -and $a.name -match '\.(zip|tar.gz|exe)$') { return $a } }
  return $null
}

function Find-VerificationAssets($release, $assetName) {
  $sig = $null; $cert = $null; $checksum = $null
  foreach ($a in $release.assets) {
    if ($a.name -match [regex]::Escape($assetName) -and $a.name -match '\.sha256') { $checksum = $a }
    if ($a.name -match [regex]::Escape($assetName) -and $a.name -match '\.sig$') { $sig = $a }
    if ($a.name -match [regex]::Escape($assetName) -and $a.name -match '\.(pem|crt)$') { $cert = $a }
  }
  return @{ checksum = $checksum; sig = $sig; cert = $cert }
}

function Verify-Checksum($checksumUrl, $filePath) {
  $tmp = [System.IO.Path]::GetTempFileName()
  try { Invoke-WebRequest -Uri $checksumUrl -OutFile $tmp -UseBasicParsing } catch { Write-Warn "Failed to download checksum"; return $false }
  $expected = Get-Content $tmp | Select-Object -First 1 | ForEach-Object { ($_ -split '\s+')[0] }
  if (-not $expected) { Write-Warn "Checksum file empty or unparsable"; return $false }
  $hash = Get-FileHash -Path $filePath -Algorithm SHA256
  if ($hash.Hash -eq $expected) { Write-Ok "Checksum OK"; return $true } else { Write-Err "Checksum mismatch: expected $expected, got $($hash.Hash)" }
}

function Verify-Cosign($sigUrl, $certUrl, $filePath) {
  if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) { Write-Warn "cosign not installed"; return $false }
  $tmpDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([guid]::NewGuid().ToString())
  New-Item -ItemType Directory -Path $tmpDir | Out-Null
  try {
    $sigFile = Join-Path $tmpDir 'asset.sig'
    $certFile = Join-Path $tmpDir 'asset.pem'
    Invoke-WebRequest -Uri $sigUrl -OutFile $sigFile -UseBasicParsing
    Invoke-WebRequest -Uri $certUrl -OutFile $certFile -UseBasicParsing
    $args = @('verify-blob', '--signature', $sigFile, '--certificate', $certFile, $filePath)
    $res = & cosign @args 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Ok 'cosign verification OK'; return $true } else { Write-Err "cosign verify failed: $res" }
  } finally { Remove-Item -Recurse -Force $tmpDir }
}

function Add-ToPath($installDir) {
  if ($NoPath) { Write-Info 'Skipping PATH update (--NoPath)'; return }
  $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
  if ($userPath -and $userPath -like "*${installDir}*") { Write-Info 'Install dir already on PATH'; return }
  # Best-effort: set user PATH
  $newPath = if ($userPath) { $userPath + ';' + $installDir } else { $installDir }
  [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
  Write-Ok "Appended $installDir to user PATH. Restart your shell to pick up changes."
}

# MAIN
if ($Uninstall) {
  if (Test-Path (Join-Path $InstallDir 'leakscan.exe')) {
    if ($DryRun) { Write-Info "Would remove $InstallDir\leakscan.exe" } else { Remove-Item -Force -Path (Join-Path $InstallDir 'leakscan.exe'); Write-Ok 'Removed binary' }
  } else { Write-Warn 'No installation found' }
  exit 0
}

$os = 'windows'; $arch = Get-Architecture
Write-Info "Platform: $os/$arch"
Write-Info "Install dir: $InstallDir"
Write-Info "Tag: $Tag"

$release = Get-LatestRelease -Repo $Repo -Tag $Tag
$asset = Find-Asset -release $release -os $os -arch $arch
if (-not $asset) { Write-Err "No release asset found for $os/$arch" }
Write-Step "Selected asset: $($asset.name)"

$ver = Find-VerificationAssets -release $release -assetName $asset.name

# Download asset
$tmpDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([guid]::NewGuid().ToString())
if (-not $DryRun) { New-Item -ItemType Directory -Path $tmpDir | Out-Null }
$assetFile = Join-Path $tmpDir $asset.name
if ($DryRun) { Write-Info "DRY-RUN: would download $($asset.browser_download_url) to $assetFile" } else { Write-Step "Downloading asset..."; Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $assetFile -UseBasicParsing }

# Verify: checksum first
$verified = $false
if ($ver.checksum) {
  Write-Step "Attempting checksum verification..."
  if (-not $DryRun) { $verified = Verify-Checksum -checksumUrl $ver.checksum.browser_download_url -filePath $assetFile }
}
if (-not $verified -and $VerifyCosign -and $ver.sig -and $ver.cert) {
  Write-Step 'Attempting cosign verification...'
  if (-not $DryRun) { $verified = Verify-Cosign -sigUrl $ver.sig.browser_download_url -certUrl $ver.cert.browser_download_url -filePath $assetFile }
}
if (-not $verified) { Write-Warn 'No verification succeeded (checksum/cosign may be missing). Proceeding at your risk.' }

# Extract and install
if ($DryRun) { Write-Info "DRY-RUN: would extract and install to $InstallDir"; exit 0 }
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

if ($asset.name -match '\.zip$') {
  Expand-Archive -Path $assetFile -DestinationPath $tmpDir -Force
  $exe = Get-ChildItem -Path $tmpDir -Recurse -Filter '*.exe' | Select-Object -First 1
  if (-not $exe) { Write-Err 'No .exe found in archive' }
  Copy-Item -Path $exe.FullName -Destination (Join-Path $InstallDir 'leakscan.exe') -Force
} elseif ($asset.name -match '\.(tar.gz|tgz)$') {
  # Windows: unlikely; but support for consistency
  Write-Err 'tar.gz install path not implemented on Windows in this script' 
} else {
  Copy-Item -Path $assetFile -Destination (Join-Path $InstallDir 'leakscan.exe') -Force
}
Write-Ok "Installed leakscan to $InstallDir\leakscan.exe"

# PATH
Add-ToPath -installDir $InstallDir

# Verify
try {
  $verOut = & (Join-Path $InstallDir 'leakscan.exe') --version 2>&1
  Write-Ok "Verify: $verOut"
} catch { Write-Warn 'Could not run leakscan --version. Restart shell or open a new terminal.' }

Write-Info 'Done. Run "leakscan scan ." to try a scan.'