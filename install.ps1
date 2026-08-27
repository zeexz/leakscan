<#
.SYNOPSIS
    Install leakscan CLI on Windows via PowerShell one-liner.

.DESCRIPTION
    Downloads the latest leakscan release from GitHub Releases,
    installs it to ~\.leakscan\bin, and adds that directory to your
    user PATH so you can run 'leakscan' from any terminal.

.EXAMPLE
    iex (irm https://raw.githubusercontent.com/zeexz/secret-leak-scanner/main/install.ps1)
#>

$ErrorActionPreference = "Stop"

# ── Configuration ─────────────────────────────────────────────────
$REPO          = "zeexz/secret-leak-scanner"
$BINARY_NAME   = "leakscan.exe"
$INSTALL_DIR   = Join-Path $env:USERPROFILE ".leakscan\bin"
$GITHUB_API    = "https://api.github.com/repos/$REPO/releases/latest"
# ──────────────────────────────────────────────────────────────────

function Write-Banner {
    $purple = "`e[35m"
    $cyan   = "`e[36m"
    $blue   = "`e[34m"
    $reset  = "`e[0m"
    $bold   = "`e[1m"

    Write-Host ""
    Write-Host "  ${bold}${purple}⚡ LEAKSCAN INSTALLER ⚡${reset}"
    Write-Host "  ${cyan}Secrets & Credential Leak Scanner${reset}"
    Write-Host "  ${blue}────────────────────────────────────${reset}"
    Write-Host ""
}

function Get-Architecture {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"   { return "amd64" }
        "Arm64" { return "arm64" }
        "X86"   { return "386" }
        default {
            Write-Error "Unsupported architecture: $arch"
            exit 1
        }
    }
}

function Get-LatestRelease {
    Write-Host "  → Fetching latest release from GitHub..." -ForegroundColor DarkGray

    try {
        $headers = @{ "Accept" = "application/vnd.github.v3+json" }
        if ($env:GITHUB_TOKEN) {
            $headers["Authorization"] = "Bearer $env:GITHUB_TOKEN"
        }

        $release = Invoke-RestMethod -Uri $GITHUB_API -Headers $headers
        return $release
    }
    catch {
        Write-Error "Failed to fetch latest release. Check your network connection and repo URL."
        Write-Error "API URL: $GITHUB_API"
        Write-Error "Error: $_"
        exit 1
    }
}

function Find-Asset {
    param (
        [Parameter(Mandatory)] $Release,
        [Parameter(Mandatory)] [string] $Arch
    )

    $pattern = "leakscan.*windows.*${Arch}"

    foreach ($asset in $Release.assets) {
        if ($asset.name -match $pattern -and $asset.name -match '\.(zip|exe)$') {
            return $asset
        }
    }

    # Fallback: try to find any windows asset
    foreach ($asset in $Release.assets) {
        if ($asset.name -match "windows" -and $asset.name -match '\.(zip|exe)$') {
            return $asset
        }
    }

    Write-Error "No compatible asset found for Windows $Arch in release $($Release.tag_name)"
    Write-Error "Available assets:"
    foreach ($asset in $Release.assets) {
        Write-Error "  - $($asset.name)"
    }
    exit 1
}

function Install-LeakScan {
    Write-Banner

    $arch = Get-Architecture
    Write-Host "  ● Platform:     Windows ($arch)" -ForegroundColor Cyan
    Write-Host "  ● Install Dir:  $INSTALL_DIR" -ForegroundColor Cyan
    Write-Host ""

    # Step 1: Get latest release info
    $release = Get-LatestRelease
    $version = $release.tag_name
    Write-Host "  ● Version:      $version" -ForegroundColor Green
    Write-Host ""

    # Step 2: Find the correct binary asset
    $asset = Find-Asset -Release $release -Arch $arch
    Write-Host "  → Downloading $($asset.name)..." -ForegroundColor DarkGray

    # Step 3: Create install directory
    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    }

    # Step 4: Download to a temp location
    $tempDir  = Join-Path ([System.IO.Path]::GetTempPath()) "leakscan-install"
    $tempFile = Join-Path $tempDir $asset.name

    if (Test-Path $tempDir) {
        Remove-Item -Recurse -Force $tempDir
    }
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    $headers = @{}
    if ($env:GITHUB_TOKEN) {
        $headers["Authorization"] = "Bearer $env:GITHUB_TOKEN"
    }
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tempFile -Headers $headers -UseBasicParsing

    # Step 5: Extract or copy binary
    $destBinary = Join-Path $INSTALL_DIR $BINARY_NAME

    if ($asset.name -match '\.zip$') {
        Write-Host "  → Extracting archive..." -ForegroundColor DarkGray
        Expand-Archive -Path $tempFile -DestinationPath $tempDir -Force

        # Find the .exe inside the extracted archive
        $exe = Get-ChildItem -Path $tempDir -Recurse -Filter "*.exe" | Select-Object -First 1
        if (-not $exe) {
            Write-Error "No .exe found inside the downloaded archive."
            exit 1
        }
        Copy-Item -Path $exe.FullName -Destination $destBinary -Force
    }
    else {
        # Direct .exe download
        Copy-Item -Path $tempFile -Destination $destBinary -Force
    }

    # Cleanup temp
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue

    # Step 6: Add to PATH if not already present
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notlike "*$INSTALL_DIR*") {
        Write-Host "  → Adding to user PATH..." -ForegroundColor DarkGray
        [Environment]::SetEnvironmentVariable("PATH", "$userPath;$INSTALL_DIR", "User")
        $env:PATH = "$env:PATH;$INSTALL_DIR"
    }

    # Step 7: Verify installation
    Write-Host ""
    Write-Host "  ✅ leakscan $version installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  ● Binary:  $destBinary" -ForegroundColor Cyan
    Write-Host ""

    # Quick verify
    try {
        $versionOutput = & $destBinary --version 2>&1
        Write-Host "  ● Verify:  $versionOutput" -ForegroundColor Green
    }
    catch {
        Write-Host "  ⚠ Could not verify. You may need to restart your terminal." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  Restart your terminal, then run:               │" -ForegroundColor DarkGray
    Write-Host "  │                                                 │" -ForegroundColor DarkGray
    Write-Host "  │    leakscan scan .                              │" -ForegroundColor Cyan
    Write-Host "  │    leakscan tui                                 │" -ForegroundColor Cyan
    Write-Host "  │                                                 │" -ForegroundColor DarkGray
    Write-Host "  └─────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
}

# Run installer
Install-LeakScan
