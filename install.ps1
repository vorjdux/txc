<#
.SYNOPSIS
    txc installer for Windows.

.DESCRIPTION
    Downloads the released archive for this machine, checks it against the
    published SHA256SUMS, and puts txc.exe somewhere on the PATH.

.EXAMPLE
    irm https://raw.githubusercontent.com/vorjdux/txc/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Version 0.3.0 -InstallDir C:\tools\bin
#>
[CmdletBinding()]
param(
    # Version to install, without the v prefix. Defaults to the latest release.
    [string]$Version,
    # Where txc.exe goes. Defaults to a per user directory needing no elevation.
    [string]$InstallDir,
    # Download without checking the published checksum. Not recommended.
    [switch]$Insecure,
    # Report what would happen and change nothing.
    [switch]$DryRun,
    # Leave the PATH alone.
    [switch]$NoModifyPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'vorjdux/txc'
$Binary = 'txc.exe'

function Write-Info { param($Message) Write-Host $Message -ForegroundColor White }
function Write-Ok   { param($Message) Write-Host "ok $Message" -ForegroundColor Green }
function Write-Warn { param($Message) Write-Warning $Message }

function Get-Architecture {
    # PROCESSOR_ARCHITECTURE reports the emulated architecture inside a 32 bit
    # shell, so the OS architecture is asked for directly.
    switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        'X64'   { return 'x86_64' }
        'Arm64' { return 'arm64' }
        default {
            throw "unsupported architecture: $_. Try: cargo install txc"
        }
    }
}

function Get-LatestVersion {
    Write-Info 'Looking up the latest release'
    $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
    return $release.tag_name -replace '^v', ''
}

function Add-ToUserPath {
    param([string]$Directory)

    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if ($current) { $entries = $current -split ';' }
    if ($entries -contains $Directory) { return }

    $updated = (@($entries | Where-Object { $_ }) + $Directory) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $updated, 'User')
    # The change reaches new shells only, so make this one work straight away.
    $env:Path = "$env:Path;$Directory"
    Write-Ok "added $Directory to your PATH, open a new terminal for it to take effect elsewhere"
}

# ── Work out what to fetch ─────────────────────────────────────────────────
$arch = Get-Architecture
if (-not $Version) { $Version = Get-LatestVersion }
$Version = $Version -replace '^v', ''
if (-not $Version) { throw 'cannot determine the version to install; pass -Version x.y.z' }

if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\txc'
}

$archive = "txc-$Version-windows-$arch.zip"
$base = "https://github.com/$Repo/releases/download/v$Version"

Write-Info "txc $Version for windows/$arch"
Write-Info "Installing into $InstallDir"

if ($DryRun) {
    Write-Host "  would download $base/$archive"
    Write-Ok 'dry run complete, nothing was changed'
    exit 0
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("txc-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $temp -Force | Out-Null

try {
    $archivePath = Join-Path $temp $archive
    Write-Info "Downloading $archive"
    Invoke-WebRequest -Uri "$base/$archive" -OutFile $archivePath -UseBasicParsing

    if (-not $Insecure) {
        try {
            $sumsPath = Join-Path $temp 'SHA256SUMS'
            Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing
            Write-Info 'Verifying checksum'
            $line = Get-Content $sumsPath | Where-Object { $_ -match [regex]::Escape($archive) + '$' }
            if (-not $line) { throw "$archive is not listed in SHA256SUMS" }
            $expected = ($line -split '\s+')[0]
            $actual = (Get-FileHash $archivePath -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $expected.ToLower()) {
                throw "checksum mismatch for $archive"
            }
            Write-Ok 'checksum verified'
        } catch [System.Net.WebException] {
            Write-Warn 'SHA256SUMS is not published for this release, skipping verification'
        }
    }

    Expand-Archive -Path $archivePath -DestinationPath $temp -Force
    $binary = Get-ChildItem -Path $temp -Filter $Binary -Recurse | Select-Object -First 1
    if (-not $binary) { throw "the archive does not contain $Binary" }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item $binary.FullName (Join-Path $InstallDir $Binary) -Force
    Write-Ok "installed $(Join-Path $InstallDir $Binary)"

    if (-not $NoModifyPath) { Add-ToUserPath $InstallDir }

    Write-Host ''
    & (Join-Path $InstallDir $Binary) --version
    Write-Host ''
    Write-Host '  txc            open the interactive interface'
    Write-Host '  txc list       every operation'
    Write-Host '  txc --help     usage'
    Write-Host ''
    Write-Host '  PowerShell completions:'
    Write-Host '    txc completions powershell | Out-String | Invoke-Expression'
}
finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}
