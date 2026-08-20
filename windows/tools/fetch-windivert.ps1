<#
.SYNOPSIS
    Downloads WinDivert and places it next to the SplitLane engine.

.DESCRIPTION
    WinDivert is a signed third-party kernel driver. It is deliberately not committed to this
    repository: vendoring a driver binary in source control is a supply-chain decision that should be
    made explicitly, by a person, and not inherited by everyone who clones the repo.

    This script fetches a release from the official GitHub project, verifies the archive against a
    known SHA-256, and copies the 64-bit DLL and .sys into the engine's output directory.

.PARAMETER Version
    WinDivert release to fetch. 2.2.2 is the version SplitLane is written against.

.PARAMETER Destination
    Where to put the binaries. Defaults to the shared runtime folder the engine project copies from,
    so a rebuild picks them up automatically.

.PARAMETER Sha256
    Expected SHA-256 of the archive.

    There is deliberately no default. A hash baked into this file would be a hash nobody checked —
    it would be copied from whatever the script author happened to download, and it would look
    exactly as authoritative when it was wrong as when it was right. The script prints the hash of
    what it fetched; compare that against the WinDivert release page yourself, once, and pass it back
    on subsequent runs so that later downloads are actually verified against something you checked.

.EXAMPLE
    .\fetch-windivert.ps1
    Downloads WinDivert 2.2.2 and prints its SHA-256 for you to verify.

.EXAMPLE
    .\fetch-windivert.ps1 -Sha256 <hash you verified>
    Downloads and refuses to install unless the archive matches.

.NOTES
    Installing the driver still requires administrative rights, but that happens the first time the
    engine opens a divert handle — not here. This script only copies files.
#>
[CmdletBinding()]
param(
    [string]$Version = '2.2.2',
    [string]$Destination = (Join-Path $PSScriptRoot '..\runtime\windivert'),
    [string]$Sha256 = ''
)

$ErrorActionPreference = 'Stop'

$archiveName = "WinDivert-$Version-A.zip"
$url = "https://github.com/basil00/WinDivert/releases/download/v$Version/$archiveName"
$staging = Join-Path ([System.IO.Path]::GetTempPath()) "splitlane-windivert-$Version"
$archive = Join-Path $staging $archiveName

Write-Host "SplitLane :: fetching WinDivert $Version" -ForegroundColor Cyan
Write-Host "  source      $url"
Write-Host "  destination $([System.IO.Path]::GetFullPath($Destination))"
Write-Host ''

New-Item -ItemType Directory -Force -Path $staging | Out-Null
New-Item -ItemType Directory -Force -Path $Destination | Out-Null

if (-not (Test-Path $archive)) {
    Write-Host 'Downloading...'
    # TLS 1.2 has to be requested explicitly on Windows PowerShell 5.1; without it the GitHub
    # release host refuses the connection with an unhelpful "could not create SSL/TLS channel".
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
}

$actual = (Get-FileHash -Path $archive -Algorithm SHA256).Hash

if ($Sha256) {
    if ($actual -ne $Sha256) {
        Write-Host ''
        Write-Warning "SHA-256 mismatch for $archiveName."
        Write-Warning "  expected $Sha256"
        Write-Warning "  actual   $actual"
        Write-Host ''
        Write-Host 'The file is not what you asked for. It may be a different release, or the'
        Write-Host 'download may have been tampered with. Check the WinDivert release page before'
        Write-Host 'going any further.'
        throw 'Refusing to install an unverified kernel driver.'
    }

    Write-Host "SHA-256 verified against the value you supplied: $actual" -ForegroundColor Green
}
else {
    Write-Host ''
    Write-Warning 'No expected hash was supplied, so nothing has been verified.'
    Write-Host ''
    Write-Host "  $archiveName"
    Write-Host "  SHA-256  $actual" -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Compare that against the checksum published with the WinDivert release, then re-run'
    Write-Host 'this script with the value so future downloads are actually checked:'
    Write-Host ''
    Write-Host "  .\fetch-windivert.ps1 -Version $Version -Sha256 $actual" -ForegroundColor Yellow
    Write-Host ''
}

$extracted = Join-Path $staging 'extracted'
if (Test-Path $extracted) { Remove-Item -Recurse -Force $extracted }
Expand-Archive -Path $archive -DestinationPath $extracted -Force

# The archive lays out x86 and x64 side by side; SplitLane is 64-bit only, because WinDivert ships
# no 32-bit driver that loads on a modern 64-bit Windows.
$x64 = Get-ChildItem -Path $extracted -Recurse -Directory | Where-Object { $_.Name -eq 'x64' } | Select-Object -First 1
if (-not $x64) { throw "No x64 directory inside $archiveName." }

$wanted = @('WinDivert.dll', 'WinDivert64.sys')
foreach ($name in $wanted) {
    $source = Join-Path $x64.FullName $name
    if (-not (Test-Path $source)) { throw "$name is missing from the archive." }
    Copy-Item -Path $source -Destination $Destination -Force
    Write-Host "  copied $name"
}

Write-Host ''
Write-Host 'Done. Rebuild the engine so the binaries land beside SplitLane.Engine.exe:' -ForegroundColor Green
Write-Host '  dotnet build windows\src\SplitLane.Engine\SplitLane.Engine.csproj'
Write-Host ''
Write-Host 'Then confirm the machine can actually load it:'
Write-Host '  SplitLane.Engine.exe --check'
