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
    [string]$Destination = '',

    # Pinned, and checked by default. The driver now ships inside the installer, so what this
    # downloads is what gets handed to other people's kernels - "trust whatever the URL served
    # today" stopped being an acceptable default the moment that became true.
    #
    # Recorded from the published 2.2.2 archive, 405137 bytes. Change it only together with
    # -Version, and only after checking the new value against the WinDivert release.
    [string]$Sha256 = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'
)

# Where the driver belongs depends on which layout this script is sitting in.
#
#   <repo>/windows/tools/          -> ../runtime/windivert, which the engine project copies from
#   <install>/Tools/               -> ../Engine, which is where the engine looks
#
# It used to always assume the first. Run from an installed copy - which is exactly what the
# engine's own error message told people to do - it put the driver in a folder nothing reads, and
# the application went on reporting that the driver was missing.
if (-not $Destination) {
    $installedEngine = Join-Path $PSScriptRoot '..\Engine'
    $Destination = if (Test-Path (Join-Path $installedEngine 'SplitLane.Engine.exe')) {
        $installedEngine
    }
    else {
        Join-Path $PSScriptRoot '..\runtime\windivert'
    }
}

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

# The licence travels with the binaries, always. WinDivert is LGPLv3 or GPLv2, and both require the
# terms to accompany it - so a copy that arrives without them is not a copy anyone may pass on.
$licence = Get-ChildItem -Path $extracted -Recurse -File | Where-Object { $_.Name -eq 'LICENSE' } | Select-Object -First 1
if (-not $licence) { throw 'The archive contains no LICENSE. Refusing to install a driver without its terms.' }
Copy-Item -Path $licence.FullName -Destination (Join-Path $Destination 'WinDivert-LICENSE.txt') -Force
Write-Host '  copied WinDivert-LICENSE.txt'

# Upstream's own statement of its version, carried alongside so the notice that names it in the
# package quotes the archive rather than a number written down somewhere else and left to drift.
$versionFile = Get-ChildItem -Path $extracted -Recurse -File | Where-Object { $_.Name -eq 'VERSION' } | Select-Object -First 1
if ($versionFile) {
    Copy-Item -Path $versionFile.FullName -Destination (Join-Path $Destination 'WinDivert-VERSION.txt') -Force
    Write-Host '  copied WinDivert-VERSION.txt'
}

Write-Host ''
Write-Host 'Done. Rebuild the engine so the binaries land beside SplitLane.Engine.exe:' -ForegroundColor Green
Write-Host '  dotnet build windows\src\SplitLane.Engine\SplitLane.Engine.csproj'
Write-Host ''
Write-Host 'Then confirm the machine can actually load it:'
Write-Host '  SplitLane.Engine.exe --check'
