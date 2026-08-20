<#
.SYNOPSIS
    Publishes both applications and builds the MSI.

.DESCRIPTION
    The same script CI runs, so a release built on a developer machine and a release built by GitHub
    Actions come out of the same steps rather than out of two descriptions of the same steps that
    drift apart.

    Both applications are published self-contained. That roughly doubles the download, and it buys
    an installer that works on a machine with no .NET runtime — which is most machines, and exactly
    the machine someone installing a network tool is likely to be on.

.PARAMETER Version
    Product version stamped into the MSI and its file name.

.PARAMETER Configuration
    Build configuration. Release unless you are debugging the packaging itself.

.PARAMETER OutputDirectory
    Where the finished MSI and the portable zip are written.

.EXAMPLE
    .\build-installer.ps1 -Version 0.1.0
#>
[CmdletBinding()]
param(
    [string]$Version = '0.1.0',
    [string]$Configuration = 'Release',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\artifacts\release')
)

$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$staging = Join-Path $root 'artifacts\publish'
$appOut = Join-Path $staging 'app'
$engineOut = Join-Path $staging 'engine'

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path $OutputDirectory).ProviderPath

Write-Host "SplitLane :: building $Version ($Configuration)" -ForegroundColor Cyan

# A stale publish folder silently ships deleted files, which is the packaging bug that is hardest to
# notice: everything works, and the installer carries a binary that no longer exists in source.
foreach ($path in @($appOut, $engineOut)) {
    if (Test-Path $path) { Remove-Item -Recurse -Force $path }
}

# Every MSBuild property is passed as one quoted argument. PowerShell does not join a bare token to
# an adjacent parenthesised expression, so `-p:ToolsDir=(Join-Path ...)` arrives as two separate
# arguments and the property silently never gets set.
$appProject = Join-Path $root 'src\SplitLane.App\SplitLane.App.csproj'
$engineProject = Join-Path $root 'src\SplitLane.Engine\SplitLane.Engine.csproj'
$installerProject = Join-Path $root 'installer\SplitLane.Installer.wixproj'
$toolsDir = Join-Path $root 'tools'

# Symbols and XML documentation are build outputs, not product. Shipping them adds tens of megabytes
# to every download and helps nobody installing the tool: a crash on a user's machine is diagnosed
# from the engine log, not from a PDB they never asked for.
$publishFlags = @(
    '-p:PublishSingleFile=false'
    '-p:DebugType=none'
    '-p:DebugSymbols=false'
    '-p:GenerateDocumentationFile=false'
)

Write-Host ''
Write-Host 'Publishing the app...'
dotnet publish $appProject -c $Configuration -r win-x64 --self-contained true `
    "-p:Version=$Version" @publishFlags -o $appOut
if ($LASTEXITCODE -ne 0) { throw 'Publishing SplitLane.App failed.' }

Write-Host 'Publishing the engine...'
dotnet publish $engineProject -c $Configuration -r win-x64 --self-contained true `
    "-p:Version=$Version" @publishFlags -o $engineOut
if ($LASTEXITCODE -ne 0) { throw 'Publishing SplitLane.Engine failed.' }

# The driver ships inside the package, and this is where that is made certain.
#
# It used to be fetched by hand after installing, which kept a third-party kernel driver out of a
# repository that has not chosen a licence - but it also meant a product that did not work when
# installed. Somebody who runs an installer has installed the thing; being handed a PowerShell
# script and a path afterwards is not a product.
#
# So it is downloaded here, from the official release, pinned by SHA-256, with its licence carried
# alongside. WinDivert is LGPLv3 or GPLv2 and may be redistributed on those terms; the terms travel
# with it, unmodified, and the notice at the install root says what it is and where it came from.
# See ADR W-0009, which supersedes the fetch-it-yourself half of W-0001.
$driverFiles = @('WinDivert.dll', 'WinDivert64.sys', 'WinDivert-LICENSE.txt')
$missing = @($driverFiles | Where-Object { -not (Test-Path (Join-Path $engineOut $_)) })

if ($missing.Count -gt 0) {
    Write-Host ''
    Write-Host 'Fetching the divert driver into the publish...'
    & (Join-Path $PSScriptRoot 'fetch-windivert.ps1') -Destination $engineOut
    if ($LASTEXITCODE -ne 0) { throw 'Fetching WinDivert failed.' }
}

foreach ($name in $driverFiles) {
    if (-not (Test-Path (Join-Path $engineOut $name))) {
        throw "$name is not in the publish. The package must not ship a driver without it."
    }
}

$driverVersion = (Get-Content (Join-Path $engineOut 'WinDivert-VERSION.txt') -ErrorAction SilentlyContinue |
    Select-Object -First 1)
if (-not $driverVersion) { throw 'WinDivert-VERSION.txt is missing; the notice would name no version.' }

# A notice at the root, where somebody looking for "what else is in here" would look, rather than
# only next to the binary it describes.
$notice = @(
    'Third-party software included with SplitLane'
    '============================================'
    ''
    # Upstream's own words, from the archive's README and VERSION. A notice about somebody else's
    # copyright is not a place to paraphrase, and an earlier draft of this named an author who does
    # not appear anywhere in what WinDivert actually ships.
    'WinDivert ' + $driverVersion
    '  Written by basil <basil@reqrypt.org>'
    '  https://github.com/basil00/WinDivert'
    '  Licensed under LGPL v3 or GPL v2. The full terms are in'
    '  Engine' + [char]92 + 'WinDivert-LICENSE.txt, distributed unmodified with the binaries.'
    ''
    '  WinDivert.dll and WinDivert64.sys are redistributed unmodified. SplitLane calls the'
    '  library through P/Invoke and does not link it statically, so it can be replaced with'
    '  another build of the same version.'
) -join [Environment]::NewLine

Set-Content -Path (Join-Path $appOut 'THIRD-PARTY-NOTICES.txt') -Value $notice -Encoding utf8

Write-Host ''
Write-Host 'Building the MSI...'
# Output is not swallowed. A packaging failure is reported by the toolchain in one line that names
# the offending element; hiding it behind Out-Null turns a two-minute fix into a bisect.
dotnet build $installerProject -c $Configuration `
    "-p:BuildVersion=$Version" `
    "-p:AppPublishDir=$appOut" `
    "-p:EnginePublishDir=$engineOut" `
    "-p:ToolsDir=$toolsDir"
if ($LASTEXITCODE -ne 0) { throw 'Building the installer failed.' }

$msi = Get-ChildItem -Path (Join-Path $root 'installer\bin') -Filter '*.msi' -Recurse |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $msi) { throw 'The installer build produced no MSI.' }

Copy-Item $msi.FullName -Destination $OutputDirectory -Force

# A portable zip alongside the MSI, for anyone who would rather not run an installer to try a tool.
$zip = Join-Path $OutputDirectory "SplitLane-$Version-x64-portable.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }

$portable = Join-Path $staging 'portable'
if (Test-Path $portable) { Remove-Item -Recurse -Force $portable }
New-Item -ItemType Directory -Force -Path $portable | Out-Null
Copy-Item -Recurse $appOut (Join-Path $portable 'SplitLane')
Copy-Item -Recurse $engineOut (Join-Path $portable 'SplitLane\Engine')
New-Item -ItemType Directory -Force -Path (Join-Path $portable 'SplitLane\Tools') | Out-Null
Copy-Item (Join-Path $root 'tools\fetch-windivert.ps1') (Join-Path $portable 'SplitLane\Tools')
Copy-Item (Join-Path $root 'README.md') (Join-Path $portable 'SplitLane\README.md')
Compress-Archive -Path (Join-Path $portable 'SplitLane') -DestinationPath $zip

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Get-ChildItem $OutputDirectory | ForEach-Object {
    '  {0,-44} {1,8:N1} MB' -f $_.Name, ($_.Length / 1MB)
}
