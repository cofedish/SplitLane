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

# The driver never goes in the package, and this is where that gets enforced rather than assumed.
#
# The engine project copies runtime/windivert next to its output when the folder is there, which is
# what makes F5 work on a development machine. A publish carries that along, so a package built by
# hand on a machine that had fetched the driver quietly redistributed somebody else's signed kernel
# driver - while CI, which has no such folder, produced a package without it. Two builds of the same
# tag that differ in what they redistribute is not a difference to discover later.
#
# See ADR W-0001. The fetch script ships instead, and the engine's preflight points at it.
$bundledDriver = @(Get-ChildItem $engineOut -Filter 'WinDivert*' -File -ErrorAction SilentlyContinue)
if ($bundledDriver.Count -gt 0) {
    Write-Host ("  removing {0} driver file(s) from the publish - not ours to redistribute" -f $bundledDriver.Count) -ForegroundColor Yellow
    $bundledDriver | Remove-Item -Force
}

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
