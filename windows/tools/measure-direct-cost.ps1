<#
.SYNOPSIS
    Measures what SplitLane costs an application it was never asked to touch.

.DESCRIPTION
    The product's promise is that unselected applications are left alone. On Windows that promise has
    a caveat the design is honest about - their packets are copied to user mode and reinjected - and
    this measures the size of the caveat, in milliseconds, on the operation that pays for it.

    Connection setup is where the cost lands. A SYN with no routing decision waits briefly for one,
    because losing that race means a selected application connects to its real destination and can
    never be proxied. An unselected application has no decision coming, so it waits the full window
    every time.

    The probe opens and closes TCP connections to a destination on the local network that answers
    immediately, times each one, and reports the distribution with the engine down and up. Loopback
    is deliberately not used: the divert filter excludes it, so a loopback probe would measure
    nothing and report a reassuring zero.

.PARAMETER Destination
    Host to connect to. Defaults to the default gateway, which is on the local network, answers fast
    and is not somebody else's server.

.PARAMETER Port
    Port to connect to.

.PARAMETER Count
    Connections per phase.
#>
[CmdletBinding()]
param(
    [string]$Destination,
    [int]$Port = 80,
    [int]$Count = 60
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
. (Join-Path $PSScriptRoot 'engine-binary.ps1')

if (-not $Destination) {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1
    $Destination = $route.NextHop
}
if (-not $Destination) { throw 'No default gateway; pass -Destination.' }

$isElevated = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Stop-Engine {
    foreach ($p in @(Get-Process -Name 'SplitLane.Engine' -ErrorAction SilentlyContinue)) {
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { }
    }
    if (Get-Process -Name 'SplitLane.Engine' -ErrorAction SilentlyContinue) {
        if ($isElevated) { & cmd.exe /c 'taskkill /f /im SplitLane.Engine.exe >nul 2>&1' }
        else { Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '/c taskkill /f /im SplitLane.Engine.exe' }
    }
    Start-Sleep -Milliseconds 500
}

function Measure-Connects {
    param([string]$Host_, [int]$Port_, [int]$Count_)

    $samples = New-Object 'System.Collections.Generic.List[double]'
    for ($i = 0; $i -lt $Count_; $i++) {
        $client = New-Object Net.Sockets.TcpClient
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $async = $client.BeginConnect($Host_, $Port_, $null, $null)
            if (-not $async.AsyncWaitHandle.WaitOne(3000)) { continue }
            $client.EndConnect($async)
            $sw.Stop()
            $samples.Add($sw.Elapsed.TotalMilliseconds)
        }
        catch { }
        finally { $client.Close() }
    }
    return $samples
}

function Format-Samples {
    param([string]$Label, $Samples)
    if ($Samples.Count -eq 0) { Write-Host ("  {0,-14}: no successful connections" -f $Label); return $null }
    $sorted = @($Samples | Sort-Object)
    $median = $sorted[[int]($sorted.Count / 2)]
    $p95 = $sorted[[int][math]::Min($sorted.Count - 1, [math]::Floor($sorted.Count * 0.95))]
    Write-Host ("  {0,-14}: median {1,6:N2} ms   p95 {2,6:N2} ms   max {3,6:N2} ms   ({4} connections)" -f `
        $Label, $median, $p95, $sorted[-1], $sorted.Count)
    return $median
}

Write-Host 'SplitLane :: cost to an unselected application' -ForegroundColor Cyan
Write-Host "  probing ${Destination}:$Port, $Count connections per phase"
$engine = Get-EngineBinary -Root $root
Write-Host ''

Stop-Engine
Measure-Connects -Host_ $Destination -Port_ $Port -Count_ 10 | Out-Null   # warm the path
$before = Format-Samples -Label 'engine down' -Samples (Measure-Connects -Host_ $Destination -Port_ $Port -Count_ $Count)

$command = 'taskkill /f /im SplitLane.Engine.exe >nul 2>&1' +
    ' & md "C:\ProgramData\SplitLane\logs" 2>nul' +
    ' & "' + $engine + '" --verbose --no-console-log > "' + (Join-Path $root 'artifacts\cost-engine.log') + '" 2>&1'

if ($isElevated) { & cmd.exe /c ('start /b ' + $command) | Out-Null }
else {
    Write-Host '  Accept the UAC prompt to start the engine.'
    Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList ('/c ' + $command)
}

$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline -and -not (Get-Process -Name 'SplitLane.Engine' -ErrorAction SilentlyContinue)) {
    Start-Sleep -Milliseconds 300
}
if (-not (Get-Process -Name 'SplitLane.Engine' -ErrorAction SilentlyContinue)) { throw 'Engine did not start.' }
Start-Sleep -Seconds 3

Measure-Connects -Host_ $Destination -Port_ $Port -Count_ 10 | Out-Null
$after = Format-Samples -Label 'engine up' -Samples (Measure-Connects -Host_ $Destination -Port_ $Port -Count_ $Count)

Write-Host ''
if ($null -ne $before -and $null -ne $after) {
    Write-Host ("  cost of running SplitLane, per connection an unselected application opens: {0:N2} ms" -f `
        ($after - $before)) -ForegroundColor Yellow
}

$log = 'C:\ProgramData\SplitLane\logs\engine.log'
if (Test-Path $log) {
    $counters = @(Select-String -Path $log -Pattern 'divert: socket events' | Select-Object -Last 1)
    if ($counters) { Write-Host "  counters: $($counters[0].Line.Trim())" }
}

Stop-Engine
if (Test-Path 'C:\ProgramData\SplitLane') {
    $wipe = 'rd /s /q "C:\ProgramData\SplitLane"'
    if ($isElevated) { & cmd.exe /c $wipe } else { Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList ('/c ' + $wipe) }
}
Write-Host '  cleaned up'
