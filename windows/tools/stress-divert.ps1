<#
.SYNOPSIS
    Puts the divert layer under load: several applications at once, many concurrent connections, and
    a bulk transfer, with an unselected application alongside as a control.

.DESCRIPTION
    verify-divert.ps1 answers "does one connection work". This answers the questions that come next,
    and that a single connection cannot: does it hold up with several applications running together,
    does it survive concurrency, does it move data at a sensible rate, and - the one that matters
    most - does an application nobody selected stay untouched while all that is going on.

    Everything runs locally, and the destination is chosen so the result cannot be misread.

    Requests are aimed at TEST-NET (203.0.113.0/24), an address block reserved for documentation that
    routes nowhere. The bundled SOCKS5 server answers as the origin as well as the proxy, so it never
    dials the destination and the address does not have to exist. The consequence is that a request
    can only succeed by going through the proxy: a selected application that succeeds was proxied,
    and the unselected control must fail. There is nothing left to interpret.

    An earlier version served the payload from this machine's own LAN address, which measured
    nothing at all: traffic from a machine to its own address is loopback as far as the stack is
    concerned, the divert filter excludes loopback, and not one packet was ever redirected.

    Several distinct "applications" are made by copying curl.exe into separate directories. They are
    genuinely different executables at different paths, which is what SplitLane routes on, so this
    exercises several routing keys rather than one rule hit repeatedly.

.PARAMETER Apps
    How many selected applications to run concurrently.

.PARAMETER Requests
    Requests each application makes.

.PARAMETER Concurrency
    How many of an application's requests are in flight at once.

.PARAMETER PayloadKb
    Response body size, in kilobytes.

.PARAMETER KeepRunning
    Leave the engine and servers up afterwards.

.EXAMPLE
    .\stress-divert.ps1
    .\stress-divert.ps1 -Apps 4 -Requests 50 -Concurrency 10 -PayloadKb 1024
#>
[CmdletBinding()]
param(
    [int]$Apps = 3,
    [int]$Requests = 30,
    [int]$Concurrency = 8,
    [int]$PayloadKb = 256,
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
. (Join-Path $PSScriptRoot 'engine-binary.ps1')
$engine = Get-EngineBinary -Root $root -Quiet
$testbed = Join-Path $root 'tools\socks5-testbed\bin\Release\net10.0\SplitLane.Testbed.Socks5.exe'
$artifacts = Join-Path $root 'artifacts'
$stage = Join-Path $artifacts 'stress'
$socksLog = Join-Path $artifacts 'stress-socks.log'
$originLog = Join-Path $artifacts 'stress-origin.log'
$engineOut = Join-Path $artifacts 'stress-engine.log'
$engineLog = 'C:\ProgramData\SplitLane\logs\engine.log'

foreach ($required in @($engine, $testbed)) {
    if (-not (Test-Path $required)) { throw "Not built: $required" }
}

$script:IsElevated = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Invoke-Privileged {
    param([string]$CommandLine)
    if ($script:IsElevated) { & cmd.exe /c $CommandLine }
    else { Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList ('/c ' + $CommandLine) }
}

function Stop-Everything {
    foreach ($name in @('SplitLane.Testbed.Socks5', 'SplitLane.Engine')) {
        foreach ($p in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { }
        }
    }
    if (Get-Process -Name 'SplitLane.Engine' -ErrorAction SilentlyContinue) {
        try { Invoke-Privileged 'taskkill /f /im SplitLane.Engine.exe >nul 2>&1' } catch { }
    }
}

Write-Host 'SplitLane :: divert stress test' -ForegroundColor Cyan
Write-Host "  $Apps selected applications, $Requests requests each, $Concurrency in flight, ${PayloadKb}KB responses"
Get-EngineBinary -Root $root | Out-Null
Stop-Everything

New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# ---- The local network: a SOCKS5 upstream and an HTTP origin ------------------------------------
Remove-Item $socksLog -Force -ErrorAction SilentlyContinue
Start-Process $testbed -ArgumentList '--serve-payload-kb', $PayloadKb `
    -WindowStyle Hidden -RedirectStandardOutput $socksLog | Out-Null
Start-Sleep -Seconds 2

$socksPort = [int](Select-String -Path $socksLog -Pattern '127\.0\.0\.1:(\d+)').Matches[0].Groups[1].Value

# TEST-NET-3, reserved for documentation and routed nowhere. Reachable only through the proxy,
# which is what makes both the success and the failure in this test mean something definite.
$originUrl = 'http://203.0.113.7/payload'
Write-Host "  SOCKS5 upstream 127.0.0.1:$socksPort (answers as the origin too)"
Write-Host "  destination     $originUrl - unroutable except through the proxy"

# ---- Several distinct applications, plus one control --------------------------------------------
$selected = @()
for ($i = 1; $i -le $Apps; $i++) {
    $dir = Join-Path $stage "app$i"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $exe = Join-Path $dir "app$i.exe"
    Copy-Item 'C:\Windows\System32\curl.exe' $exe -Force
    $selected += $exe
}

$controlDir = Join-Path $stage 'control'
New-Item -ItemType Directory -Force -Path $controlDir | Out-Null
$control = Join-Path $controlDir 'control.exe'
Copy-Item 'C:\Windows\System32\curl.exe' $control -Force

Write-Host "  selected: $($selected.Count) applications; control: 1 (unselected, must fail)"

$rules = $selected | ForEach-Object {
    @{
        identity  = @{
            executablePath = $_
            displayName    = [IO.Path]::GetFileNameWithoutExtension($_)
            capturedAt     = (Get-Date).ToUniversalTime().ToString('o')
        }
        action    = 'Proxy'
        matchMode = 'Exact'
        isEnabled = $true
    }
}

$stagedConfig = Join-Path $artifacts 'stress-config.json'
@{
    version = @{ schemaVersion = 1; generation = 1 }
    rules   = @($rules)
    proxy   = @{
        id                          = [guid]::NewGuid().ToString()
        displayName                 = 'Stress testbed'
        type                        = 'Socks5'
        endpoint                    = @{ host = '127.0.0.1'; port = $socksPort }
        isEnabled                   = $true
        handshakeTimeoutMilliseconds = 10000
        allowDirectFallback         = $false
        preferHostnames             = $true
    }
    isRoutingEnabled = $true
    logsDirectFlows  = $false
    redirectPort     = 0
} | ConvertTo-Json -Depth 8 | Set-Content $stagedConfig -Encoding utf8

# ---- The engine ----------------------------------------------------------------------------------
Remove-Item $engineOut -Force -ErrorAction SilentlyContinue

$command = 'taskkill /f /im SplitLane.Engine.exe >nul 2>&1' +
    ' & md "C:\ProgramData\SplitLane\logs" 2>nul' +
    ' & del /q "' + $engineLog + '" 2>nul' +
    ' & copy /y "' + $stagedConfig + '" "C:\ProgramData\SplitLane\configuration.json" >nul' +
    ' & "' + $engine + '" --verbose --no-console-log > "' + $engineOut + '" 2>&1'

Write-Host ''
if ($script:IsElevated) {
    & cmd.exe /c ('start /b ' + $command) | Out-Null
}
else {
    Write-Host '  Accept the UAC prompt to start the engine.' -ForegroundColor Yellow
    Start-Process cmd.exe -Verb RunAs -ArgumentList ('/c ' + $command) -WindowStyle Hidden
}

$up = $false
for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Seconds 1
    if (Get-Process -Name 'SplitLane.Engine' -ErrorAction SilentlyContinue) { $up = $true; break }
}
if (-not $up) { Stop-Everything; throw 'The engine did not start.' }
Start-Sleep -Seconds 3
Write-Host '  engine up'

# ---- The load ------------------------------------------------------------------------------------
# Each application runs in its own job so they genuinely overlap, and each job drives its requests
# with curl's own parallelism rather than one process per request - the latter would measure process
# creation more than it measures the relay.
$runner = {
    param($Exe, $Url, $Count, $Parallel, $PayloadBytes, $Timeout)

    # In parallel mode curl wants an output target per URL. Given a single -o for thirty URLs it
    # writes the first and fails the rest, which looks exactly like the proxy dropping connections -
    # and was read that way once already.
    $arguments = @()
    for ($n = 0; $n -lt $Count; $n++) { $arguments += @('-o', 'NUL', $Url) }

    $started = [Diagnostics.Stopwatch]::StartNew()

    # stderr is deliberately not merged in. curl writes progress and diagnostics there, and
    # folding them into the -w output turns a measurement into a parsing puzzle.
    $output = & $Exe --noproxy '*' --parallel --parallel-max $Parallel `
        -s --max-time $Timeout -w '%{http_code} %{size_download}\n' @arguments

    $started.Stop()

    # Only lines that are exactly "<code> <bytes>". Anything else curl chose to say is not a
    # result, and treating it as one is how this reported a cast failure instead of a number.
    $pattern = '^\s*(\d{3})\s+(\d+)\s*$'
    $codes = @()
    $bytes = @()
    foreach ($line in $output) {
        if ($line -match $pattern) {
            $codes += $Matches[1]
            $bytes += [int64]$Matches[2]
        }
    }

    [pscustomobject]@{
        App        = [IO.Path]::GetFileNameWithoutExtension($Exe)
        Requested  = $Count
        Succeeded  = @($codes | Where-Object { $_ -eq '200' }).Count
        Bytes      = ($bytes | Measure-Object -Sum).Sum
        Correct    = @($bytes | Where-Object { $_ -eq $PayloadBytes }).Count
        Seconds    = $started.Elapsed.TotalSeconds
    }
}

Write-Host ''
Write-Host '  Running load...' -ForegroundColor Yellow

$payloadBytes = $PayloadKb * 1024
$wall = [Diagnostics.Stopwatch]::StartNew()

$jobs = $selected | ForEach-Object {
    Start-Job -ScriptBlock $runner -ArgumentList $_, $originUrl, $Requests, $Concurrency, $payloadBytes, 30
}

# The control runs at the same time, at the same address, and must fail: it is not selected, so it
# goes DIRECT, and DIRECT to TEST-NET goes nowhere. A control that succeeded would mean traffic was
# reaching the destination without the proxy.
# A short timeout for the control. It is required to fail, and waiting a full minute per request for
# an outcome the test demands would make the control take longer than everything else together.
$controlJob = Start-Job -ScriptBlock $runner -ArgumentList $control, $originUrl, $Requests, $Concurrency, $payloadBytes, 5

$results = $jobs | Wait-Job -Timeout 300 | Receive-Job
$controlResult = $controlJob | Wait-Job -Timeout 300 | Receive-Job
$jobs + $controlJob | Remove-Job -Force -ErrorAction SilentlyContinue
$wall.Stop()

Start-Sleep -Seconds 2

# ---- What happened -------------------------------------------------------------------------------
$connects = @(Select-String -Path $socksLog -Pattern 'CONNECT' -ErrorAction SilentlyContinue)
$counters = @(Select-String -Path $engineLog -Pattern 'socket events' -ErrorAction SilentlyContinue)
$failures = @(Select-String -Path $engineLog -Pattern 'proxy handshake failed|refused unrecognised|reinjection refused|receive failed' -ErrorAction SilentlyContinue)

$totalRequested = ($results | Measure-Object -Property Requested -Sum).Sum
$totalOk = ($results | Measure-Object -Property Succeeded -Sum).Sum
$totalBytes = ($results | Measure-Object -Property Bytes -Sum).Sum
$totalCorrect = ($results | Measure-Object -Property Correct -Sum).Sum

Write-Host ''
Write-Host '================ RESULT ================' -ForegroundColor Cyan
Write-Host ("  wall clock        : {0:N1}s" -f $wall.Elapsed.TotalSeconds)
Write-Host ''
foreach ($r in $results) {
    Write-Host ("  {0,-8} {1,3}/{2,-3} ok, {3,3} intact, {4,8:N1} KB, {5,5:N1}s" -f `
        $r.App, $r.Succeeded, $r.Requested, $r.Correct, ($r.Bytes / 1KB), $r.Seconds)
}
Write-Host ''
Write-Host ("  selected total    : {0}/{1} succeeded, {2} payloads intact" -f $totalOk, $totalRequested, $totalCorrect)
# Against the applications' own elapsed time, not the wall clock. The wall clock is dominated by the
# control waiting out timeouts it is supposed to hit, and dividing by it would understate the relay
# several times over while looking like a measurement of it.
$busiest = ($results | Measure-Object -Property Seconds -Maximum).Maximum
Write-Host ("  throughput        : {0:N1} MB in {1:N1}s of transfer = {2:N1} MB/s across {3} applications" -f `
    ($totalBytes / 1MB), $busiest, ($totalBytes / 1MB / $busiest), $results.Count)
Write-Host ("  upstream CONNECTs : {0}" -f $connects.Count)
Write-Host ("  control (DIRECT)  : {0}/{1} succeeded - expected 0, since it is not proxied" -f `
    $controlResult.Succeeded, $controlResult.Requested)
Write-Host ''
Write-Host "  counters          : $(if ($counters) { $counters[-1].Line.Trim() } else { 'none' })"
Write-Host "  engine complaints : $($failures.Count)"
if ($failures) { $failures | Select-Object -First 5 | ForEach-Object { Write-Host "    $($_.Line.Trim())" } }

Write-Host ''
$verdict = $true
if ($totalOk -ne $totalRequested) { Write-Host '  FAIL: not every selected request succeeded' -ForegroundColor Red; $verdict = $false }
if ($totalCorrect -ne $totalRequested) { Write-Host '  FAIL: some payloads were truncated or corrupted' -ForegroundColor Red; $verdict = $false }
if ($connects.Count -lt $totalRequested) { Write-Host "  FAIL: upstream saw $($connects.Count) CONNECTs for $totalRequested requests - some bypassed the proxy" -ForegroundColor Red; $verdict = $false }
if ($controlResult.Succeeded -ne 0) { Write-Host '  FAIL: the unselected control reached the destination, so something bypassed the routing decision' -ForegroundColor Red; $verdict = $false }

if ($verdict) {
    Write-Host '  PASS - every selected request was proxied with its payload intact, and the' -ForegroundColor Green
    Write-Host '         unselected control never reached the destination' -ForegroundColor Green
}
Write-Host '=======================================' -ForegroundColor Cyan

if (-not $KeepRunning) {
    Stop-Everything
    try { Invoke-Privileged 'rmdir /s /q "C:\ProgramData\SplitLane" >nul 2>&1' } catch { }
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    Write-Host '  cleaned up'
}
