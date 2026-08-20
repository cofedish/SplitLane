<#
.SYNOPSIS
    Proves - or disproves - that the divert layer routes a selected application through the proxy.

.DESCRIPTION
    This is the test that decides whether SplitLane works. Everything else in the repository is
    verified by `dotnet test`; interception is not, because it needs a kernel driver and elevation.

    The script does the whole setup so the run is one command:

      1. Starts the bundled SOCKS5 server on an ephemeral loopback port, which logs every CONNECT.
         That log is the proof: if a selected application's connection really was intercepted and
         relayed, it appears there, named, on the upstream side.
      2. Writes a configuration with a single rule for curl.exe pointing at that server.
      3. Starts the engine elevated. Windows will raise a UAC prompt - accept it.
      4. Runs curl, and reports what happened.

    curl is used deliberately: it is present on every Windows install, it is in System32 (so the rule
    is matched exactly, which also exercises the shared-directory guard of ADR W-0003), and it can be
    told to ignore the machine's own proxy settings.

    That last point matters more than it looks. On a machine running a local proxy client, almost
    every application connects to 127.0.0.1, and SplitLane correctly declines to proxy loopback
    destinations. Without -noproxy the test measures the loop defence rather than the redirect.

.PARAMETER Mode
    Which redirect shape to test.

    loopback - the original design. Both endpoints move to 127.0.0.1.
    local    - the alternative. Only the destination changes, to the machine's own address, so the
               loopback fast path is not involved at all.

.PARAMETER Trace
    Sniff the redirect port and report what the stack actually carries. Answers the question counters
    cannot: does the injected packet reach the stack, or is it discarded on injection?

.PARAMETER KeepRunning
    Leave the engine and the test server up afterwards, to poke at by hand.

.EXAMPLE
    .\verify-divert.ps1 -Mode loopback -Trace
    .\verify-divert.ps1 -Mode local -Trace
#>
[CmdletBinding()]
param(
    [ValidateSet('loopback', 'local')]
    [string]$Mode = 'loopback',
    [switch]$Trace,
    [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'

# Whether this session can already do the privileged parts itself.
#
# Raising a UAC prompt is not always possible. With PromptOnSecureDesktop set - the default - the
# consent dialog is drawn on the secure desktop, and a full-screen application in front of it means
# the prompt is never seen and the launch silently does nothing. Running this from an elevated
# terminal sidesteps that entirely, so the script has to work both ways.
$script:IsElevated = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Invoke-Privileged {
    param([string]$CommandLine)

    if ($script:IsElevated) {
        & cmd.exe /c $CommandLine
    }
    else {
        Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList ('/c ' + $CommandLine)
    }
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
$engine = Join-Path $root 'src\SplitLane.Engine\bin\Debug\net10.0-windows\win-x64\SplitLane.Engine.exe'
$testbed = Join-Path $root 'tools\socks5-testbed\bin\Release\net10.0\SplitLane.Testbed.Socks5.exe'
$artifacts = Join-Path $root 'artifacts'
$testbedLog = Join-Path $artifacts 'verify-testbed.log'
$engineOut = Join-Path $artifacts 'verify-engine.log'
$engineLog = 'C:\ProgramData\SplitLane\logs\engine.log'

foreach ($required in @($engine, $testbed)) {
    if (-not (Test-Path $required)) {
        throw "Not built: $required`nRun: dotnet build $root\SplitLane.Windows.slnx"
    }
}

New-Item -ItemType Directory -Force -Path $artifacts | Out-Null

function Stop-Everything {
    # Best effort throughout. A leftover from an earlier elevated run cannot be stopped from an
    # unelevated session, and failing to kill one is not a reason to refuse to run the test - the
    # new server binds an ephemeral port of its own, so a stale one is inert rather than in the way.
    foreach ($name in @('SplitLane.Testbed.Socks5', 'SplitLane.Engine')) {
        foreach ($process in @(Get-Process -Name $name -ErrorAction SilentlyContinue)) {
            try { Stop-Process -Id $process.Id -Force -ErrorAction Stop } catch { }
        }
    }

    # Anything left is elevated and needs the same to clear.
    if (Get-Process -Name 'SplitLane.Engine' -ErrorAction SilentlyContinue) {
        try { Invoke-Privileged 'taskkill /f /im SplitLane.Engine.exe >nul 2>&1' } catch { }
    }
}

Write-Host "SplitLane :: divert verification ($Mode mode)" -ForegroundColor Cyan
Write-Host "  session: $(if ($script:IsElevated) { 'elevated' } else { 'not elevated - a UAC prompt will be raised' })"
Stop-Everything

# ---- 1. The upstream, which is where the proof comes from --------------------------------------
Remove-Item $testbedLog -Force -ErrorAction SilentlyContinue
Start-Process $testbed -WindowStyle Hidden -RedirectStandardOutput $testbedLog | Out-Null
Start-Sleep -Seconds 2

$match = Select-String -Path $testbedLog -Pattern '127\.0\.0\.1:(\d+)'
if (-not $match) { throw 'The test SOCKS5 server did not start.' }
$proxyPort = [int]$match.Matches[0].Groups[1].Value
Write-Host "  test SOCKS5 server on 127.0.0.1:$proxyPort"

# ---- 2. One rule, for curl -----------------------------------------------------------------------
#
# Written next to the script and copied into place by the elevated command below, rather than written
# directly. %ProgramData%\SplitLane is created by whichever process gets there first, and once an
# elevated engine has owned it an unelevated session can no longer overwrite the file.
$stagedConfig = Join-Path $artifacts 'verify-config.json'
@{
    version = @{ schemaVersion = 1; generation = 1 }
    rules   = @(@{
            identity  = @{
                executablePath = 'C:\Windows\System32\curl.exe'
                displayName    = 'curl'
                capturedAt     = (Get-Date).ToUniversalTime().ToString('o')
            }
            action    = 'Proxy'
            matchMode = 'Exact'
            isEnabled = $true
        })
    proxy   = @{
        id                          = [guid]::NewGuid().ToString()
        displayName                 = 'Verification testbed'
        type                        = 'Socks5'
        endpoint                    = @{ host = '127.0.0.1'; port = $proxyPort }
        isEnabled                   = $true
        handshakeTimeoutMilliseconds = 8000
        allowDirectFallback         = $false
        preferHostnames             = $true
    }
    isRoutingEnabled = $true
    logsDirectFlows  = $false
    redirectPort     = 0
} | ConvertTo-Json -Depth 8 | Set-Content $stagedConfig -Encoding utf8
Write-Host '  rule: curl.exe -> PROXY'

# ---- 3. The engine, elevated ---------------------------------------------------------------------
Remove-Item $engineOut -Force -ErrorAction SilentlyContinue

$switches = @('--verbose', '--no-console-log')
if ($Mode -eq 'local') { $switches += '--redirect-local' }
if ($Trace) { $switches += '--trace' }

# Output is redirected inside cmd rather than by Start-Process, which cannot redirect an elevated
# child. It also keeps the engine off a console: an elevated console window with QuickEdit enabled
# blocks Console.WriteLine on a stray selection, and takes every thread that logs with it.
# One elevated step does everything that needs elevation: clear any leftover engine, put the
# configuration in place, drop the previous log, and start. Asking for the prompt once is worth a
# slightly longer command line.
$command = '/c taskkill /f /im SplitLane.Engine.exe >nul 2>&1' +
    ' & md "C:\ProgramData\SplitLane\logs" 2>nul' +
    ' & del /q "' + $engineLog + '" 2>nul' +
    ' & copy /y "' + $stagedConfig + '" "C:\ProgramData\SplitLane\configuration.json" >nul' +
    ' & "' + $engine + '" ' + ($switches -join ' ') + ' > "' + $engineOut + '" 2>&1'

Write-Host ''

if ($script:IsElevated) {
    # Already privileged: put the configuration in place and start the engine directly. No prompt,
    # nothing to miss, and the output redirection is ours rather than cmd's.
    New-Item -ItemType Directory -Force -Path 'C:\ProgramData\SplitLane\logs' | Out-Null
    Remove-Item $engineLog -Force -ErrorAction SilentlyContinue
    Copy-Item $stagedConfig 'C:\ProgramData\SplitLane\configuration.json' -Force

    Start-Process $engine -ArgumentList $switches -WindowStyle Hidden `
        -RedirectStandardOutput $engineOut -RedirectStandardError ($engineOut + '.err') | Out-Null
}
else {
    Write-Host '  Accept the UAC prompt to start the engine.' -ForegroundColor Yellow
    Write-Host '  If no prompt appears, the secure desktop is hidden behind a full-screen'
    Write-Host '  application. Minimise it, or run this script from an elevated terminal.'
    Start-Process cmd.exe -Verb RunAs -ArgumentList $command -WindowStyle Hidden
}

$up = $false
for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Seconds 1
    if (Get-Process -Name 'SplitLane.Engine' -ErrorAction SilentlyContinue) { $up = $true; break }
}

if (-not $up) {
    Stop-Everything
    if ($script:IsElevated) {
        throw "The engine did not start. See $engineOut."
    }

    throw 'The engine did not start - no elevated process appeared. Either the UAC prompt was ' +
        'declined, or it was drawn on the secure desktop behind a full-screen application and ' +
        'never seen. Run this script from an elevated terminal instead.'
}

Start-Sleep -Seconds 3
Write-Host '  engine up'

# ---- 4. The measurement --------------------------------------------------------------------------
Write-Host ''
Write-Host '  Running curl through the proxy lane...'
$output = & C:\Windows\System32\curl.exe -s -o NUL --noproxy '*' `
    -w 'http_code=%{http_code} time=%{time_total}s' --max-time 15 http://example.com 2>&1
$curlExit = $LASTEXITCODE
Start-Sleep -Seconds 2

$connects = @(Select-String -Path $testbedLog -Pattern 'CONNECT' -ErrorAction SilentlyContinue)
$decisions = @(Select-String -Path $engineLog -Pattern 'PROXY curl' -ErrorAction SilentlyContinue)
$traces = @(Select-String -Path $engineLog -Pattern 'TRACE' -ErrorAction SilentlyContinue)
$counters = @(Select-String -Path $engineLog -Pattern 'socket events' -ErrorAction SilentlyContinue)

Write-Host ''
Write-Host '================ RESULT ================' -ForegroundColor Cyan
Write-Host "  curl            : $output (exit $curlExit)"
Write-Host "  routing decision: $(if ($decisions) { $decisions[-1].Line.Trim() } else { 'none - the rule did not match' })"
Write-Host "  counters        : $(if ($counters) { $counters[-1].Line.Trim() } else { 'none' })"

if ($traces) {
    Write-Host '  packets seen on the redirect port:'
    $traces | Select-Object -Last 6 | ForEach-Object { Write-Host "    $($_.Line.Trim())" }
}
elseif ($Trace) {
    Write-Host '  packets seen on the redirect port: NONE' -ForegroundColor Yellow
    Write-Host '    The injected packet never reached the stack, so the problem is the injection'
    Write-Host '    itself rather than the listening socket.'
}

Write-Host ''
if ($connects.Count -gt 0) {
    Write-Host '  INTERCEPTION WORKS' -ForegroundColor Green
    Write-Host "  The upstream saw: $($connects[-1].Line.Trim())"
    Write-Host '  A selected application was routed through the proxy.'
}
else {
    Write-Host '  INTERCEPTION DID NOT HAPPEN' -ForegroundColor Red
    Write-Host '  The upstream saw no CONNECT, so nothing was relayed.'
    if ($decisions) {
        Write-Host '  The rule matched and the packet was redirected, so the failure is after the'
        Write-Host '  rewrite - between injection and the listening socket.'
    }
}
Write-Host '=======================================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  engine log: $engineLog"

if (-not $KeepRunning) {
    Stop-Everything
    # The tree belongs to an elevated process, so removing it needs the same. Best effort: a leftover
    # test configuration is untidy, not dangerous, and the engine is already stopped.
    try { Invoke-Privileged 'rmdir /s /q "C:\ProgramData\SplitLane" >nul 2>&1' } catch { }
    Write-Host '  cleaned up (engine stopped, test configuration removed)'
}
