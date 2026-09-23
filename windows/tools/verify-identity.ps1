<#
.SYNOPSIS
    Proves - or disproves - that a rule follows its application through an update and a move, on a
    live machine, and puts the machine back the way it found it.

.DESCRIPTION
    Schema 2 stopped keying rules on a path (ADR W-0013). A rule now records who signed the
    application, its product name and its file name, so that an updater which moves the application
    into a new version or hash directory - what silently dropped Discord, and then Codex, back to
    DIRECT - no longer loses it. `dotnet test` proves the matching over recorded evidence. It cannot
    prove the part that only happens on a real machine: that WinDivert attributes a real socket to a
    real process, that the engine verifies that process's signature while the connection waits,
    matches it to the rule, and that the connection then actually reaches the proxy. This does.

    One application in three places, and one control:

      picked   The rule is made from a copy of curl.exe at Vendor\bin\1a2b3c4d5e6f7a8b\probe.exe -
               a hash directory, the layout Codex's command-line tool uses - with the engine's
               --describe, which runs the same code the app runs when someone picks an application.
      updated  The same binary in Vendor\bin\9f8e7d6c5b4a3921\, with the old directory deleted.
               That is what an updater does.
      moved    The same binary in a folder with nothing in common with the first. That is what a
               person does.
      control  PowerShell itself connects to the same address. It is not the selected application,
               so it must be left alone.

    Every request goes to TEST-NET-3 (203.0.113.10), which routes nowhere. The bundled SOCKS5 server
    answers as the origin, so a request can only succeed by being proxied, and each one is counted by
    the CONNECT the server logs. There is nothing left to interpret: +1 for each copy of the selected
    application and +0 for the control, or the test failed.

    curl is used because it is on every Windows install and carries an embedded Microsoft signature,
    which a copy keeps - so a copy anywhere is, by identity, the same application. Its -noproxy '*'
    keeps the machine's own proxy settings out of the measurement, as in verify-divert.ps1.

    What a PASS proves:
      - the socket layer names the real process behind a real connection, from a path the engine has
        never seen before;
      - the engine verifies that file's signature on demand while the connection is held. The first
        request from each new copy takes about a second for that reason: the SYN is held, the
        signature checked, and the retransmission a second later is the one redirected;
      - the rule matches by signer, product and file name, not by the path it was made from;
      - the connection reaches the proxy;
      - an application the rule does not describe is not swept up by it.

    What it does not prove:
      - a real vendor update. The "update" is the same bytes in a new directory; a real one changes
        the bytes and the version under the same signer. Matching reads neither, and dotnet test
        covers that, but this run does not.
      - helpers (a different binary from the same publisher), packaged applications, unsigned
        applications, UDP, or the refusal of a different file found at a rule's recorded location.
      - the installed engine. The run uses the newest engine you built, printed with its build time,
        because that is the code under test. The installed service is stopped meanwhile.
      - an unelevated application. The probes are started from this elevated session, so they run
        elevated. Attribution does not depend on that, but it is not what an ordinary application
        looks like.

    Why it puts the machine back:

    It has to change the machine to run at all. Only one engine can divert at a time, so the
    installed SplitLane service is stopped; and the engine reads its rules from %ProgramData%\SplitLane,
    so the test rule has to be written there. That directory holds the user's real rules.
    verify-divert.ps1 ends by deleting it, which was harmless before the product was installed and is
    not harmless now.

    So before anything changes, configuration.json and configuration.v2.json are copied to
    artifacts\verify-identity-<time>\backup with their hashes, and whether the service was running is
    recorded. Everything after that runs under try/finally. The engine and the test server this script
    started are stopped by process id - never by image name, which would also take down the installed
    service - the configuration files are written back byte for byte and checked against their hashes,
    a configuration.v2.json that did not exist before is deleted, and the service is started again if
    it had been running. The engine under test creates %ProgramData%\SplitLane\Policy when it is
    missing; if this run created it, it is removed again while it is still empty.
    restore-instructions.txt in the backup folder says how to do all of it by hand if the window is
    closed mid-run.

    While it runs - about a minute - the service is stopped and your own rules are not in force, so
    the applications you selected are not proxied. Close them first if that matters. The test rule is
    a family rule, as the app makes by default, so for that minute it also covers curl.exe itself:
    anything else on the machine that runs curl then is sent to the test server, not the internet.

    engine.log is shared with the service and keeps this run's lines. Only the lines appended after
    the test engine started are read, and they are also saved to the artifacts folder.

.PARAMETER DryRun
    Do everything that needs no privilege and changes nothing: start the test server, make the probe,
    describe it with the engine, generate the test configuration into the artifacts folder instead of
    %ProgramData%, and have the engine parse it with --explain --config. Stops before the service or
    %ProgramData% is touched, and does not need elevation.

.EXAMPLE
    .\verify-identity.ps1

    From an elevated terminal. Runs the four scenarios, prints a RESULT table, and restores the
    machine.

.EXAMPLE
    .\verify-identity.ps1 -DryRun

    From any terminal. Checks the configuration a real run would write, without writing it.
#>
[CmdletBinding()]
param(
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$script:IsElevated = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "SplitLane :: identity verification$(if ($DryRun) { ' (dry run)' })" -ForegroundColor Cyan

# Refused before anything else happens - before a folder is created or a binary is looked for - so a
# refusal is guaranteed to have changed nothing.
#
# No UAC prompt, deliberately. verify-divert.ps1 raises one, and with PromptOnSecureDesktop set the
# prompt can be drawn behind a full-screen window and never seen. Here there is a second reason: the
# privileged half stops a service and rewrites its configuration, and the restore has to run in the
# same elevated session that did it, under the same finally.
if (-not $script:IsElevated -and -not $DryRun) {
    Write-Host '  session         : not elevated'
    Write-Host ''
    Write-Host '  Refused: run from an elevated terminal.' -ForegroundColor Red
    Write-Host '  The test stops the SplitLane service and replaces its configuration for about a minute,'
    Write-Host '  and restores both afterwards. That needs administrator rights, and this script does'
    Write-Host '  not raise a UAC prompt for them.'
    Write-Host ''
    Write-Host '  Nothing was changed. -DryRun runs the half that needs no privilege.'
    exit 1
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
. (Join-Path $PSScriptRoot 'engine-binary.ps1')

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$artifacts = Join-Path $root "artifacts\verify-identity-$stamp"
$backupDir = Join-Path $artifacts 'backup'
$restoreNotes = Join-Path $backupDir 'restore-instructions.txt'
$testbedLog = Join-Path $artifacts 'testbed.log'
$testbedErr = Join-Path $artifacts 'testbed.err.log'
$engineOut = Join-Path $artifacts 'engine.out.log'
$engineErr = Join-Path $artifacts 'engine.err.log'
$engineExcerpt = Join-Path $artifacts 'engine-log-excerpt.log'
$describeFile = Join-Path $artifacts 'describe.json'
$stagedConfig = Join-Path $artifacts 'configuration.v2.json'
$explainStaged = Join-Path $artifacts 'explain-staged.txt'
$explainInstalled = Join-Path $artifacts 'explain-before-start.txt'
$explainFile = Join-Path $artifacts 'explain.txt'

$dataRoot = Join-Path $env:ProgramData 'SplitLane'
$legacyConfig = Join-Path $dataRoot 'configuration.json'
$liveConfig = Join-Path $dataRoot 'configuration.v2.json'
$engineLog = Join-Path $dataRoot 'logs\engine.log'

# The managed policy's folder. The engine under test creates it, administrator-only, when it is not
# there; the installed build may predate it. Removed afterwards if this run is what created it.
$policyDir = Join-Path $dataRoot 'Policy'
$policyFile = Join-Path $policyDir 'policy.json'

# Everything the run could leave behind in the configuration directory. The .tmp is what the
# engine's atomic save writes first; it is tracked so a save interrupted by the stop is cleaned up.
$trackedFiles = @('configuration.json', 'configuration.v2.json', 'configuration.v2.json.tmp')

$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
$target = '203.0.113.10'
$targetUrl = "http://$target/"
$connectPattern = 'CONNECT 203\.0\.113\.10:80\b'

# Written into the test configuration so a copy of it left behind by an interrupted run is recognised,
# and never backed up as if it were the user's own.
$marker = 'verify-identity testbed (temporary)'

# The long form of the path. %TEMP% is often an 8.3 path (C:\Users\ABCDEF~1\...), a process started
# from one reports that as its image path, and no application is ever launched that way from the
# Start menu. Get-Item expands it.
$tempRoot = (Get-Item -LiteralPath $env:TEMP).FullName
$probeRoot = Join-Path $tempRoot 'splitlane-verify-identity'
$pickedExe = Join-Path $probeRoot 'Vendor\bin\1a2b3c4d5e6f7a8b\probe.exe'
$updatedExe = Join-Path $probeRoot 'Vendor\bin\9f8e7d6c5b4a3921\probe.exe'
$movedExe = Join-Path $probeRoot 'Moved\Elsewhere\probe.exe'

$utf8 = New-Object Text.UTF8Encoding($false)

# ---- Helpers --------------------------------------------------------------------------------------

function Get-TestbedBinary {
    # The newest build, for the reason engine-binary.ps1 gives: a fixed path under bin\Release ran a
    # month-old server while the solution build refreshed bin\Debug.
    param([Parameter(Mandatory)][string]$Root)

    $candidates = @(Get-ChildItem -Path (Join-Path $Root 'tools\socks5-testbed\bin') `
            -Filter 'SplitLane.Testbed.Socks5.exe' -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)

    if ($candidates.Count -eq 0) {
        throw "No SplitLane.Testbed.Socks5.exe under $Root\tools\socks5-testbed\bin - build it first: " +
            "dotnet build $Root\SplitLane.Windows.slnx"
    }

    $chosen = $candidates[0]
    $relative = $chosen.FullName.Substring($Root.Length).TrimStart('\')
    Write-Host ("  test server     : {0}  (built {1:HH:mm:ss})" -f $relative, $chosen.LastWriteTime)
    return $chosen.FullName
}

function Read-SharedText {
    # Both logs are open for writing by another process while they are read.
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true)
        return $reader.ReadToEnd()
    }
    finally {
        $stream.Dispose()
    }
}

function Read-CompleteLine {
    # Appends the complete lines after $Offset to $Into and returns the offset to continue from. A
    # line with no newline yet is still being written, and is left for the next read.
    param([string]$Path, [long]$Offset, [System.Collections.Generic.List[string]]$Into)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        if ($Offset -ge $stream.Length) { return $Offset }

        $count = [int]($stream.Length - $Offset)
        $buffer = New-Object byte[] $count
        [void]$stream.Seek($Offset, [IO.SeekOrigin]::Begin)
        $read = 0
        while ($read -lt $count) {
            $chunk = $stream.Read($buffer, $read, $count - $read)
            if ($chunk -le 0) { break }
            $read += $chunk
        }

        if ($read -le 0) { return $Offset }
        $end = [Array]::LastIndexOf($buffer, [byte]10, $read - 1)
        if ($end -lt 0) { return $Offset }

        $text = [Text.Encoding]::UTF8.GetString($buffer, 0, $end + 1)
        foreach ($line in ($text -split "`r?`n")) {
            $clean = $line.TrimStart([char]0xFEFF)
            if ($clean.Length -gt 0) { $Into.Add($clean) }
        }

        return $Offset + $end + 1
    }
    finally {
        $stream.Dispose()
    }
}

function Read-NewEngineLog {
    # The lines the test engine appended since the last call. engine.log is the service's log too, so
    # the read starts where the file ended when the test engine was started, never at the top.
    $fresh = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $engineLog)) { return }

    if ((Get-Item -LiteralPath $engineLog).Length -lt $script:EngineLogOffset) {
        # Rolled to .1 at 4 MB since the last read. Finish the old file, then start the new one.
        $rolled = $engineLog + '.1'
        if (Test-Path -LiteralPath $rolled) {
            [void](Read-CompleteLine -Path $rolled -Offset $script:EngineLogOffset -Into $fresh)
        }
        $script:EngineLogOffset = 0
    }

    $script:EngineLogOffset = Read-CompleteLine -Path $engineLog -Offset $script:EngineLogOffset -Into $fresh
    foreach ($line in $fresh) { $script:EngineLines.Add($line) }
    $fresh.ToArray()
}

function Format-LogLine {
    # Drops the date and the UTC offset. The time is what tells the lines of one request apart.
    param([string]$Line)
    return ($Line -replace '^\d{4}-\d{2}-\d{2} (\d{2}:\d{2}:\d{2}\.\d{3}) [+-]\d{2}:\d{2} ', '$1 ')
}

function Get-ConnectCount {
    param([string]$Pattern = $connectPattern)
    return ([regex]::Matches((Read-SharedText $testbedLog), $Pattern)).Count
}

function Test-SignedRule {
    # The line --explain prints under "Rules in force" for the test rule. The separators between the
    # fields are not ASCII and depend on the console code page, so they are not matched. Case-sensitive:
    # a process row says "signed identity of", and must not pass for the rule.
    param([string[]]$Lines)
    return @($Lines | Where-Object { $_ -cmatch '\bProxy\b.*\bSigned\b.*\bsigned by .*\bprobe\.exe\b' }).Count -eq 1
}

function Get-ExplainRow {
    # The "now :" line --explain prints under a process's path.
    param([string[]]$Lines, [string]$Exe)

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i].Trim() -eq $Exe) {
            for ($j = $i + 1; $j -lt [Math]::Min($i + 6, $Lines.Count); $j++) {
                if ($Lines[$j] -match '^\s+now\s+:') { return $Lines[$j].Trim() }
            }
        }
    }
    return $null
}

function Invoke-Probe {
    param([string]$Exe)

    # stderr is not merged in: under $ErrorActionPreference = 'Stop', Windows PowerShell turns a native
    # command's redirected stderr into a terminating error. -s keeps curl quiet there anyway.
    $output = & $Exe -s -o NUL --noproxy '*' --max-time 20 `
        -w 'http_code=%{http_code} time=%{time_total}s' $targetUrl
    $exit = $LASTEXITCODE

    $text = (@($output) -join ' ').Trim()
    if ($text.Length -eq 0) { $text = 'no output' }
    $code = if ($text -match 'http_code=(\d{3})') { $Matches[1] } else { '000' }
    return [pscustomobject]@{ Text = $text; Exit = $exit; HttpCode = $code }
}

function Show-EngineEvidence {
    param([string[]]$Lines, [string]$Exe)

    $identityLine = "identity: $Exe"
    $relevant = @($Lines | Where-Object {
            $_.IndexOf($identityLine, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $_ -match '\b(HOLD|PROXY|BLOCK|relaying) probe\.exe\b' -or
            $_ -match 'proxy handshake failed|refused unrecognised'
        })

    Write-Host '      engine  :'
    if ($relevant.Count -eq 0) {
        Write-Host '        nothing about probe.exe - the connection was never attributed to it, or never decided'
    }
    else {
        $relevant | Select-Object -First 8 | ForEach-Object { Write-Host "        $(Format-LogLine $_)" }
    }

    # Verification is reported once per file. If it happened before this scenario began, say so
    # rather than leave its absence to be read as "never verified".
    if (-not ($relevant | Where-Object { $_.IndexOf($identityLine, [StringComparison]::OrdinalIgnoreCase) -ge 0 })) {
        $earlier = @($script:EngineLines | Where-Object {
                $_.IndexOf($identityLine, [StringComparison]::OrdinalIgnoreCase) -ge 0 }) | Select-Object -Last 1
        if ($earlier) {
            Write-Host "        (verified earlier) $(Format-LogLine $earlier)"
        }
    }
}

function Invoke-ProbeScenario {
    param([string]$Name, [string]$Story, [string]$Exe)

    Write-Host ''
    Write-Host "  [$Name] $Story" -ForegroundColor Yellow
    Write-Host "      probe   : $Exe"

    $null = Read-NewEngineLog
    $before = Get-ConnectCount
    $beforeAll = Get-ConnectCount -Pattern 'CONNECT '
    $run = Invoke-Probe -Exe $Exe
    Start-Sleep -Seconds 1
    $delta = (Get-ConnectCount) - $before
    $deltaAll = (Get-ConnectCount -Pattern 'CONNECT ') - $beforeAll
    $lines = @(Read-NewEngineLog)

    Write-Host ("      curl    : {0} (exit {1})" -f $run.Text, $run.Exit)
    Write-Host ("      upstream: {0:+0;-0;+0} CONNECT to {1}:80" -f $delta, $target)
    if ($deltaAll -gt $delta) {
        Write-Host ("                and {0} other CONNECT(s) - something else matched the rule meanwhile" -f ($deltaAll - $delta))
    }
    Show-EngineEvidence -Lines $lines -Exe $Exe

    $pass = ($delta -eq 1) -and ($run.HttpCode -eq '200')
    $note = $null
    if ($delta -eq 1 -and -not $pass) { $note = 'reached the proxy, but the exchange did not complete' }
    elseif ($delta -eq 0) { $note = 'never reached the proxy' }

    $results.Add([pscustomobject]@{
            Scenario = $Name; Expected = '+1'; Delta = $delta; Result = $run.Text; Pass = $pass; Note = $note
        })
}

function Test-DirectConnect {
    param([string]$Address, [int]$Port, [int]$TimeoutMs)

    $client = New-Object System.Net.Sockets.TcpClient
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $pending = $client.ConnectAsync($Address, $Port)
        if ($pending.Wait($TimeoutMs)) {
            return [pscustomobject]@{ Connected = $true; Text = ('connected after {0:N2}s' -f $watch.Elapsed.TotalSeconds) }
        }
        return [pscustomobject]@{ Connected = $false; Text = ('no connection in {0}s' -f [int]($TimeoutMs / 1000)) }
    }
    catch {
        return [pscustomobject]@{
            Connected = $false
            Text      = ('failed after {0:N2}s: {1}' -f $watch.Elapsed.TotalSeconds, $_.Exception.GetBaseException().Message)
        }
    }
    finally {
        $client.Close()
    }
}

function ConvertTo-Quoted {
    param([string]$Text)
    return "'" + $Text.Replace("'", "''") + "'"
}

# ---- Before anything changes: what is there, and whether it is safe to go on ----------------------
Write-Host "  session         : $(if ($script:IsElevated) { 'elevated' } else { 'not elevated - dry run only' })"
$engine = Get-EngineBinary -Root $root
$testbed = Get-TestbedBinary -Root $root
if (-not (Test-Path -LiteralPath $curl)) { throw "$curl is missing, and the probe is a copy of it." }

$service = Get-Service -Name 'SplitLane' -ErrorAction SilentlyContinue
$serviceStatus = if ($service) { [string]$service.Status } else { 'not installed' }
$servicePid = 0
if ($service -and $service.Status -eq 'Running') {
    $servicePid = [int](Get-CimInstance -ClassName Win32_Service -Filter "Name='SplitLane'").ProcessId
}
Write-Host "  service         : SplitLane $serviceStatus$(if ($servicePid) { " (pid $servicePid)" })"

foreach ($name in ($trackedFiles | Select-Object -First 2)) {
    $path = Join-Path $dataRoot $name
    Write-Host ("  {0,-16}: {1}" -f $name, $(if (Test-Path -LiteralPath $path) { "present, $((Get-Item -LiteralPath $path).Length) bytes" } else { 'absent' }))
}
$policyPresent = Test-Path -LiteralPath $policyFile
Write-Host ("  {0,-16}: {1}" -f 'managed policy', $(if ($policyPresent) { "present at $policyFile" } else { 'none' }))
if ($policyPresent) {
    # Applied on top of the test rule by the engine. If it adds rules or sets the user's aside, the run
    # stops at the engine's own account of what it applied rather than measure something else.
    Write-Host '  note: a managed policy is in place and the engine will apply it; the run stops if it' -ForegroundColor Yellow
    Write-Host '        adds rules or sets the test rule aside.' -ForegroundColor Yellow
}

# Engines this script did not start. Two engines diverting at once would make any result meaningless,
# and the installed service is the only one this script is entitled to stop.
$strays = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='SplitLane.Engine.exe'" |
    Where-Object { [int]$_.ProcessId -ne $servicePid })

$leftover = $false
try {
    $leftover = (Test-Path -LiteralPath $liveConfig) -and
        [bool](Select-String -LiteralPath $liveConfig -SimpleMatch $marker -Quiet)
}
catch {
    Write-Host "  note: could not read $liveConfig ($($_.Exception.Message))" -ForegroundColor Yellow
}

$refusals = @()
if ($service -and $serviceStatus -notin @('Running', 'Stopped')) {
    $refusals += "The SplitLane service is $serviceStatus. Run this again once it has settled."
}
foreach ($stray in $strays) {
    $refusals += "SplitLane.Engine.exe pid $($stray.ProcessId) is running and is not the service " +
        "($($stray.ExecutablePath)). Stop it first: Stop-Process -Id $($stray.ProcessId)"
}
if ($leftover) {
    $refusals += "$liveConfig is the test configuration from an interrupted run, not your own. " +
        'Restore it from the newest artifacts\verify-identity-*\backup (restore-instructions.txt ' +
        'there says how) before running this again - otherwise it would be backed up as yours.'
}

if ($refusals.Count -gt 0 -and -not $DryRun) {
    Write-Host ''
    Write-Host '  Refused - nothing was changed:' -ForegroundColor Red
    foreach ($reason in $refusals) { Write-Host "    $reason" }
    exit 1
}
foreach ($reason in $refusals) { Write-Host "  note: a real run would refuse: $reason" -ForegroundColor Yellow }

if (-not $DryRun -and (Get-Process -Name 'SplitLane' -ErrorAction SilentlyContinue)) {
    Write-Host '  note: the SplitLane app is open. It will talk to the test engine while this runs.' -ForegroundColor Yellow
    Write-Host '        Leave it alone: anything changed in it now is discarded by the restore.' -ForegroundColor Yellow
}

# ---- The run --------------------------------------------------------------------------------------
$state = @{
    Testbed           = $null
    Engine            = $null
    Parked            = $null
    Files             = @()
    PolicyDirExisted  = $true
    BackupComplete    = $false
    ServiceWasRunning = $false
    ServiceStopped    = $false
    ProbeCreated      = $false
}
$script:EngineLines = New-Object System.Collections.Generic.List[string]
$script:EngineLogOffset = [long]0
$results = New-Object System.Collections.Generic.List[object]
$restoreProblems = New-Object System.Collections.Generic.List[string]
$failure = $null
$verdict = $false

try {
    New-Item -ItemType Directory -Force -Path $artifacts | Out-Null
    Write-Host "  artifacts       : $($artifacts.Substring($root.Length).TrimStart('\'))"

    # ---- 1. The upstream, which is where the proof comes from --------------------------------------
    # Answering as the origin (--serve-payload-kb) is what lets the destination be TEST-NET: the
    # server never dials it, so a request that succeeds was proxied and nothing else.
    $state.Testbed = Start-Process -FilePath $testbed -ArgumentList '--serve-payload-kb', '1' `
        -WindowStyle Hidden -RedirectStandardOutput $testbedLog -RedirectStandardError $testbedErr -PassThru
    $null = $state.Testbed.Handle

    $proxyPort = 0
    for ($i = 0; $i -lt 40 -and -not $proxyPort; $i++) {
        Start-Sleep -Milliseconds 250
        if ((Read-SharedText $testbedLog) -match '127\.0\.0\.1:(\d+)') { $proxyPort = [int]$Matches[1] }
        elseif ($state.Testbed.HasExited) { break }
    }
    if (-not $proxyPort) { throw "The test SOCKS5 server did not start. See $testbedLog and $testbedErr." }
    Write-Host "  test server     : 127.0.0.1:$proxyPort, pid $($state.Testbed.Id) (answers as the origin; logs every CONNECT)"

    # ---- 2. The application, where it was picked ---------------------------------------------------
    if (Test-Path -LiteralPath $probeRoot) {
        # Left by an earlier run that did not finish. It is this script's own directory, by name.
        Remove-Item -LiteralPath $probeRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $pickedExe -Parent) | Out-Null
    $state.ProbeCreated = $true
    Copy-Item -LiteralPath $curl -Destination $pickedExe
    Write-Host "  probe           : $pickedExe (a copy of curl.exe)"

    # ---- 3. The rule, exactly as the app would make it ---------------------------------------------
    $describe = @(& $engine --describe $pickedExe)
    $describeExit = $LASTEXITCODE
    $describeText = ($describe -join "`n")
    [IO.File]::WriteAllText($describeFile, $describeText, $utf8)
    if ($describeExit -ne 0) { throw "--describe refused the probe (exit $describeExit): $describeText" }

    $identity = $describeText | ConvertFrom-Json
    if ($identity.kind -ne 'Signed' -or $identity.binaryName -ne 'probe.exe') {
        throw "--describe produced a $($identity.kind) identity for $($identity.binaryName); the test needs a " +
            "Signed one for probe.exe. curl.exe on this machine may not carry an embedded signature. See $describeFile."
    }
    Write-Host "  identity        : $($identity.kind) - signed by $($identity.publisher), product '$($identity.productName)', $($identity.binaryName)"

    # Every member named here exists on RuntimeConfiguration, AppRule, AppIdentity and
    # ProxyConfiguration. The codec rejects a member it does not know, so nothing may be invented.
    $configuration = [ordered]@{
        version          = [ordered]@{ schemaVersion = 2; generation = 1 }
        rules            = @([ordered]@{
                identity  = $identity
                action    = 'Proxy'
                matchMode = 'ExecutableFamily'
                isEnabled = $true
                status    = 'Active'
            })
        proxy            = [ordered]@{
            id                           = [guid]::NewGuid().ToString()
            displayName                  = $marker
            type                         = 'Socks5'
            endpoint                     = [ordered]@{ host = '127.0.0.1'; port = $proxyPort }
            isEnabled                    = $true
            handshakeTimeoutMilliseconds = 8000
            allowDirectFallback          = $false
            preferHostnames              = $true
        }
        isRoutingEnabled = $true
        logsDirectFlows  = $false
        proxiesUdp       = $false
        redirectPort     = 0
    }
    $json = $configuration | ConvertTo-Json -Depth 10

    # Without a byte order mark: Set-Content -Encoding utf8 writes one in Windows PowerShell, and a
    # configuration is a file other programs read too.
    [IO.File]::WriteAllText($stagedConfig, $json, $utf8)

    $staged = @(& $engine --explain --config $stagedConfig)
    $stagedExit = $LASTEXITCODE
    [IO.File]::WriteAllLines($explainStaged, [string[]]$staged, $utf8)
    if ($stagedExit -ne 0 -or -not (Test-SignedRule $staged)) {
        throw "The engine did not accept the generated configuration (exit $stagedExit). See $explainStaged."
    }
    Write-Host '  configuration   : generated; the engine parses it and lists the rule as Signed'
    $staged | Where-Object { $_ -cmatch '^Configuration:|^Rules in force|\bSigned\b' } |
        ForEach-Object { Write-Host "    $($_.Trim())" }

    if ($DryRun) {
        Write-Host ''
        Write-Host '================ DRY RUN ================' -ForegroundColor Cyan
        Write-Host '  Everything that needs no privilege worked. A real run would now:'
        Write-Host "    - back up configuration.json and configuration.v2.json to $($backupDir.Substring($root.Length).TrimStart('\'))"
        Write-Host "    - stop the SplitLane service (now: $serviceStatus) and start it again afterwards"
        Write-Host "    - write the generated configuration to $liveConfig"
        Write-Host '    - start the engine above, run the four scenarios, and restore the machine'
        Write-Host "  Nothing under $dataRoot was touched, and the service was not."
        Write-Host '=========================================' -ForegroundColor Cyan
    }
    else {
        # ---- 4. The backup, before anything changes ------------------------------------------------
        Write-Host ''
        Write-Host '  From here the machine is changed, and put back afterwards. While the test runs your own' -ForegroundColor Yellow
        Write-Host '  rules are not in force: applications you selected are not proxied for about a minute.' -ForegroundColor Yellow

        New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
        $records = @()
        foreach ($name in $trackedFiles) {
            $path = Join-Path $dataRoot $name
            $record = [pscustomobject]@{
                Name = $name; Path = $path; Existed = $false; Sha256 = $null; LastWriteUtc = $null; Backup = $null
            }

            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $record.Existed = $true
                $record.LastWriteUtc = [IO.File]::GetLastWriteTimeUtc($path)
                $record.Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
                $record.Backup = Join-Path $backupDir $name
                Copy-Item -LiteralPath $path -Destination $record.Backup -Force

                if ((Get-FileHash -LiteralPath $record.Backup -Algorithm SHA256).Hash -ne $record.Sha256) {
                    throw "The backup of $name does not match the original. Nothing has been changed."
                }
            }

            $records += $record
        }
        $state.Files = $records
        $state.PolicyDirExisted = Test-Path -LiteralPath $policyDir
        $state.BackupComplete = $true

        # By hand, for the one case the finally below cannot cover: the window closed mid-run.
        $notes = New-Object System.Collections.Generic.List[string]
        $notes.Add("SplitLane identity verification, started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').")
        $notes.Add('If the run was interrupted before it restored the machine, run these from an elevated PowerShell.')
        $notes.Add('')
        $notes.Add('# 1. Stop the test engine and test server - by the path they run from, not by image name,')
        $notes.Add('#    which would also stop the installed service.')
        foreach ($exe in @($engine, $testbed)) {
            $notes.Add("Get-CimInstance Win32_Process | Where-Object { `$_.ExecutablePath -eq $(ConvertTo-Quoted $exe) } | ForEach-Object { Stop-Process -Id `$_.ProcessId -Force }")
        }
        $notes.Add('')
        $notes.Add('# 2. Put the configuration back.')
        foreach ($record in $records) {
            if ($record.Existed) {
                $notes.Add("Copy-Item -LiteralPath $(ConvertTo-Quoted $record.Backup) -Destination $(ConvertTo-Quoted $record.Path) -Force   # sha256 $($record.Sha256)")
                $notes.Add("[IO.File]::SetLastWriteTimeUtc($(ConvertTo-Quoted $record.Path), [DateTime]::Parse('$($record.LastWriteUtc.ToString('o'))').ToUniversalTime())")
            }
            else {
                $notes.Add("Remove-Item -LiteralPath $(ConvertTo-Quoted $record.Path) -Force -ErrorAction SilentlyContinue   # did not exist before the run")
            }
        }
        if (-not $state.PolicyDirExisted) {
            $notes.Add("Remove-Item -LiteralPath $(ConvertTo-Quoted $policyDir) -ErrorAction SilentlyContinue   # created by the test engine; only if empty")
        }
        $notes.Add('')
        if ($serviceStatus -eq 'Running') {
            $notes.Add('# 3. Start the service again - it was running before the run.')
            $notes.Add('Start-Service SplitLane')
        }
        else {
            $notes.Add("# 3. The service was $serviceStatus before the run; leave it that way.")
        }
        $notes.Add('')
        $notes.Add('# 4. Remove the probe copies.')
        $notes.Add("Remove-Item -LiteralPath $(ConvertTo-Quoted $probeRoot) -Recurse -Force")
        [IO.File]::WriteAllLines($restoreNotes, $notes.ToArray(), $utf8)

        foreach ($record in ($records | Where-Object { $_.Name -ne 'configuration.v2.json.tmp' -or $_.Existed })) {
            Write-Host ("  backed up       : {0,-24} {1}" -f $record.Name,
                $(if ($record.Existed) { "sha256 $($record.Sha256.Substring(0, 16))..." } else { 'absent - will be deleted afterwards if created' }))
        }
        Write-Host "  by hand         : $restoreNotes"

        # ---- 5. The installed service, out of the way ----------------------------------------------
        if ($service -and $service.Status -eq 'Running') {
            $state.ServiceWasRunning = $true
            # Recorded before the call, so a stop that half-happens is still undone.
            $state.ServiceStopped = $true
            Write-Host '  stopping the SplitLane service...'
            Stop-Service -Name 'SplitLane' -Force -WarningAction SilentlyContinue
            $service.Refresh()
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
            if ($servicePid) {
                # Its process holds the divert handles; the service reporting Stopped is not the same as
                # the process being gone. The check below says so if it is still there.
                try { Wait-Process -Id $servicePid -Timeout 30 -ErrorAction SilentlyContinue } catch { }
            }
            Write-Host '  service         : stopped'
        }

        $remaining = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='SplitLane.Engine.exe'")
        if ($remaining.Count -gt 0) {
            throw "SplitLane.Engine.exe is still running after the service stopped (pid " +
                "$(($remaining | ForEach-Object { $_.ProcessId }) -join ', ')). A second engine diverting beside it " +
                'would make the result meaningless.'
        }

        # ---- 6. The test rule, where the engine reads it -------------------------------------------
        # configuration.json is left alone. The store reads configuration.v2.json unless the schema 1
        # file is newer, and this one is written last - but a clock that has moved backwards could
        # still make the older file look newer, so that is checked rather than assumed.
        New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null
        [IO.File]::WriteAllText($liveConfig, $json, $utf8)
        if (Test-Path -LiteralPath $legacyConfig) {
            $legacyTime = [IO.File]::GetLastWriteTimeUtc($legacyConfig)
            if ([IO.File]::GetLastWriteTimeUtc($liveConfig) -le $legacyTime) {
                [IO.File]::SetLastWriteTimeUtc($liveConfig, $legacyTime.AddSeconds(2))
            }
        }

        $accepted = @(& $engine --explain)
        $acceptedExit = $LASTEXITCODE
        [IO.File]::WriteAllLines($explainInstalled, [string[]]$accepted, $utf8)
        $sourceLine = @($accepted | Where-Object { $_ -match '^Configuration:' }) | Select-Object -First 1
        if ($acceptedExit -ne 0 -or $sourceLine -notmatch 'configuration\.v2\.json \(schema 2, generation 1, 1 rules\)' -or
            -not (Test-SignedRule $accepted)) {
            throw "The engine would not read the test configuration from $liveConfig. It reports: $sourceLine. See $explainInstalled."
        }
        Write-Host "  configuration   : written to $liveConfig; the engine will read it"

        # ---- 7. The engine under test --------------------------------------------------------------
        $script:EngineLogOffset = if (Test-Path -LiteralPath $engineLog) { (Get-Item -LiteralPath $engineLog).Length } else { [long]0 }

        # Output goes to files and the console sink is off: an elevated console window with QuickEdit
        # blocks Console.WriteLine on a stray click, and takes every thread that logs with it.
        $state.Engine = Start-Process -FilePath $engine -ArgumentList '--verbose', '--no-console-log' `
            -WindowStyle Hidden -RedirectStandardOutput $engineOut -RedirectStandardError $engineErr -PassThru
        $null = $state.Engine.Handle
        Write-Host "  engine started  : pid $($state.Engine.Id)"

        $listenerPort = 0
        $deadline = (Get-Date).AddSeconds(45)
        while (-not $listenerPort -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
            foreach ($line in @(Read-NewEngineLog)) {
                if ($line -match 'listener port (\d+)') { $listenerPort = [int]$Matches[1] }
                if ($line -match 'could not start routing|must run elevated') {
                    throw "The engine could not start routing: $(Format-LogLine $line)"
                }
            }
            if (-not $listenerPort -and $state.Engine.HasExited) {
                throw "The engine exited (code $($state.Engine.ExitCode)) before it started routing. See $engineOut and $engineErr."
            }
        }
        if (-not $listenerPort) { throw 'The engine did not report a listener port within 45 s.' }

        # Exactly the test rule and nothing else: no managed rules added, none of the user's set aside.
        # The count of managed rules is absent from builds before the managed policy existed.
        $applied = @($script:EngineLines | Where-Object { $_ -match 'configuration generation \d+ applied:' }) | Select-Object -Last 1
        if ($applied -notmatch 'applied: 1 active rules \(1 by identity(, 0 managed)?\)') {
            throw "The engine did not apply the test configuration. It logged: $(if ($applied) { Format-LogLine $applied } else { 'nothing' })"
        }
        Write-Host "  engine up       : divert started, redirect listener on port $listenerPort, 1 rule by identity"
        Start-Sleep -Seconds 1

        # ---- 8. The scenarios ----------------------------------------------------------------------
        Invoke-ProbeScenario -Name 'picked' -Story 'the copy the rule was made from' -Exe $pickedExe

        New-Item -ItemType Directory -Force -Path (Split-Path $updatedExe -Parent) | Out-Null
        Copy-Item -LiteralPath $curl -Destination $updatedExe
        Remove-Item -LiteralPath (Split-Path $pickedExe -Parent) -Recurse -Force
        Invoke-ProbeScenario -Name 'updated' -Story 'a new hash directory, and the old one deleted' -Exe $updatedExe

        New-Item -ItemType Directory -Force -Path (Split-Path $movedExe -Parent) | Out-Null
        Copy-Item -LiteralPath $curl -Destination $movedExe
        Invoke-ProbeScenario -Name 'moved' -Story 'a folder with nothing in common with the first' -Exe $movedExe

        # The control: the same destination, from an application the rule does not describe. It goes
        # DIRECT, and DIRECT to TEST-NET goes nowhere, so the attempt times out and the upstream sees
        # nothing. A CONNECT here would mean the rule reaches further than the application.
        Write-Host ''
        Write-Host '  [other application] PowerShell connects to the same address; it is not selected' -ForegroundColor Yellow
        Write-Host "      process : $((Get-Process -Id $PID).Path) (pid $PID)"
        $null = Read-NewEngineLog
        $before = Get-ConnectCount
        $direct = Test-DirectConnect -Address $target -Port 80 -TimeoutMs 3000
        Start-Sleep -Seconds 1
        $delta = (Get-ConnectCount) - $before
        $lines = @(Read-NewEngineLog)
        $decided = @($lines | Where-Object { $_ -match '\b(HOLD|PROXY|BLOCK) powershell' })

        Write-Host "      connect : $($direct.Text)"
        Write-Host ("      upstream: {0:+0;-0;+0} CONNECT to {1}:80" -f $delta, $target)
        Write-Host '      engine  :'
        if ($decided.Count -eq 0) {
            Write-Host '        no decision about PowerShell logged - DIRECT, which is not logged by default'
        }
        else {
            $decided | Select-Object -First 4 | ForEach-Object { Write-Host "        $(Format-LogLine $_)" }
        }
        if ($direct.Connected) {
            # Not SplitLane: the upstream saw nothing. A TUN-mode VPN completes the handshake itself.
            Write-Host '      note    : something on this machine or its network answers for TEST-NET without' -ForegroundColor Yellow
            Write-Host '                the proxy. The upstream saw nothing, so it was not SplitLane.' -ForegroundColor Yellow
        }

        $controlPass = $delta -eq 0
        $results.Add([pscustomobject]@{
                Scenario = 'other application'; Expected = '+0'; Delta = $delta
                Result   = "$($direct.Text) (DIRECT)"; Pass = $controlPass
                Note     = $(if (-not $controlPass) { 'an unselected application was proxied' } else { $null })
            })

        # ---- 9. What --explain says about it -------------------------------------------------------
        # With the moved copy parked - curl reading a config file from a stdin that never ends - so the
        # engine's own explanation has a running process to explain. It opens no socket.
        $parkedInfo = New-Object Diagnostics.ProcessStartInfo
        $parkedInfo.FileName = $movedExe
        $parkedInfo.Arguments = '-K -'
        $parkedInfo.UseShellExecute = $false
        $parkedInfo.RedirectStandardInput = $true
        $parkedInfo.RedirectStandardOutput = $true
        $parkedInfo.RedirectStandardError = $true
        $parkedInfo.CreateNoWindow = $true
        $state.Parked = [Diagnostics.Process]::Start($parkedInfo)
        Start-Sleep -Milliseconds 300

        $explain = @(& $engine --explain)
        [IO.File]::WriteAllLines($explainFile, [string[]]$explain, $utf8)
        $explainRow = Get-ExplainRow -Lines $explain -Exe $movedExe

        if (-not $state.Parked.HasExited) {
            $state.Parked.Kill()
            [void]$state.Parked.WaitForExit(5000)
        }

        # ---- 10. The verdict -----------------------------------------------------------------------
        $counters = @($script:EngineLines | Where-Object { $_ -match 'socket events' }) | Select-Object -Last 1

        Write-Host ''
        Write-Host '================ RESULT ================' -ForegroundColor Cyan
        Write-Host ('  {0,-18} {1,-9} {2,-8} {3,-44} {4}' -f 'scenario', 'expected', 'CONNECT', 'result', 'verdict')
        foreach ($result in $results) {
            Write-Host ('  {0,-18} {1,-9} {2,-8} {3,-44} ' -f $result.Scenario, $result.Expected,
                ('{0:+0;-0;+0}' -f $result.Delta), $result.Result) -NoNewline
            if ($result.Pass) { Write-Host 'PASS' -ForegroundColor Green }
            else { Write-Host "FAIL - $($result.Note)" -ForegroundColor Red }
        }
        Write-Host ''
        Write-Host '  A time of about a second is the held first SYN: the file was new to the engine, its'
        Write-Host '  signature was verified while the SYN waited, and the retransmission was redirected.'
        Write-Host ''
        Write-Host "  --explain       : $(if ($explainRow) { $explainRow } else { 'no row for the moved copy' })"
        Write-Host "  counters        : $(if ($counters) { (Format-LogLine $counters).Trim() } else { 'none logged' })"
        Write-Host ''

        $verdict = ($results.Count -eq 4) -and -not ($results | Where-Object { -not $_.Pass })
        if ($verdict) {
            Write-Host '  IDENTITY SURVIVES AN UPDATE AND A MOVE' -ForegroundColor Green
            Write-Host '  The same signed binary was proxied from the folder it was picked in, from a new hash'
            Write-Host '  directory after the old one was deleted, and from an unrelated folder - matched by signer,'
            Write-Host '  product and file name, never by path. PowerShell, aimed at the same address, was left alone.'
        }
        else {
            Write-Host '  IDENTITY VERIFICATION FAILED' -ForegroundColor Red
            $byName = @{}
            foreach ($result in $results) { $byName[$result.Scenario] = $result.Pass }
            if (-not $byName['picked']) {
                Write-Host '  Not even the copy the rule was made from was proxied. Look at the engine lines above: no'
                Write-Host '  HOLD or PROXY for probe.exe means the connection was never attributed to it or the rule'
                Write-Host '  did not match; a PROXY with no CONNECT means the failure is after the redirect.'
            }
            elseif (-not $byName['updated'] -or -not $byName['moved']) {
                Write-Host '  The copy the rule was made from was proxied and a copy elsewhere was not: the rule is still'
                Write-Host '  behaving like a path.'
            }
            if ($byName.ContainsKey('other application') -and -not $byName['other application']) {
                Write-Host '  An application the rule does not describe reached the proxy: the rule is too broad.'
            }
        }
        Write-Host '=======================================' -ForegroundColor Cyan
    }
}
catch {
    $failure = $_
    Write-Host ''
    Write-Host "  ABORTED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  (line $($_.InvocationInfo.ScriptLineNumber))"
}
finally {
    Write-Host ''
    Write-Host "  ---- $(if ($state.BackupComplete) { 'putting the machine back' } else { 'cleaning up' }) ----" -ForegroundColor Cyan

    # Each process by the object it was started with. Holding the object holds a handle, so its pid
    # cannot have been reused by something else in the meantime.
    $owned = @(
        @{ Name = 'parked probe'; Process = $state.Parked },
        @{ Name = 'test engine'; Process = $state.Engine },
        @{ Name = 'test server'; Process = $state.Testbed }
    )
    foreach ($entry in $owned) {
        $process = $entry.Process
        if ($null -eq $process) { continue }
        try {
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                [void]$process.WaitForExit(10000)
            }
            if ($process.HasExited) {
                if ($entry.Name -ne 'parked probe') { Write-Host ("    {0,-22}: stopped (pid {1})" -f $entry.Name, $process.Id) }
            }
            else {
                $restoreProblems.Add("the $($entry.Name) (pid $($process.Id)) is still running")
            }
        }
        catch {
            $restoreProblems.Add("could not stop the $($entry.Name) (pid $($process.Id)): $($_.Exception.Message)")
        }
    }

    if ($state.Engine) {
        try {
            $null = Read-NewEngineLog
            [IO.File]::WriteAllLines($engineExcerpt, $script:EngineLines.ToArray(), $utf8)
        }
        catch {
            Write-Host "    engine log excerpt    : not saved ($($_.Exception.Message))" -ForegroundColor Yellow
        }
    }

    # The configuration: byte for byte, checked against the hash taken before anything changed. The
    # write goes into the existing file rather than replacing it, so its ACL is kept; the timestamp is
    # put back too, because it decides which of the two documents the store reads.
    if ($state.BackupComplete) {
        foreach ($record in $state.Files) {
            try {
                $exists = Test-Path -LiteralPath $record.Path -PathType Leaf

                if (-not $record.Existed) {
                    if ($exists) {
                        Remove-Item -LiteralPath $record.Path -Force
                        Write-Host ("    {0,-22}: removed - it did not exist before this run" -f $record.Name)
                    }
                    elseif ($record.Name -ne 'configuration.v2.json.tmp') {
                        Write-Host ("    {0,-22}: absent, as before" -f $record.Name)
                    }
                    continue
                }

                $current = if ($exists) { (Get-FileHash -LiteralPath $record.Path -Algorithm SHA256).Hash } else { $null }
                $action = 'unchanged'
                if ($current -ne $record.Sha256) {
                    [IO.File]::WriteAllBytes($record.Path, [IO.File]::ReadAllBytes($record.Backup))
                    $action = 'restored from backup'
                }
                if ([IO.File]::GetLastWriteTimeUtc($record.Path) -ne $record.LastWriteUtc) {
                    [IO.File]::SetLastWriteTimeUtc($record.Path, $record.LastWriteUtc)
                }

                $after = (Get-FileHash -LiteralPath $record.Path -Algorithm SHA256).Hash
                if ($after -eq $record.Sha256) {
                    Write-Host ("    {0,-22}: {1}, sha256 {2}... verified" -f $record.Name, $action, $record.Sha256.Substring(0, 16))
                }
                else {
                    $restoreProblems.Add("$($record.Path) does not match its backup after the restore")
                }
            }
            catch {
                $restoreProblems.Add("could not restore $($record.Path): $($_.Exception.Message)")
            }
        }
    }

    # The policy folder, if the test engine is what created it. Only while empty: anything in it was put
    # there by someone during the run, and is not this script's to delete.
    if ($state.BackupComplete -and -not $state.PolicyDirExisted -and (Test-Path -LiteralPath $policyDir)) {
        try {
            if (@(Get-ChildItem -LiteralPath $policyDir -Force).Count -eq 0) {
                Remove-Item -LiteralPath $policyDir -Force
                Write-Host ("    {0,-22}: removed - the test engine created it" -f 'Policy folder')
            }
            else {
                Write-Host ("    {0,-22}: left in place - created during the run, but no longer empty" -f 'Policy folder') -ForegroundColor Yellow
            }
        }
        catch {
            $restoreProblems.Add("could not remove $policyDir, which the test engine created: $($_.Exception.Message)")
        }
    }

    # The service, after the files, so it starts on the configuration it had - and never while the
    # test engine is still alive, which would put two engines on the divert layer.
    if ($state.ServiceWasRunning -and $state.ServiceStopped) {
        if ($state.Engine -and -not $state.Engine.HasExited) {
            $restoreProblems.Add('the SplitLane service was not started again, because the test engine is still running')
        }
        else {
            try {
                Start-Service -Name 'SplitLane' -WarningAction SilentlyContinue
                $restarted = Get-Service -Name 'SplitLane'
                $restarted.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
                $newPid = (Get-CimInstance -ClassName Win32_Service -Filter "Name='SplitLane'").ProcessId
                Write-Host ("    {0,-22}: running again (pid {1}), as before the run" -f 'service SplitLane', $newPid)
            }
            catch {
                $restoreProblems.Add("the SplitLane service did not start again: $($_.Exception.Message)")
            }
        }
    }
    elseif ($state.BackupComplete) {
        Write-Host ("    {0,-22}: left {1}, as before the run" -f 'service SplitLane', $serviceStatus)
    }

    if ($state.ProbeCreated -and (Test-Path -LiteralPath $probeRoot)) {
        $removed = $false
        for ($attempt = 0; $attempt -lt 5 -and -not $removed; $attempt++) {
            try {
                Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction Stop
                $removed = $true
            }
            catch {
                Start-Sleep -Milliseconds 500
            }
        }
        if ($removed) { Write-Host ("    {0,-22}: removed" -f 'probe copies') }
        else { $restoreProblems.Add("could not remove $probeRoot") }
    }

    if ($restoreProblems.Count -gt 0) {
        Write-Host ''
        Write-Host '  RESTORE INCOMPLETE' -ForegroundColor Red
        foreach ($problem in $restoreProblems) { Write-Host "    $problem" -ForegroundColor Red }
        if ($state.BackupComplete) { Write-Host "  Finish it by hand: $restoreNotes" -ForegroundColor Red }
    }
    elseif ($state.BackupComplete) {
        Write-Host '  the machine is as it was before the run'
    }

    if (Test-Path -LiteralPath $artifacts) { Write-Host "  artifacts: $artifacts" }
}

if ($restoreProblems.Count -gt 0) { exit 2 }
if ($failure) { exit 1 }
if ($DryRun -or $verdict) { exit 0 }
exit 1
