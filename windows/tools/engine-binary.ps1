<#
.SYNOPSIS
    Finds the engine build a script should actually run, and says which one it picked.

.DESCRIPTION
    The build writes SplitLane.Engine.exe to a path that depends on configuration and platform, and
    the tools were pointed at one fixed path. A solution build put a fresh binary somewhere else and
    left the old one in place, so a measurement of a change that had already been made came back
    identical to the measurement before it - correct to three digits, and about the wrong program.

    So: take the newest one, and print its timestamp. A stale binary can be forgiven; one that passes
    for a result cannot.
#>
function Get-EngineBinary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [switch]$Quiet)

    $candidates = @(Get-ChildItem -Path (Join-Path $Root 'src\SplitLane.Engine\bin') `
            -Filter 'SplitLane.Engine.exe' -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)

    if ($candidates.Count -eq 0) {
        throw "No SplitLane.Engine.exe under $Root\src\SplitLane.Engine\bin - build it first."
    }

    $chosen = $candidates[0]
    if (-not $Quiet) {
        $relative = $chosen.FullName.Substring($Root.Length).TrimStart('\')
        Write-Host ("  engine          : {0}  (built {1:HH:mm:ss})" -f $relative, $chosen.LastWriteTime)
    }

    return $chosen.FullName
}
