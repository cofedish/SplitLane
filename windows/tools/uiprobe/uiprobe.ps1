<#
    Drives the SplitLane window through UI Automation and captures screenshots.

    Used to review the interface without a person sitting in front of it: launch, click a control by
    its AutomationId, wait, capture. The AutomationIds it addresses are set explicitly in the XAML,
    so this doubles as a check that the UI is reachable by a screen reader.
#>
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string[]]$Steps = @()
)

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing, System.Windows.Forms

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Bitmap.Save resolves a relative path against the *process* working directory, which is not the
# PowerShell location and is usually somewhere unwritable. It reports the failure as a bare
# "generic error occurred in GDI+", so this is resolved up front rather than diagnosed later.
$OutDir = (Resolve-Path $OutDir).ProviderPath

function Get-MainWindow {
    param([int]$ProcessId, [int]$TimeoutSeconds = 25)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $condition = New-Object Windows.Automation.PropertyCondition(
            [Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId)
        $element = [Windows.Automation.AutomationElement]::RootElement.FindFirst(
            [Windows.Automation.TreeScope]::Children, $condition)
        if ($element) { return $element }
        Start-Sleep -Milliseconds 300
    }
    throw "No window appeared for process $ProcessId"
}

function Save-Shot {
    param($Window, [string]$Name)

    # Capture is screen-region based, so whatever is on top gets captured — including, on a machine
    # someone is actually using, an unrelated application that stole focus. Re-assert the foreground
    # and verify it took before reading pixels, rather than silently saving the wrong window.
    $hwnd = [IntPtr]$Window.Current.NativeWindowHandle
    for ($i = 0; $i -lt 10; $i++) {
        if ([Win32.Mover]::GetForegroundWindow() -eq $hwnd) { break }
        [Win32.Mover]::SetForegroundWindow($hwnd) | Out-Null
        Start-Sleep -Milliseconds 250
    }

    if ([Win32.Mover]::GetForegroundWindow() -ne $hwnd) {
        Write-Output "SKIPPED $Name - could not bring the window to the foreground"
        return
    }

    Start-Sleep -Milliseconds 200

    $rect = $Window.Current.BoundingRectangle
    if ($rect.Width -le 0) { throw "Window has no bounds" }
    $bmp = New-Object System.Drawing.Bitmap([int]$rect.Width, [int]$rect.Height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen([int]$rect.X, [int]$rect.Y, 0, 0, $bmp.Size)
    $path = Join-Path $OutDir "$Name.png"
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Output "shot $Name -> $path"
}

function Invoke-ById {
    param($Window, [string]$AutomationId)
    $condition = New-Object Windows.Automation.PropertyCondition(
        [Windows.Automation.AutomationElement]::AutomationIdProperty, $AutomationId)
    $element = $Window.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
    if (-not $element) { Write-Output "MISSING $AutomationId"; return $false }

    $pattern = $null
    if ($element.TryGetCurrentPattern([Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
        $pattern.Invoke()
    } elseif ($element.TryGetCurrentPattern([Windows.Automation.TogglePattern]::Pattern, [ref]$pattern)) {
        $pattern.Toggle()
    } elseif ($element.TryGetCurrentPattern([Windows.Automation.SelectionItemPattern]::Pattern, [ref]$pattern)) {
        $pattern.Select()
    } else {
        # Fall back to a physical click for anything with no pattern, e.g. a templated NavButton.
        $r = $element.Current.BoundingRectangle
        [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(
            [int]($r.X + $r.Width / 2), [int]($r.Y + $r.Height / 2))
        $sig = '[DllImport("user32.dll")] public static extern void mouse_event(uint f,uint x,uint y,uint d,int e);'
        if (-not ('Clicker' -as [type])) {
            Add-Type -MemberDefinition $sig -Name Clicker -Namespace Win32 | Out-Null
        }
        [Win32.Clicker]::mouse_event(0x0002, 0, 0, 0, 0)
        [Win32.Clicker]::mouse_event(0x0004, 0, 0, 0, 0)
    }
    Write-Output "clicked $AutomationId"
    return $true
}

function Set-Text {
    param($Window, [string]$AutomationId, [string]$Value)
    $condition = New-Object Windows.Automation.PropertyCondition(
        [Windows.Automation.AutomationElement]::AutomationIdProperty, $AutomationId)
    $element = $Window.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
    if (-not $element) { Write-Output "MISSING $AutomationId"; return }
    $pattern = $null
    if ($element.TryGetCurrentPattern([Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {
        $pattern.SetValue($Value)
        Write-Output "set $AutomationId = $Value"
    } else {
        Write-Output "NO VALUE PATTERN on $AutomationId"
    }
}

function Read-Text {
    param($Window, [string]$AutomationId)
    $condition = New-Object Windows.Automation.PropertyCondition(
        [Windows.Automation.AutomationElement]::AutomationIdProperty, $AutomationId)
    $element = $Window.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
    if (-not $element) { return "<missing $AutomationId>" }
    return $element.Current.Name
}

if (-not ('Win32.Mover' -as [type])) {
    Add-Type -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
'@ -Name Mover -Namespace Win32 | Out-Null
}

$proc = Start-Process -FilePath $Exe -PassThru
Start-Sleep -Milliseconds 1500
$window = Get-MainWindow -ProcessId $proc.Id

# Bring it forward so the screen capture sees it rather than whatever is on top.
# A window with custom chrome may refuse the visual-state request; it is only a nicety.
$wp = $null
if ($window.TryGetCurrentPattern([Windows.Automation.WindowPattern]::Pattern, [ref]$wp)) {
    try { $wp.SetWindowVisualState([Windows.Automation.WindowVisualState]::Normal) } catch { }
}
# Pin the window to a known spot. On a multi-monitor desktop CenterScreen can land it on a
# monitor above the primary, where a screen capture at negative coordinates catches the wrong
# pixels — or nothing at all.
$hwnd = [IntPtr]$window.Current.NativeWindowHandle
[Win32.Mover]::SetWindowPos($hwnd, [IntPtr]::Zero, 40, 40, 1400, 940, 0x0040) | Out-Null
[Win32.Mover]::SetForegroundWindow($hwnd) | Out-Null
$window.SetFocus()
Start-Sleep -Milliseconds 900

Write-Output "window: $($window.Current.Name) $($window.Current.BoundingRectangle)"

foreach ($step in $Steps) {
    $parts = $step.Split(':', 2)
    switch ($parts[0]) {
        'click' { Invoke-ById -Window $window -AutomationId $parts[1] | Out-Null; Start-Sleep -Milliseconds 700 }
        'shot'  { Save-Shot -Window $window -Name $parts[1] }
        'read'  { Write-Output ("read {0} = {1}" -f $parts[1], (Read-Text -Window $window -AutomationId $parts[1])) }
        'wait'  { Start-Sleep -Milliseconds ([int]$parts[1]) }
        'set'   {
            $kv = $parts[1].Split('=', 2)
            Set-Text -Window $window -AutomationId $kv[0] -Value $kv[1]
            Start-Sleep -Milliseconds 300
        }
        default { Write-Output "unknown step $step" }
    }
}

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Write-Output "done"
