using System.Diagnostics;
using System.IO;
using System.Text;

namespace SplitLane.App.Services;

/// <summary>
/// Reopens the window after an update has replaced it.
/// </summary>
/// <remarks>
/// <para>
/// The engine installs an update by running the MSI as LocalSystem. Windows Installer closes this
/// window to replace its files, and then tries to start it again through Restart Manager - which
/// fails, because the installer runs as SYSTEM and the window belonged to the signed-in user
/// ("Application SID does not match Conductor SID"). The update went in; the window just vanished and
/// stayed gone, which looks exactly like an update that did nothing.
/// </para>
/// <para>
/// So the window starts a small watcher, as the user, before asking for the install. It cannot be
/// SplitLane itself: anything running from the install directory holds files the installer must
/// replace, and would be closed along with the window. It is Windows PowerShell from System32, with
/// its working directory outside the install folder, and it:
/// </para>
/// <list type="number">
/// <item>waits for this window to close - up to ten minutes, then gives up, because the install
/// never happened;</item>
/// <item>waits until no Windows Installer transaction is in progress - the executable is not read
/// while one is, since that is when it is being replaced - and then until the installed executable's
/// version differs from the one that was running and the service is running again;</item>
/// <item>starts the new executable, as the user, and exits.</item>
/// </list>
/// <para>
/// If the version never changes - the install failed or was cancelled - nothing is reopened. A window
/// that reappeared after a failed update would suggest the opposite of what happened.
/// </para>
/// <para>
/// Nothing the engine says reaches the watcher. Its inputs are this process's id, path and version,
/// passed through its environment rather than spliced into the script, so no value has to survive
/// PowerShell quoting.
/// </para>
/// </remarks>
public static class UpdateRelauncher
{
    /// <summary>The engine's service name, which the MSI installs.</summary>
    public const string ServiceName = "SplitLane";

    /// <summary>
    /// The watcher. Kept as a script rather than built, so what it does can be read here in one
    /// piece.
    /// </summary>
    internal const string Script = """
        $ErrorActionPreference = 'SilentlyContinue'
        $appPid  = [int]$env:SPLITLANE_RELAUNCH_PID
        $app     = $env:SPLITLANE_RELAUNCH_APP
        $from    = $env:SPLITLANE_RELAUNCH_FROM
        $service = $env:SPLITLANE_RELAUNCH_SERVICE
        $closeWait = [int]$env:SPLITLANE_RELAUNCH_CLOSE_SECONDS
        $installWait = [int]$env:SPLITLANE_RELAUNCH_INSTALL_SECONDS

        $deadline = (Get-Date).AddSeconds($closeWait)
        while ((Get-Process -Id $appPid -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
        }
        if (Get-Process -Id $appPid -ErrorAction SilentlyContinue) { exit 2 }

        $deadline = (Get-Date).AddSeconds($installWait)
        $busySeconds = 0
        while ((Get-Date) -lt $deadline) {
            # Windows Installer holds this while a transaction runs. A user usually may not open it,
            # and being refused means it exists.
            $installing = $false
            try {
                $mutex = $null
                if ([System.Threading.Mutex]::TryOpenExisting('Global\_MSIExecute', [ref]$mutex)) {
                    $installing = $true
                    $mutex.Dispose()
                }
            }
            catch {
                $e = $_.Exception
                if ($e -is [System.UnauthorizedAccessException] -or $e.InnerException -is [System.UnauthorizedAccessException]) {
                    $installing = $true
                }
            }

            # The executable is not touched while the installer may be replacing it. The mutex is
            # trusted for two minutes at most, so a stale one cannot keep the window closed.
            if ($installing) { $busySeconds++ } else { $busySeconds = 0 }

            if (-not $installing -or $busySeconds -ge 120) {
                $version = (Get-Item -LiteralPath $app -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                $running = (-not $svc) -or ($svc.Status -eq 'Running')

                if ($version -and $version -ne $from -and $running) {
                    Start-Process -FilePath $app
                    exit 0
                }
            }

            Start-Sleep -Seconds 1
        }
        exit 3
        """;

    /// <summary>
    /// Starts the watcher for this process.
    /// </summary>
    /// <returns>The watcher, to be killed if the install is refused; null if it could not start.</returns>
    public static Process? StartForThisProcess()
    {
        var path = Environment.ProcessPath;
        if (path is null)
        {
            return null;
        }

        var version = FileVersionInfo.GetVersionInfo(path).ProductVersion ?? string.Empty;
        return Start(Environment.ProcessId, path, version, ServiceName, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(5));
    }

    /// <summary>Starts a watcher for any process. The parameters exist so it can be tested.</summary>
    /// <param name="applicationProcessId">The window that the installer will close.</param>
    /// <param name="applicationPath">The executable to start once it has been replaced.</param>
    /// <param name="currentVersion">Its product version now; any other means it was replaced.</param>
    /// <param name="serviceName">The service that must be running again first; absent means no wait.</param>
    /// <param name="closeWait">How long to wait for the window to close.</param>
    /// <param name="installWait">How long to wait for the new version once it has.</param>
    internal static Process? Start(
        int applicationProcessId,
        string applicationPath,
        string currentVersion,
        string serviceName,
        TimeSpan closeWait,
        TimeSpan installWait)
    {
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell))
        {
            return null;
        }

        var start = new ProcessStartInfo(powershell)
        {
            UseShellExecute = false,
            CreateNoWindow = true,

            // Not the install folder: a process whose current directory is inside it is one the
            // installer has to close.
            WorkingDirectory = Path.GetTempPath(),
        };

        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-WindowStyle");
        start.ArgumentList.Add("Hidden");
        start.ArgumentList.Add("-EncodedCommand");
        start.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(Script)));

        start.Environment["SPLITLANE_RELAUNCH_PID"] = applicationProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        start.Environment["SPLITLANE_RELAUNCH_APP"] = applicationPath;
        start.Environment["SPLITLANE_RELAUNCH_FROM"] = currentVersion;
        start.Environment["SPLITLANE_RELAUNCH_SERVICE"] = serviceName;
        start.Environment["SPLITLANE_RELAUNCH_CLOSE_SECONDS"] = ((int)closeWait.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
        start.Environment["SPLITLANE_RELAUNCH_INSTALL_SECONDS"] = ((int)installWait.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);

        try
        {
            return Process.Start(start);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // PowerShell blocked by policy, say. The update still works; the window will not come
            // back by itself, and the banner says so.
            return null;
        }
    }

    /// <summary>The version without its build metadata: <c>0.11.0</c> for <c>0.11.0+58dfa93...</c>.</summary>
    public static string DisplayVersion(string? version)
        => string.IsNullOrEmpty(version) ? "unknown" : version.Split('+')[0];
}
