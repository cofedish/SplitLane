using System.Diagnostics;
using SplitLane.App.Services;

namespace SplitLane.Engine.Tests;

/// <summary>
/// The watcher that reopens the window after an update, run for real in Windows PowerShell.
/// </summary>
/// <remarks>
/// <para>
/// Why it exists: the MSI runs as SYSTEM, closes the window to replace its files, and cannot start it
/// again in the user's session - so after the first live self-update (0.9.1 to 0.11.0) the install
/// had worked and the window had simply gone.
/// </para>
/// <para>
/// The window is played by a sleeping process that the test kills, the way the installer closes the
/// real one. The executable to reopen is the SOCKS5 testbed, copied to a folder of its own. Its
/// version is "the new one" whenever the test says the running version was something else. The
/// service name is one that does not exist, which the watcher treats as nothing to wait for.
/// </para>
/// </remarks>
public sealed class UpdateRelauncherTests : IDisposable
{
    private const string NoSuchService = "SplitLane-Test-NoSuchService";

    private readonly string _folder = Path.Combine(Path.GetTempPath(), "splitlane-relaunch-" + Guid.NewGuid().ToString("N"));
    private readonly List<Process> _started = [];

    public UpdateRelauncherTests()
    {
        Directory.CreateDirectory(_folder);
        foreach (var file in Directory.EnumerateFiles(AppContext.BaseDirectory, "SplitLane.Testbed.Socks5.*"))
        {
            File.Copy(file, Path.Combine(_folder, Path.GetFileName(file)));
        }
    }

    private string Application => Path.Combine(_folder, "SplitLane.Testbed.Socks5.exe");

    private string InstalledVersion => FileVersionInfo.GetVersionInfo(Application).ProductVersion!;

    /// <summary>Something to stand in for the window: alive until the test closes it.</summary>
    private Process Window()
    {
        var window = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "ping.exe"), "-n 120 127.0.0.1")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
        })!;
        _started.Add(window);
        return window;
    }

    private Process Watch(Process window, string runningVersion, int closeSeconds = 30, int installSeconds = 30)
    {
        var watcher = UpdateRelauncher.Start(
            window.Id,
            Application,
            runningVersion,
            NoSuchService,
            TimeSpan.FromSeconds(closeSeconds),
            TimeSpan.FromSeconds(installSeconds));

        Assert.NotNull(watcher);
        _started.Add(watcher);
        return watcher;
    }

    private Process[] Reopened() => Process.GetProcessesByName("SplitLane.Testbed.Socks5")
        .Where(p =>
        {
            try
            {
                return string.Equals(p.MainModule?.FileName, Application, StringComparison.OrdinalIgnoreCase);
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return false;
            }
        })
        .ToArray();

    [Fact]
    public async Task TheNewVersionIsOpenedOnceTheInstallerHasClosedTheWindow()
    {
        var window = Window();
        var watcher = Watch(window, runningVersion: "0.0.1+old");

        await Task.Delay(1500);
        Assert.Empty(Reopened());

        // The installer closes the window to replace its files.
        window.Kill();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await watcher.WaitForExitAsync(timeout.Token);

        Assert.Equal(0, watcher.ExitCode);
        var reopened = Assert.Single(Reopened());
        _started.Add(reopened);
    }

    [Fact]
    public async Task NothingIsOpenedWhenTheVersionDidNotChange()
    {
        // The install failed or was cancelled after the window closed. Reopening it would read as a
        // successful update.
        var window = Window();
        var watcher = Watch(window, runningVersion: InstalledVersion, installSeconds: 3);

        window.Kill();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await watcher.WaitForExitAsync(timeout.Token);

        Assert.Equal(3, watcher.ExitCode);
        Assert.Empty(Reopened());
    }

    [Fact]
    public async Task TheWatcherGivesUpWhenTheWindowIsNeverClosed()
    {
        var window = Window();
        var watcher = Watch(window, runningVersion: "0.0.1+old", closeSeconds: 2);

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await watcher.WaitForExitAsync(timeout.Token);

        Assert.Equal(2, watcher.ExitCode);
        Assert.Empty(Reopened());
    }

    [Theory]
    [InlineData("0.11.0+58dfa93cf584b4b6079e7f3075497634c93b0312", "0.11.0")]
    [InlineData("0.9.1", "0.9.1")]
    [InlineData(null, "unknown")]
    public void DisplayVersionDropsBuildMetadata(string? version, string expected)
        => Assert.Equal(expected, UpdateRelauncher.DisplayVersion(version));

    public void Dispose()
    {
        foreach (var process in _started)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(5000);
                }
            }
            catch (InvalidOperationException)
            {
            }

            process.Dispose();
        }

        try
        {
            Directory.Delete(_folder, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
