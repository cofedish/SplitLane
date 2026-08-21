using System.Diagnostics;
using System.IO;
using SplitLane.App.Infrastructure;
using SplitLane.App.Services;
using SplitLane.App.Theme;
using SplitLane.Core.Ipc;
using SplitLane.Core.Models;

namespace SplitLane.App.ViewModels;

/// <summary>The Settings page: diagnostics, storage, and honest statements about limits.</summary>
public sealed class SettingsViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private AppTheme _theme = UiSettings.Load().Theme;
    private bool _logsDirectFlows;
    private string _redirectPort = "0";

    /// <summary>Builds the page.</summary>
    public SettingsViewModel(MainViewModel main)
    {
        _main = main ?? throw new ArgumentNullException(nameof(main));

        CheckForUpdateCommand = new AsyncRelayCommand(CheckForUpdateAsync);
        InstallUpdateCommand = new AsyncRelayCommand(InstallUpdateAsync);

        OpenConfigurationFolderCommand = new RelayCommand(() => Reveal(_main.Store.ConfigurationPath));
        OpenLogCommand = new RelayCommand(
            () => Reveal(_main.Store.EngineLogPath),
            () => File.Exists(_main.Store.EngineLogPath));
    }

    /// <summary>Shows the configuration file in Explorer.</summary>
    public RelayCommand OpenConfigurationFolderCommand { get; }

    /// <summary>Shows the engine log in Explorer.</summary>
    public RelayCommand OpenLogCommand { get; }

    /// <summary>Asks the engine to look for a newer release.</summary>
    public AsyncRelayCommand CheckForUpdateCommand { get; }

    /// <summary>Asks the engine to install the release it found.</summary>
    public AsyncRelayCommand InstallUpdateCommand { get; }

    /// <summary>What this installation is.</summary>
    /// <remarks>
    /// Read from the engine rather than from this assembly. The two are installed together and are
    /// therefore the same version - but if they ever were not, the number that matters is the one
    /// belonging to the half that routes traffic.
    /// </remarks>
    public string InstalledVersion => _main.Status?.EngineVersion is { Length: > 0 } version
        ? version
        : "unknown while the engine is not running";

    /// <summary>Whether a verified release is waiting to be installed.</summary>
    public bool UpdateAvailable =>
        string.Equals(_main.Status?.UpdateState, "Available", StringComparison.Ordinal);

    /// <summary>Whether the engine is in the middle of fetching or applying one.</summary>
    public bool UpdateInProgress =>
        _main.Status?.UpdateState is "Downloading" or "Installing";

    /// <summary>One line about where updates stand.</summary>
    public string UpdateSummary => _main.Status?.UpdateState switch
    {
        "Available" => $"Version {_main.Status?.UpdateVersion} is available. " +
                       (_main.Status?.UpdateNotes ?? string.Empty),
        "Downloading" => "Downloading the installer…",
        "Installing" => "Installing. The engine restarts, so routing pauses for a few seconds.",
        "UpToDate" => "This is the newest release.",
        "Failed" => $"The last check did not finish: {_main.Status?.UpdateError}",
        _ => "SplitLane checks once a day, and installs nothing without being asked.",
    };

    /// <summary>
    /// Which look the application wears.
    /// </summary>
    /// <remarks>
    /// Applied the moment it changes and saved at the same time. A theme that needed a restart, or a
    /// Save button, would be a setting about the thing you are looking at that does not change the
    /// thing you are looking at.
    /// </remarks>
    public AppTheme Theme
    {
        get => _theme;
        set
        {
            if (Set(ref _theme, value))
            {
                ThemeService.Apply(value);
                UiSettings.Save(new UiPreferences(value));
                Raise(nameof(IsSystemTheme));
                Raise(nameof(IsLightTheme));
                Raise(nameof(IsDarkTheme));
                Raise(nameof(ThemeSummary));
            }
        }
    }

    /// <summary>True when the theme follows Windows.</summary>
    public bool IsSystemTheme
    {
        get => Theme == AppTheme.System;
        set { if (value) { Theme = AppTheme.System; } }
    }

    /// <summary>True when the theme is pinned to light.</summary>
    public bool IsLightTheme
    {
        get => Theme == AppTheme.Light;
        set { if (value) { Theme = AppTheme.Light; } }
    }

    /// <summary>True when the theme is pinned to dark.</summary>
    public bool IsDarkTheme
    {
        get => Theme == AppTheme.Dark;
        set { if (value) { Theme = AppTheme.Dark; } }
    }

    /// <summary>What the current choice means in practice.</summary>
    public string ThemeSummary => Theme == AppTheme.System
        ? $"Following Windows, which is currently {(ThemeService.Resolved == AppTheme.Light ? "light" : "dark")}."
        : "Fixed, whatever Windows is set to.";

    /// <summary>
    /// Whether the engine should log every DIRECT decision.
    /// </summary>
    /// <remarks>
    /// Off by default and worth keeping that way: the engine sees every outbound connection on the
    /// machine, so this turns the log into a record of everything the user does, and a large one.
    /// </remarks>
    public bool LogsDirectFlows
    {
        get => _logsDirectFlows;
        set
        {
            if (Set(ref _logsDirectFlows, value))
            {
                _main.MarkDirty();
            }
        }
    }

    /// <summary>Redirect listener port, as typed. Zero means "pick one".</summary>
    public string RedirectPort
    {
        get => _redirectPort;
        set
        {
            if (Set(ref _redirectPort, value))
            {
                _main.MarkDirty();
                Raise(nameof(RedirectPortHint));
            }
        }
    }

    /// <summary>The parsed redirect port, or zero when the box does not hold a number.</summary>
    public ushort RedirectPortValue =>
        ushort.TryParse(RedirectPort.Trim(), out var port) ? port : (ushort)0;

    /// <summary>Explains what the redirect port box does.</summary>
    public string RedirectPortHint => RedirectPortValue == 0
        ? "An unused port is chosen at start. This is the better choice unless a firewall rule needs a fixed number."
        : $"The redirect listener will bind 127.0.0.1:{RedirectPortValue}.";

    /// <summary>Where the configuration lives.</summary>
    public string ConfigurationPath => _main.Store.ConfigurationPath;

    /// <summary>Where the engine log lives.</summary>
    public string LogPath => _main.Store.EngineLogPath;

    /// <summary>The pipe the app talks to the engine over.</summary>
    public string ControlChannel => $@"\\.\pipe\{EngineChannel.PipeName}";

    /// <summary>Which driver the engine has open, when it has one.</summary>
    public string DriverStatus
    {
        get
        {
            if (!_main.EngineConnected)
            {
                return "Engine not running";
            }

            return _main.Status?.DriverVersion is { } version
                ? $"WinDivert {version} loaded"
                : "WinDivert not loaded — the engine is running without the divert layer";
        }
    }

    /// <summary>Whether the driver line should read as a problem.</summary>
    public bool DriverIsMissing => _main.EngineConnected && _main.Status?.DriverVersion is null;

    /// <summary>
    /// Whether the divert layer is actually up.
    /// </summary>
    /// <remarks>
    /// Distinct from "not a problem". With no engine running there is nothing to be healthy or
    /// broken, and an indicator that shows green next to the words "Engine not running" is worse
    /// than no indicator at all.
    /// </remarks>
    public bool DriverIsHealthy => _main.EngineConnected && _main.Status?.DriverVersion is not null;

    /// <summary>Build identity, so a bug report can name it.</summary>
    public string Version =>
        typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3) ?? "0.1.0";

    /// <summary>Reloads from a configuration.</summary>
    public void LoadFrom(RuntimeConfiguration configuration)
    {
        _logsDirectFlows = configuration.LogsDirectFlows;
        _redirectPort = configuration.RedirectPort.ToString();

        Raise(nameof(LogsDirectFlows));
        Raise(nameof(RedirectPort));
        Raise(nameof(RedirectPortHint));
    }

    /// <summary>Called when the engine status changed.</summary>
    public void OnStatusChanged()
    {
        Raise(nameof(DriverStatus));
        Raise(nameof(DriverIsMissing));
        Raise(nameof(DriverIsHealthy));

        // The daily check happens without anybody pressing anything, so the page has to hear about
        // its result the same way it hears about everything else the engine reports.
        RaiseUpdate();
    }

    private async Task CheckForUpdateAsync()
    {
        var reply = await _main.Engine.CheckForUpdateAsync().ConfigureAwait(true);

        _main.SetBanner(reply.Succeeded
            ? "Checked for updates."
            : $"Could not check for updates: {reply.Message}");

        // The result arrives with the next status poll, a second away, and every page already
        // refreshes from that. Reaching for a private refresh here would be a second path to the
        // same place.
        RaiseUpdate();
    }

    private async Task InstallUpdateAsync()
    {
        // The engine restarts itself as part of this, so the reply is an acknowledgement that the
        // installer started rather than that it finished. Saying otherwise would be a promise this
        // side of the pipe cannot keep.
        var reply = await _main.Engine.ApplyUpdateAsync().ConfigureAwait(true);

        _main.SetBanner(reply.Succeeded
            ? "Installing. SplitLane will reconnect to the engine when it comes back."
            : $"The update could not be installed: {reply.Message}");

        RaiseUpdate();
    }

    private void RaiseUpdate()
    {
        Raise(nameof(InstalledVersion));
        Raise(nameof(UpdateAvailable));
        Raise(nameof(UpdateInProgress));
        Raise(nameof(UpdateSummary));
    }

    private static void Reveal(string path)
    {
        try
        {
            var target = File.Exists(path) ? $"/select,\"{path}\"" : $"\"{Path.GetDirectoryName(path)}\"";
            Process.Start(new ProcessStartInfo("explorer.exe", target) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // Explorer being unavailable is not worth an error dialog; the path is on screen anyway.
        }
    }
}
