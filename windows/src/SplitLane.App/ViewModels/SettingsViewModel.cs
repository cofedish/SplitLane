using System.Diagnostics;
using System.IO;
using SplitLane.App.Infrastructure;
using SplitLane.Core.Ipc;
using SplitLane.Core.Models;

namespace SplitLane.App.ViewModels;

/// <summary>The Settings page: diagnostics, storage, and honest statements about limits.</summary>
public sealed class SettingsViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private bool _logsDirectFlows;
    private string _redirectPort = "0";

    /// <summary>Builds the page.</summary>
    public SettingsViewModel(MainViewModel main)
    {
        _main = main ?? throw new ArgumentNullException(nameof(main));

        OpenConfigurationFolderCommand = new RelayCommand(() => Reveal(_main.Store.ConfigurationPath));
        OpenLogCommand = new RelayCommand(
            () => Reveal(_main.Store.EngineLogPath),
            () => File.Exists(_main.Store.EngineLogPath));
    }

    /// <summary>Shows the configuration file in Explorer.</summary>
    public RelayCommand OpenConfigurationFolderCommand { get; }

    /// <summary>Shows the engine log in Explorer.</summary>
    public RelayCommand OpenLogCommand { get; }

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
