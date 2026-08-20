using SplitLane.App.Infrastructure;
using SplitLane.Core.Ipc;
using SplitLane.Core.Models;
using SplitLane.App.Services;

namespace SplitLane.App.ViewModels;

/// <summary>The Overview page: what state is SplitLane in, and how much has it done.</summary>
public sealed class OverviewViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private bool _isRoutingEnabled;

    /// <summary>Builds the page.</summary>
    public OverviewViewModel(MainViewModel main)
    {
        _main = main ?? throw new ArgumentNullException(nameof(main));
        _isRoutingEnabled = main.Configuration.IsRoutingEnabled;

        StartCommand = new AsyncRelayCommand(
            async () =>
            {
                var reply = await _main.Engine.StartRoutingAsync().ConfigureAwait(true);
                _main.SetBanner(
                    reply.Succeeded ? "Routing started." : reply.Message ?? "Could not start routing.",
                    isError: !reply.Succeeded);
            },
            () => _main.EngineConnected);

        StopCommand = new AsyncRelayCommand(
            async () =>
            {
                var reply = await _main.Engine.StopRoutingAsync().ConfigureAwait(true);
                _main.SetBanner(
                    reply.Succeeded ? "Routing stopped." : reply.Message ?? "Could not stop routing.",
                    isError: !reply.Succeeded);
            },
            () => _main.EngineConnected);

        ResetCommand = new AsyncRelayCommand(
            async () =>
            {
                await _main.Engine.ResetStatisticsAsync().ConfigureAwait(true);
                _main.SetBanner("Counters reset.");
            },
            () => _main.EngineConnected);
    }

    /// <summary>Asks the engine to start diverting.</summary>
    public AsyncRelayCommand StartCommand { get; }

    /// <summary>Asks the engine to stop diverting.</summary>
    public AsyncRelayCommand StopCommand { get; }

    /// <summary>Zeroes the counters.</summary>
    public AsyncRelayCommand ResetCommand { get; }

    /// <summary>
    /// The master switch.
    /// </summary>
    /// <remarks>
    /// Turning it off routes everything DIRECT while leaving the engine installed and running. That
    /// is a different state from stopping the engine, and the UI says so, because "paused" and "not
    /// installed" look identical from the outside and are not the same promise.
    /// </remarks>
    public bool IsRoutingEnabled
    {
        get => _isRoutingEnabled;
        set
        {
            if (Set(ref _isRoutingEnabled, value))
            {
                _main.MarkDirty();
                Raise(nameof(RoutingStateLabel));
            }
        }
    }

    /// <summary>Reloads from a configuration.</summary>
    public void LoadFrom(RuntimeConfiguration configuration) =>
        IsRoutingEnabled = configuration.IsRoutingEnabled;

    /// <summary>Called when the engine status changed.</summary>
    public void OnStatusChanged()
    {
        Raise(nameof(StateLabel));
        Raise(nameof(StateDetail));
        Raise(nameof(IsHealthy));
        Raise(nameof(HasStatus));
        Raise(nameof(IsFaulted));
        Raise(nameof(ProxiedCount));
        Raise(nameof(DirectCount));
        Raise(nameof(BlockedCount));
        Raise(nameof(ActiveCount));
        Raise(nameof(TransferredLabel));
        Raise(nameof(UptimeLabel));
        Raise(nameof(RedirectPortLabel));
        Raise(nameof(DriverLabel));
        Raise(nameof(LastError));
        Raise(nameof(HasLastError));
    }

    private EngineStatus? Status => _main.Status;

    /// <summary>One word for the big state pill.</summary>
    public string StateLabel
    {
        get
        {
            if (!_main.EngineConnected)
            {
                return "Engine not running";
            }

            return Status?.State switch
            {
                DivertState.Running => "Routing",
                DivertState.Paused => "Paused",
                DivertState.Starting => "Starting",
                DivertState.Faulted => "Faulted",
                _ => "Stopped",
            };
        }
    }

    /// <summary>A sentence explaining the state, and what to do about it.</summary>
    public string StateDetail
    {
        get
        {
            if (!_main.EngineConnected)
            {
                // Always end on the step the user can take. Echoing only the transport error tells
                // them what failed and not what to do about it - and the step differs by machine,
                // so it is read from how the engine is actually installed rather than assumed.
                var remedy = EngineServicePresence.Remedy(EngineServicePresence.Read());

                return _main.EngineMessage is { } message &&
                       !message.StartsWith("The SplitLane engine is not running", StringComparison.Ordinal)
                    ? $"{message} {remedy}"
                    : remedy;
            }

            return Status?.State switch
            {
                DivertState.Running =>
                    $"{Status.ActiveRuleCount} rule{(Status.ActiveRuleCount == 1 ? "" : "s")} active. " +
                    "Applications you have not selected are untouched.",
                DivertState.Paused =>
                    "The engine is running but routing is switched off, so every application is DIRECT.",
                DivertState.Starting => "Opening the divert handles.",
                DivertState.Faulted => Status.LastError ?? "The divert layer stopped with an error.",
                _ => "The engine is running but is not diverting. Press Start routing.",
            };
        }
    }

    /// <summary>Whether the engine reported anything at all, so placeholders can be hidden.</summary>
    public bool HasStatus => _main.EngineConnected && Status is not null;

    /// <summary>True when everything is as it should be.</summary>
    public bool IsHealthy => _main.EngineConnected && Status?.State == DivertState.Running;

    /// <summary>True when something needs attention.</summary>
    public bool IsFaulted => _main.EngineConnected && Status?.State == DivertState.Faulted;

    /// <summary>Connections relayed since start.</summary>
    public string ProxiedCount => Format(Status?.ProxiedFlowCount);

    /// <summary>Connections left alone since start.</summary>
    public string DirectCount => Format(Status?.DirectFlowCount);

    /// <summary>Datagrams and connections refused.</summary>
    public string BlockedCount => Format(Status?.BlockedFlowCount);

    /// <summary>Connections being relayed right now.</summary>
    public string ActiveCount => Status is null ? "—" : Status.ActiveProxiedFlows.ToString("N0");

    /// <summary>Bytes moved, both directions.</summary>
    public string TransferredLabel => Status is null
        ? "—"
        : $"{Bytes(Status.BytesSent)} up · {Bytes(Status.BytesReceived)} down";

    /// <summary>How long the engine has been diverting.</summary>
    public string UptimeLabel
    {
        get
        {
            if (Status?.Uptime is not { } uptime)
            {
                return "—";
            }

            return uptime.TotalHours >= 1
                ? $"{(int)uptime.TotalHours}h {uptime.Minutes}m"
                : uptime.TotalMinutes >= 1
                    ? $"{uptime.Minutes}m {uptime.Seconds}s"
                    : $"{uptime.Seconds}s";
        }
    }

    /// <summary>Where the redirect listener is bound.</summary>
    public string RedirectPortLabel =>
        Status is null || Status.RedirectPort == 0 ? "—" : $"127.0.0.1:{Status.RedirectPort}";

    /// <summary>Which driver the engine is bound to.</summary>
    /// <remarks>
    /// "Divert layer off" rather than "not loaded": a running engine with no driver is a deliberate
    /// mode, not a half-failure, and the sidebar should not imply something went wrong.
    /// </remarks>
    public string DriverLabel => Status?.DriverVersion is { } version
        ? $"WinDivert {version}"
        : _main.EngineConnected ? "Divert layer off" : "—";

    /// <summary>The engine's most recent failure.</summary>
    public string? LastError => Status?.LastError;

    /// <summary>Whether there is a failure worth showing.</summary>
    public bool HasLastError => !string.IsNullOrEmpty(LastError);

    /// <summary>Word form of the master switch, so colour is never the only signal.</summary>
    public string RoutingStateLabel => IsRoutingEnabled ? "On" : "Off";

    private static string Format(ulong? value) => value is null ? "—" : value.Value.ToString("N0");

    /// <summary>Renders a byte count at a sensible scale.</summary>
    internal static string Bytes(ulong value)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double scaled = value;
        var unit = 0;

        while (scaled >= 1024 && unit < units.Length - 1)
        {
            scaled /= 1024;
            unit++;
        }

        return unit == 0 ? $"{value} B" : $"{scaled:0.#} {units[unit]}";
    }
}
