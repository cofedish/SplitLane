using System.Collections.ObjectModel;
using SplitLane.App.Infrastructure;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.App.ViewModels;

/// <summary>One connection in the Activity list.</summary>
public sealed class ConnectionRowViewModel(ConnectionEvent connection)
{
    /// <summary>The underlying record.</summary>
    public ConnectionEvent Connection { get; } = connection;

    /// <summary>Application name, or the executable's file name when no rule named it.</summary>
    public string ApplicationName =>
        Connection.ApplicationName ?? ExecutablePath.FileName(Connection.ExecutablePath);

    /// <summary>Where it was going.</summary>
    public string Destination => Connection.DestinationDisplay;

    /// <summary>Local time of the decision.</summary>
    public string Time => Connection.Timestamp.ToLocalTime().ToString("HH:mm:ss");

    /// <summary>The lane, as a word.</summary>
    public string LaneLabel => Connection.Route switch
    {
        RouteAction.Proxy => "PROXY",
        RouteAction.Block => "BLOCKED",
        _ => "DIRECT",
    };

    /// <summary>Lifecycle state, or the error when it failed.</summary>
    public string StateLabel => Connection.State switch
    {
        ConnectionState.Failed => Connection.Error?.Describe() ?? "Failed",
        ConnectionState.Connecting => "Connecting",
        ConnectionState.Active => "Active",
        ConnectionState.Blocked => "Refused",
        _ => "Closed",
    };

    /// <summary>Volume moved, or a dash while nothing has.</summary>
    public string TransferLabel => Connection.BytesSent == 0 && Connection.BytesReceived == 0
        ? "—"
        : $"{OverviewViewModel.Bytes(Connection.BytesSent)} ↑ {OverviewViewModel.Bytes(Connection.BytesReceived)} ↓";

    /// <summary>How long it lasted.</summary>
    public string DurationLabel => Connection.Duration is { } duration
        ? duration.TotalSeconds >= 1 ? $"{duration.TotalSeconds:0.0}s" : $"{duration.TotalMilliseconds:0}ms"
        : "—";

    /// <summary>Whether this row failed, so it can be tinted.</summary>
    public bool IsFailure => Connection.State is ConnectionState.Failed or ConnectionState.Blocked;

    /// <summary>Whether this row is in the proxy lane.</summary>
    public bool IsProxied => Connection.Route == RouteAction.Proxy;

    /// <summary>Full detail for the tooltip.</summary>
    public string Tooltip =>
        $"{Connection.ExecutablePath}\nPID {Connection.ProcessId}\n{Connection.Protocol.ToString().ToUpperInvariant()} to " +
        $"{Connection.DestinationDisplay}\n{Connection.Reason ?? StateLabel}";
}

/// <summary>The Activity page: what the engine actually did.</summary>
public sealed class ActivityViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private bool _showFailuresOnly;

    /// <summary>Builds the page.</summary>
    public ActivityViewModel(MainViewModel main)
    {
        _main = main ?? throw new ArgumentNullException(nameof(main));
        RefreshCommand = new AsyncRelayCommand(RefreshAsync);
    }

    /// <summary>Recent connections, newest first.</summary>
    public ObservableCollection<ConnectionRowViewModel> Connections { get; } = [];

    /// <summary>Rows after the failure filter.</summary>
    public IEnumerable<ConnectionRowViewModel> VisibleConnections =>
        ShowFailuresOnly ? Connections.Where(row => row.IsFailure) : Connections;

    /// <summary>Re-reads the list from the engine.</summary>
    public AsyncRelayCommand RefreshCommand { get; }

    /// <summary>Whether to hide everything that worked.</summary>
    public bool ShowFailuresOnly
    {
        get => _showFailuresOnly;
        set
        {
            if (Set(ref _showFailuresOnly, value))
            {
                Raise(nameof(VisibleConnections));
                Raise(nameof(IsEmpty));
                Raise(nameof(EmptyMessage));
            }
        }
    }

    /// <summary>Whether there is nothing to show.</summary>
    public bool IsEmpty => !VisibleConnections.Any();

    /// <summary>
    /// What to say when the list is empty, which depends on why it is empty.
    /// </summary>
    /// <remarks>
    /// "No activity" is unhelpful when the real answer is "the engine is not running" or "you have
    /// not selected any applications yet". Each of those needs a different next step.
    /// </remarks>
    public string EmptyMessage
    {
        get
        {
            if (!_main.EngineConnected)
            {
                return "The engine is not running, so there is nothing to report yet.";
            }

            if (ShowFailuresOnly)
            {
                return "No failed connections. That is the good outcome.";
            }

            return _main.Applications.ProxiedCount == 0
                ? "No applications are in the proxy lane, so there is nothing to relay."
                : "No connections yet. Activity appears here as selected applications reach the network.";
        }
    }

    /// <summary>A reminder of what this list deliberately omits.</summary>
    public string FooterNote =>
        "DIRECT connections are counted on the Overview page but not listed here. The engine sees " +
        "every connection on the machine, and recording each one would make SplitLane a log of " +
        "everything you do.";

    /// <summary>Pulls the latest rows from the engine.</summary>
    public async Task RefreshAsync()
    {
        var reply = await _main.Engine.ActivityAsync(200).ConfigureAwait(true);

        if (reply.Response?.Activity is not { } activity)
        {
            if (Connections.Count > 0 && !reply.Connected)
            {
                Connections.Clear();
                RaiseAll();
            }

            return;
        }

        // Rebuilt wholesale rather than diffed. Two hundred rows is nothing to rebuild, and a diff
        // would need a stable sort key that survives a row moving from Connecting to Closed.
        Connections.Clear();
        foreach (var connection in activity)
        {
            Connections.Add(new ConnectionRowViewModel(connection));
        }

        RaiseAll();
    }

    private void RaiseAll()
    {
        Raise(nameof(VisibleConnections));
        Raise(nameof(IsEmpty));
        Raise(nameof(EmptyMessage));
    }
}
