using System.Collections.Concurrent;
using SplitLane.Core.Ipc;
using SplitLane.Core.Models;

namespace SplitLane.Engine.Runtime;

/// <summary>
/// Counters and the recent-connection ring.
/// </summary>
/// <remarks>
/// <para>
/// DIRECT decisions are counted, not enumerated. The engine is consulted for every outbound
/// connection on the machine, so keeping a record of each one would turn a routing component into a
/// surveillance log of everything the user does — and would be the single largest thing in memory.
/// Proxied and blocked connections are enumerated, because there are few of them and because they
/// are the ones a user needs to see to trust the product.
/// </para>
/// <para>
/// All counters are <see cref="Interlocked"/>-updated rather than locked. They are written from the
/// divert threads and the relay tasks and read from the IPC thread; a lock on the divert path would
/// be a lock held once per packet.
/// </para>
/// </remarks>
public sealed class EngineStatistics
{
    private readonly ConcurrentQueue<ConnectionEvent> _activity = new();
    private readonly ConcurrentDictionary<Guid, byte> _live = new();

    private long _directFlows;
    private long _proxiedFlows;
    private long _blockedFlows;
    private long _bytesSent;
    private long _bytesReceived;

    /// <summary>How many recent connections are retained.</summary>
    public int ActivityCapacity { get; init; } = 500;

    /// <summary>Connections left alone.</summary>
    public ulong DirectFlowCount => (ulong)Interlocked.Read(ref _directFlows);

    /// <summary>Connections relayed.</summary>
    public ulong ProxiedFlowCount => (ulong)Interlocked.Read(ref _proxiedFlows);

    /// <summary>Datagrams and connections refused.</summary>
    public ulong BlockedFlowCount => (ulong)Interlocked.Read(ref _blockedFlows);

    /// <summary>Bytes relayed application-to-upstream.</summary>
    public ulong BytesSent => (ulong)Interlocked.Read(ref _bytesSent);

    /// <summary>Bytes relayed upstream-to-application.</summary>
    public ulong BytesReceived => (ulong)Interlocked.Read(ref _bytesReceived);

    /// <summary>Connections currently being relayed.</summary>
    public int ActiveProxiedFlows => _live.Count;

    /// <summary>Records a DIRECT decision.</summary>
    public void CountDirect() => Interlocked.Increment(ref _directFlows);

    /// <summary>Records a PROXY decision.</summary>
    public void CountProxied() => Interlocked.Increment(ref _proxiedFlows);

    /// <summary>Records a BLOCK decision.</summary>
    public void CountBlocked() => Interlocked.Increment(ref _blockedFlows);

    /// <summary>Records relayed volume.</summary>
    public void AddTransferred(ulong sent, ulong received)
    {
        Interlocked.Add(ref _bytesSent, (long)sent);
        Interlocked.Add(ref _bytesReceived, (long)received);
    }

    /// <summary>Adds a connection to the Activity ring, trimming the oldest.</summary>
    public void Record(ConnectionEvent connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        _activity.Enqueue(connection);

        while (_activity.Count > ActivityCapacity && _activity.TryDequeue(out _))
        {
        }
    }

    /// <summary>Replaces an existing Activity row, normally to move it to a terminal state.</summary>
    public void Update(ConnectionEvent connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var items = _activity.ToArray();
        while (_activity.TryDequeue(out _))
        {
        }

        var replaced = false;
        foreach (var item in items)
        {
            if (item.Id == connection.Id)
            {
                _activity.Enqueue(connection);
                replaced = true;
            }
            else
            {
                _activity.Enqueue(item);
            }
        }

        if (!replaced)
        {
            Record(connection);
        }
    }

    /// <summary>Marks a connection as being relayed right now.</summary>
    public void MarkLive(Guid id) => _live[id] = 0;

    /// <summary>Marks a connection as finished.</summary>
    public void MarkFinished(Guid id) => _live.TryRemove(id, out _);

    /// <summary>Most recent connections, newest first.</summary>
    public IReadOnlyList<ConnectionEvent> RecentActivity(int limit)
    {
        var snapshot = _activity.ToArray();
        Array.Reverse(snapshot);
        return limit <= 0 || limit >= snapshot.Length ? snapshot : snapshot[..limit];
    }

    /// <summary>Zeroes the counters and empties the ring.</summary>
    public void Reset()
    {
        Interlocked.Exchange(ref _directFlows, 0);
        Interlocked.Exchange(ref _proxiedFlows, 0);
        Interlocked.Exchange(ref _blockedFlows, 0);
        Interlocked.Exchange(ref _bytesSent, 0);
        Interlocked.Exchange(ref _bytesReceived, 0);

        while (_activity.TryDequeue(out _))
        {
        }
    }

    /// <summary>Builds the IPC status payload.</summary>
    public EngineStatus ToStatus(
        DivertState state,
        ulong generation,
        bool routingEnabled,
        int activeRuleCount,
        ushort redirectPort,
        string? lastError,
        DateTimeOffset? startedAt,
        string? driverVersion)
        => new()
        {
            State = state,
            ConfigurationGeneration = generation,
            IsRoutingEnabled = routingEnabled,
            ActiveRuleCount = activeRuleCount,
            ActiveProxiedFlows = ActiveProxiedFlows,
            DirectFlowCount = DirectFlowCount,
            ProxiedFlowCount = ProxiedFlowCount,
            BlockedFlowCount = BlockedFlowCount,
            BytesSent = BytesSent,
            BytesReceived = BytesReceived,
            RedirectPort = redirectPort,
            LastError = lastError,
            StartedAt = startedAt,
            DriverVersion = driverVersion,
        };
}
