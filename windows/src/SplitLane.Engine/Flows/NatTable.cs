using System.Collections.Concurrent;
using System.Net;
using SplitLane.Core.Models;

namespace SplitLane.Engine.Flows;

/// <summary>
/// Everything the engine needs to un-rewrite a redirected connection and to relay it.
/// </summary>
/// <param name="OriginalSource">The address the application actually bound.</param>
/// <param name="OriginalDestination">Where the application believes it is connected.</param>
/// <param name="OriginalDestinationPort">The port it believes it is connected to.</param>
/// <param name="ProcessId">Owning process at connect time. Diagnostic.</param>
/// <param name="ExecutablePath">Routing key of the owning process.</param>
/// <param name="ApplicationName">Display name from the matched rule.</param>
/// <param name="Hostname">Name the destination was resolved from, when the DNS observer saw it.</param>
/// <param name="CreatedAt">When the entry was made.</param>
public sealed record NatEntry(
    IPAddress OriginalSource,
    IPAddress OriginalDestination,
    ushort OriginalDestinationPort,
    uint ProcessId,
    string ExecutablePath,
    string? ApplicationName,
    string? Hostname,
    DateTimeOffset CreatedAt)
{
    /// <summary>
    /// Whether this connection's opening SYN was redirected.
    /// </summary>
    /// <remarks>
    /// The socket-layer event and the packet loop run on different threads, so it is possible for a
    /// SYN to be sent before the routing decision has been recorded. When that happens the
    /// connection establishes with its real destination, and diverting its <i>later</i> packets is
    /// strictly worse than leaving it alone: it takes a working connection and points it at a port
    /// with no matching endpoint, which the stack answers with a reset.
    ///
    /// <para>
    /// Observed in a packet capture before it was understood: the SYN left un-redirected, and the
    /// ACK and the HTTP request that followed were rewritten and dropped with "transport endpoint
    /// was not found".
    /// </para>
    /// </remarks>
    public bool SynRedirected { get; set; }

    private long _lastSeenTicks = CreatedAt.UtcTicks;
    private int _closing;

    /// <summary>
    /// When a packet of this connection last passed, in either direction. Expiry is measured from here,
    /// not from <see cref="CreatedAt"/> (SL-SEC-004): a connection that is in use is never forgotten.
    /// </summary>
    public DateTimeOffset LastSeen => new(Interlocked.Read(ref _lastSeenTicks), TimeSpan.Zero);

    /// <summary>Whether a FIN or RST has been seen, after which a shorter idle limit applies.</summary>
    public bool IsClosing => Volatile.Read(ref _closing) != 0;

    /// <summary>Records that a packet of this connection passed.</summary>
    internal void Touch(DateTimeOffset now) => Interlocked.Exchange(ref _lastSeenTicks, now.UtcTicks);

    /// <summary>Records that the connection is being torn down.</summary>
    internal void MarkClosing() => Volatile.Write(ref _closing, 1);

    /// <summary>The policy action captured for this connection.</summary>
    public RouteAction Action { get; init; } = RouteAction.Proxy;

    /// <summary>Matched application or destination rule, for diagnostics.</summary>
    public string? RuleKey { get; init; }

    /// <summary>
    /// The WinDivert endpoint id of the socket that made the connection, or 0 when unknown. Only a
    /// CLOSE from that socket removes the entry (SL-SEC-005).
    /// </summary>
    public ulong EndpointId { get; init; }
}

/// <summary>What was decided about a connection that is not redirected.</summary>
public enum NatVerdict
{
    /// <summary>Leave it alone: its packets are reinjected unchanged.</summary>
    Direct = 0,

    /// <summary>
    /// Refuse it: its packets are dropped. A lane the user chose, or a selected application's
    /// connection that cannot be carried safely.
    /// </summary>
    Block = 1,

    /// <summary>
    /// Hold it: its packets are dropped until the process's identity is verified, then the connection
    /// is decided again. TCP retransmits the SYN, so the connection proceeds once the answer is in.
    /// </summary>
    Pending = 2,
}

/// <summary>
/// Maps a redirected connection back to where it was actually going.
/// </summary>
/// <remarks>
/// <para>
/// Rows are keyed on the connection's local end - family, local address and local port
/// (<see cref="FlowKey"/>) - which is what both the socket layer and an outbound packet carry. The key
/// used to be the port alone, and a port is not unique across families or local addresses: any
/// process could open a socket on the same number elsewhere and its CONNECT or CLOSE overwrote or
/// erased a selected application's decision (SL-SEC-005, formerly accepted as W-6).
/// </para>
/// <para>
/// A redirected connection is also indexed by <see cref="PortSlot"/> - family and port - because that
/// is all that survives the rewrite: the redirect listener and the reply path see the application at
/// a loopback address. A slot holds at most one redirected connection; a second one that would share
/// it is refused rather than allowed to answer for the first.
/// </para>
/// <para>
/// Every row remembers the WinDivert endpoint id of the socket that produced it, and a socket CLOSE
/// removes only rows that socket owns.
/// </para>
/// <para>
/// Redirected entries expire after a period without traffic, not a fixed time after they were made
/// (SL-SEC-004). They used to be dropped five minutes after creation however busy the connection was,
/// after which its segments matched nothing and left DIRECT. The socket CLOSE remains the normal end;
/// idle expiry only cleans up after a CLOSE that never arrived. A FIN or RST shortens the idle limit.
/// When a redirected entry ends - CLOSE or expiry - a short-lived tombstone refuses any packet that
/// still turns up for it, so a late segment is dropped rather than sent DIRECT.
/// </para>
/// </remarks>
public sealed class NatTable(TimeProvider? timeProvider = null)
{
    private readonly ConcurrentDictionary<FlowKey, NatEntry> _entries = new();
    private readonly ConcurrentDictionary<PortSlot, FlowKey> _redirected = new();
    private readonly ConcurrentDictionary<FlowKey, DirectDecision> _direct = new();
    private readonly ConcurrentDictionary<FlowKey, DirectDecision> _closedStrict = new();
    private readonly Lock _gate = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// How long an entry survives without traffic (redirected entries) or without being claimed
    /// (leave-alone decisions).
    /// </summary>
    /// <remarks>
    /// Generous relative to the gap between a socket-layer CONNECT event and the SYN that follows it
    /// — microseconds — and to a quiet but open connection, but short relative to ephemeral port
    /// reuse, which Windows spreads over thousands of ports.
    /// </remarks>
    public TimeSpan EntryLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>The idle limit once a FIN or RST has been seen.</summary>
    public TimeSpan ClosingLifetime { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Records that a packet of a redirected connection passed, so it is not expired.</summary>
    public void Touch(NatEntry entry, bool closing = false)
    {
        ArgumentNullException.ThrowIfNull(entry);
        entry.Touch(_time.GetUtcNow());

        if (closing)
        {
            entry.MarkClosing();
        }
    }

    /// <summary>Number of live entries.</summary>
    public int Count => _entries.Count;

    /// <summary>The table's clock. Entries are stamped with it so expiry is measured on one clock.</summary>
    public DateTimeOffset Now => _time.GetUtcNow();

    /// <summary>
    /// Records where a connection was really going, replacing any stale row for the same local end.
    /// </summary>
    /// <returns>
    /// False when another live redirected connection already holds the same family and port: the two
    /// could not be told apart after the rewrite, so the newcomer is refused rather than allowed to
    /// answer for the other.
    /// </returns>
    public bool Record(FlowKey key, NatEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        lock (_gate)
        {
            if (_redirected.TryGetValue(key.Slot, out var holder) && holder != key && IsLive(holder))
            {
                return false;
            }

            _closedStrict.TryRemove(key, out _);
            _entries[key] = entry;
            _redirected[key.Slot] = key;
            return true;
        }
    }

    /// <summary>Looks up a live entry; strict policy remains until socket CLOSE or routing shutdown.</summary>
    public bool TryGet(FlowKey key, out NatEntry entry)
    {
        if (!_entries.TryGetValue(key, out var found))
        {
            entry = null!;
            return false;
        }

        if (Expired(found))
        {
            RemoveEntry(key, found);
            entry = null!;
            return false;
        }

        entry = found;
        return true;
    }

    /// <summary>
    /// Looks up the redirected connection holding a family-and-port slot - what the redirect listener
    /// and the reply path can see.
    /// </summary>
    public bool TryGetRedirected(PortSlot slot, out NatEntry entry)
    {
        if (_redirected.TryGetValue(slot, out var key) && TryGet(key, out entry))
        {
            return true;
        }

        entry = null!;
        return false;
    }

    /// <summary>Records that a connection was decided against proxying.</summary>
    /// <remarks>
    /// <para>
    /// A decision that produced no redirect still has to be visible, because the packet loop cannot
    /// tell "not decided yet" from "decided to leave alone" by the absence of an entry. Without this
    /// it assumes the former and every SYN on the machine waits out the full decision window for an
    /// answer that already arrived, which measured 8 ms added to every connection an unselected
    /// application opened - against 0.68 ms with the engine down.
    /// </para>
    /// <para>
    /// Destination and port are kept so a recycled ephemeral port cannot answer for a connection
    /// that has nothing to do with it. Getting that wrong would be the serious direction of the two:
    /// a stale row would end a real decision's wait early and let a selected application's SYN out
    /// un-redirected.
    /// </para>
    /// </remarks>
    public void RecordDirect(FlowKey key, IPAddress destination, ushort destinationPort, ulong endpointId = 0) =>
        RecordVerdict(key, destination, destinationPort, NatVerdict.Direct, endpointId);

    /// <summary>
    /// Records a decision that produced no redirect, and what the packet loop must do about it.
    /// </summary>
    /// <remarks>
    /// Block and Pending used to be recorded as plain "leave alone", which made a TCP connection a
    /// rule blocked leave the machine DIRECT - counted as blocked, and delivered. The verdict is what
    /// makes the packet loop actually drop it. A "leave alone" from another socket never replaces a
    /// live refusal: two sockets share a local end only through address reuse, and when they do, the
    /// stricter answer stands.
    /// </remarks>
    public void RecordVerdict(
        FlowKey key, IPAddress destination, ushort destinationPort, NatVerdict verdict, ulong endpointId = 0)
    {
        ArgumentNullException.ThrowIfNull(destination);

        lock (_gate)
        {
            if (verdict == NatVerdict.Direct &&
                _direct.TryGetValue(key, out var existing) &&
                existing.Verdict != NatVerdict.Direct &&
                existing.EndpointId != endpointId)
            {
                return;
            }

            _closedStrict.TryRemove(key, out _);
            _direct[key] = new DirectDecision(destination, destinationPort, _time.GetUtcNow(), verdict, endpointId);
        }
    }

    /// <summary>
    /// Replaces a pending verdict with the decision that followed it, but only if the pending one is
    /// still the row for that local end. A socket that closed, or a port since reused for another
    /// connection, is left alone.
    /// </summary>
    public bool TryResolvePending(FlowKey key, IPAddress destination, ushort destinationPort)
    {
        lock (_gate)
        {
            return _direct.TryGetValue(key, out var found) &&
                   found.Verdict == NatVerdict.Pending &&
                   found.Port == destinationPort &&
                   found.Destination.Equals(destination) &&
                   _direct.TryRemove(new KeyValuePair<FlowKey, DirectDecision>(key, found));
        }
    }

    /// <summary>Looks up a live non-redirect decision with its verdict.</summary>
    public bool TryGetVerdict(
        FlowKey key, out IPAddress destination, out ushort destinationPort, out NatVerdict verdict)
    {
        verdict = NatVerdict.Direct;
        if (!TryGetDirect(key, out destination, out destinationPort))
        {
            return false;
        }

        verdict = _direct.TryGetValue(key, out var found) ? found.Verdict : NatVerdict.Direct;
        return true;
    }

    /// <summary>
    /// Looks up a live decision that produced no redirect - of any verdict - treating an expired one
    /// as absent.
    /// </summary>
    public bool TryGetDirect(FlowKey key, out IPAddress destination, out ushort destinationPort)
    {
        destination = null!;
        destinationPort = 0;

        if (!_direct.TryGetValue(key, out var found))
        {
            return false;
        }

        if (found.Verdict == NatVerdict.Direct && _time.GetUtcNow() - found.CreatedAt > EntryLifetime)
        {
            _direct.TryRemove(new KeyValuePair<FlowKey, DirectDecision>(key, found));
            return false;
        }

        destination = found.Destination;
        destinationPort = found.Port;
        return true;
    }

    /// <summary>Forgets a connection outright. Used for explicit cleanup, never for a socket CLOSE.</summary>
    public bool Remove(FlowKey key)
    {
        lock (_gate)
        {
            var removedDirect = _direct.TryRemove(key, out _);
            var removedEntry = _entries.TryRemove(key, out _);
            _redirected.TryRemove(new KeyValuePair<PortSlot, FlowKey>(key.Slot, key));
            return removedEntry || removedDirect;
        }
    }

    /// <summary>
    /// Forgets what a closing socket owned. Rows another socket recorded for the same local end are
    /// left alone (SL-SEC-005).
    /// </summary>
    /// <remarks>
    /// Socket CLOSE precedes some final kernel packets. A bounded refusal tombstone keeps FIN/ACK/RST
    /// of a strict connection from escaping DIRECT after its row is forgotten; a new CONNECT replaces it.
    /// </remarks>
    /// <param name="key">The closing socket's local end.</param>
    /// <param name="endpointId">The closing socket's endpoint id.</param>
    public void Close(FlowKey key, ulong endpointId)
    {
        lock (_gate)
        {
            if (_entries.TryGetValue(key, out var entry) && SameSocket(entry.EndpointId, endpointId))
            {
                // Any redirected connection, not only a strict one: its last segments must not leave
                // DIRECT after the row is gone.
                RemoveEntry(key, entry);
            }

            if (_direct.TryGetValue(key, out var decision) && SameSocket(decision.EndpointId, endpointId))
            {
                if (decision.Verdict != NatVerdict.Direct)
                {
                    _closedStrict[key] = decision with { CreatedAt = _time.GetUtcNow() };
                }

                _direct.TryRemove(new KeyValuePair<FlowKey, DirectDecision>(key, decision));
            }
        }
    }

    /// <summary>A final packet of a closed strict connection must still be refused.</summary>
    public bool IsClosedStrict(FlowKey key, IPAddress destination, ushort destinationPort) =>
        _closedStrict.TryGetValue(key, out var found) &&
        _time.GetUtcNow() - found.CreatedAt <= EntryLifetime &&
        found.Port == destinationPort && found.Destination.Equals(destination);

    /// <summary>
    /// Drops idle rows. ProxyOnly and refusal rows remain until socket CLOSE or routing shutdown, and an
    /// expired redirected row leaves a tombstone, so expiry cannot turn a protected flow into DIRECT.
    /// </summary>
    public int Sweep()
    {
        var cutoff = _time.GetUtcNow() - EntryLifetime;
        var removed = 0;

        foreach (var (key, entry) in _entries)
        {
            if (Expired(entry) && RemoveEntry(key, entry))
            {
                removed++;
            }
        }

        foreach (var (key, decision) in _direct)
        {
            if (decision.Verdict == NatVerdict.Direct && decision.CreatedAt < cutoff &&
                _direct.TryRemove(new KeyValuePair<FlowKey, DirectDecision>(key, decision)))
            {
                removed++;
            }
        }

        foreach (var (key, decision) in _closedStrict)
        {
            if (decision.CreatedAt < cutoff)
            {
                _closedStrict.TryRemove(new KeyValuePair<FlowKey, DirectDecision>(key, decision));
            }
        }

        return removed;
    }

    /// <summary>Forgets everything. Used when routing stops.</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
            _redirected.Clear();
            _direct.Clear();
            _closedStrict.Clear();
        }
    }

    /// <summary>
    /// Whether a recorded owner and a closing socket are the same socket. An owner of 0 was recorded
    /// without an endpoint id (tests, diagnostics) and is matched by any close.
    /// </summary>
    private static bool SameSocket(ulong owner, ulong closing) => owner == 0 || owner == closing;

    private bool Expired(NatEntry entry) =>
        entry.Action != RouteAction.ProxyOnly &&
        _time.GetUtcNow() - entry.LastSeen > (entry.IsClosing ? ClosingLifetime : EntryLifetime);

    private bool IsLive(FlowKey key) => _entries.TryGetValue(key, out var entry) && !Expired(entry);

    private bool RemoveEntry(FlowKey key, NatEntry entry)
    {
        if (!_entries.TryRemove(new KeyValuePair<FlowKey, NatEntry>(key, entry)))
        {
            return false;
        }

        _redirected.TryRemove(new KeyValuePair<PortSlot, FlowKey>(key.Slot, key));

        // A tombstone: a segment of this connection that still turns up - after a CLOSE, or after idle
        // expiry - is refused, never sent DIRECT. A new CONNECT on the same local end replaces it.
        _closedStrict[key] = new DirectDecision(
            entry.OriginalDestination, entry.OriginalDestinationPort, _time.GetUtcNow(), NatVerdict.Block, entry.EndpointId);
        return true;
    }

    private readonly record struct DirectDecision(
        IPAddress Destination,
        ushort Port,
        DateTimeOffset CreatedAt,
        NatVerdict Verdict = NatVerdict.Direct,
        ulong EndpointId = 0);

    /// <summary>Builds an entry from a routing decision and a socket-layer event.</summary>
    public static NatEntry EntryFor(
        IPAddress source,
        IPAddress destination,
        ushort destinationPort,
        uint processId,
        string executablePath,
        AppRule? rule,
        string? hostname,
        DateTimeOffset now)
        => new(
            source,
            destination,
            destinationPort,
            processId,
            executablePath,
            rule?.Identity.DisplayName,
            hostname,
            now);
}
