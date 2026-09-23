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
/// <param name="CreatedAt">When the entry was made, for expiry.</param>
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
/// The key is the application's own local port. That is the only identifier that survives the
/// rewrite: the engine changes both addresses and the destination port, but the source port is left
/// alone precisely so that the return path and the redirect listener can both find the entry.
/// </para>
/// <para>
/// A local port is unique per protocol per local address, not globally, so two sockets bound to the
/// same port on different local addresses would collide here. Windows allocates ephemeral ports from
/// a shared pool and the case requires a deliberate <c>SO_REUSEADDR</c> bind, so the collision is
/// theoretical rather than practical; it is recorded in docs/THREAT_MODEL.md as W-6 rather
/// than defended against, because defending against it would mean keying on an address the redirect
/// listener never sees.
/// </para>
/// <para>
/// Entries expire. Without expiry, a table keyed on a 16-bit port would accumulate stale rows for
/// every connection the engine ever saw and eventually mis-attribute a recycled port to a long-dead
/// flow — a leak of one app's traffic into another app's lane.
/// </para>
/// </remarks>
public sealed class NatTable(TimeProvider? timeProvider = null)
{
    private readonly ConcurrentDictionary<ushort, NatEntry> _entries = new();
    private readonly ConcurrentDictionary<ushort, DirectDecision> _direct = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// How long an entry survives without being claimed.
    /// </summary>
    /// <remarks>
    /// Generous relative to the gap between a socket-layer CONNECT event and the SYN that follows it
    /// — microseconds — but short relative to ephemeral port reuse, which Windows spreads over
    /// thousands of ports.
    /// </remarks>
    public TimeSpan EntryLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Number of live entries.</summary>
    public int Count => _entries.Count;

    /// <summary>Records where a connection was really going, replacing any stale row on that port.</summary>
    public void Record(ushort localPort, NatEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _entries[localPort] = entry;
    }

    /// <summary>Looks up a live entry, treating an expired one as absent.</summary>
    public bool TryGet(ushort localPort, out NatEntry entry)
    {
        if (!_entries.TryGetValue(localPort, out var found))
        {
            entry = null!;
            return false;
        }

        if (_time.GetUtcNow() - found.CreatedAt > EntryLifetime)
        {
            _entries.TryRemove(localPort, out _);
            entry = null!;
            return false;
        }

        entry = found;
        return true;
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
    public void RecordDirect(ushort localPort, IPAddress destination, ushort destinationPort) =>
        RecordVerdict(localPort, destination, destinationPort, NatVerdict.Direct);

    /// <summary>
    /// Records a decision that produced no redirect, and what the packet loop must do about it.
    /// </summary>
    /// <remarks>
    /// Block and Pending used to be recorded as plain "leave alone", which made a TCP connection a
    /// rule blocked leave the machine DIRECT - counted as blocked, and delivered. The verdict is what
    /// makes the packet loop actually drop it.
    /// </remarks>
    public void RecordVerdict(ushort localPort, IPAddress destination, ushort destinationPort, NatVerdict verdict)
    {
        ArgumentNullException.ThrowIfNull(destination);
        _direct[localPort] = new DirectDecision(destination, destinationPort, _time.GetUtcNow(), verdict);
    }

    /// <summary>
    /// Replaces a pending verdict with the decision that followed it, but only if the pending one is
    /// still the row on that port. A socket that closed, or a port since reused for another
    /// connection, is left alone.
    /// </summary>
    public bool TryResolvePending(ushort localPort, IPAddress destination, ushort destinationPort)
    {
        return _direct.TryGetValue(localPort, out var found) &&
               found.Verdict == NatVerdict.Pending &&
               found.Port == destinationPort &&
               found.Destination.Equals(destination) &&
               _direct.TryRemove(new KeyValuePair<ushort, DirectDecision>(localPort, found));
    }

    /// <summary>Looks up a live non-redirect decision with its verdict.</summary>
    public bool TryGetVerdict(
        ushort localPort, out IPAddress destination, out ushort destinationPort, out NatVerdict verdict)
    {
        verdict = NatVerdict.Direct;
        if (!TryGetDirect(localPort, out destination, out destinationPort))
        {
            return false;
        }

        verdict = _direct.TryGetValue(localPort, out var found) ? found.Verdict : NatVerdict.Direct;
        return true;
    }

    /// <summary>
    /// Looks up a live decision that produced no redirect - of any verdict - treating an expired one
    /// as absent.
    /// </summary>
    public bool TryGetDirect(ushort localPort, out IPAddress destination, out ushort destinationPort)
    {
        destination = null!;
        destinationPort = 0;

        if (!_direct.TryGetValue(localPort, out var found))
        {
            return false;
        }

        if (_time.GetUtcNow() - found.CreatedAt > EntryLifetime)
        {
            _direct.TryRemove(localPort, out _);
            return false;
        }

        destination = found.Destination;
        destinationPort = found.Port;
        return true;
    }

    /// <summary>Forgets a connection, normally when its socket closes.</summary>
    /// <remarks>
    /// Both halves go together. A close that forgot only one of them would leave the other to answer
    /// for whichever connection inherits the port next.
    /// </remarks>
    public bool Remove(ushort localPort)
    {
        var removedDirect = _direct.TryRemove(localPort, out _);
        return _entries.TryRemove(localPort, out _) || removedDirect;
    }

    /// <summary>Drops expired rows. Called periodically rather than on every lookup.</summary>
    public int Sweep()
    {
        var cutoff = _time.GetUtcNow() - EntryLifetime;
        var removed = 0;

        foreach (var (port, entry) in _entries)
        {
            if (entry.CreatedAt < cutoff && _entries.TryRemove(port, out _))
            {
                removed++;
            }
        }

        foreach (var (port, decision) in _direct)
        {
            if (decision.CreatedAt < cutoff && _direct.TryRemove(port, out _))
            {
                removed++;
            }
        }

        return removed;
    }

    /// <summary>Forgets everything. Used when routing stops.</summary>
    public void Clear()
    {
        _entries.Clear();
        _direct.Clear();
    }

    private readonly record struct DirectDecision(
        IPAddress Destination,
        ushort Port,
        DateTimeOffset CreatedAt,
        NatVerdict Verdict = NatVerdict.Direct);

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
