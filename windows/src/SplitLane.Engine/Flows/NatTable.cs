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
    DateTimeOffset CreatedAt);

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
/// theoretical rather than practical; it is recorded in docs/windows/THREAT_MODEL.md as W-6 rather
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

    /// <summary>Forgets a connection, normally when its socket closes.</summary>
    public bool Remove(ushort localPort) => _entries.TryRemove(localPort, out _);

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

        return removed;
    }

    /// <summary>Forgets everything. Used when routing stops.</summary>
    public void Clear() => _entries.Clear();

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
