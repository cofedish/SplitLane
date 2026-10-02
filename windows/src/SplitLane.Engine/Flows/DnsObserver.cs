using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using SplitLane.Core.Rules;

namespace SplitLane.Engine.Flows;

/// <summary>
/// Correlates addresses with bounded, TTL-limited DNS evidence.
/// </summary>
/// <remarks>
/// <para>
/// SplitLane never sees a hostname on Windows. The socket-layer event that carries the process id
/// carries an address, because resolution already happened — in a different process, the DNS Client
/// service, which is where the same limitation the macOS build documents comes from.
/// </para>
/// <para>
/// So the name is recovered rather than intercepted: DNS <i>responses</i> are sniffed, and the
/// answers are remembered. The existing proxy path and domain policies share this evidence. Multiple
/// live names on one IP are ambiguous; the observer does not guess the application's intended name.
/// </para>
/// <para>
/// It does <b>not</b> make DNS private. The query still left this machine in the clear. That
/// limitation is real, is the same one macOS has, and is documented rather than papered over.
/// </para>
/// </remarks>
public sealed class DnsObserver(TimeProvider? timeProvider = null)
{
    private readonly ConcurrentDictionary<IPAddress, Entry[]> _names = new();
    private readonly Lock _writeGate = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    private readonly record struct Entry(string Hostname, DateTimeOffset ExpiresAt);

    /// <summary>How long a remembered name is trusted.</summary>
    /// <remarks>
    /// Short on purpose. A stale mapping would send the upstream a name that no longer resolves to
    /// the address the application is trying to reach, which turns a working connection into a
    /// confusing failure. Ten minutes comfortably covers a page load without outliving a DNS change.
    /// </remarks>
    public TimeSpan EntryLifetime { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Upper bound on remembered names, so a hostile resolver cannot grow the table forever.</summary>
    public int MaxEntries { get; init; } = 8192;

    /// <summary>Number of remembered addresses.</summary>
    public int Count => _names.Count;

    /// <summary>Records that an address answers to a name.</summary>
    public void Record(IPAddress address, string hostname)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (!DomainPattern.TryNormalize(hostname, out var normalized))
        {
            return;
        }

        lock (_writeGate)
        {
            Add(address, normalized, _time.GetUtcNow() + EntryLifetime);
        }
    }

    /// <summary>Returns the remembered name for an address, or null.</summary>
    public string? Lookup(IPAddress? address)
    {
        if (address is null || !_names.TryGetValue(address, out var entries))
        {
            return null;
        }

        var now = _time.GetUtcNow();
        string? result = null;
        foreach (var entry in entries)
        {
            if (entry.ExpiresAt <= now)
            {
                continue;
            }

            if (result is not null && !string.Equals(result, entry.Hostname, StringComparison.Ordinal))
            {
                return null;
            }

            result = entry.Hostname;
        }
        return result;
    }

    /// <summary>Forgets everything.</summary>
    public void Clear()
    {
        lock (_writeGate)
        {
            _names.Clear();
        }
    }

    /// <summary>Removes expired associations periodically; readers see immutable arrays.</summary>
    public void Sweep()
    {
        lock (_writeGate)
        {
            var now = _time.GetUtcNow();
            foreach (var (address, entries) in _names)
            {
                var live = entries.Where(e => e.ExpiresAt > now).ToArray();
                if (live.Length == 0)
                {
                    _names.TryRemove(address, out _);
                }
                else if (live.Length != entries.Length)
                {
                    _names[address] = live;
                }
            }
        }
    }

    private void Add(IPAddress address, string hostname, DateTimeOffset expiresAt)
    {
        if (MaxEntries <= 0 || expiresAt <= _time.GetUtcNow())
        {
            return;
        }

        if (!_names.ContainsKey(address) && _names.Count >= MaxEntries)
        {
            Sweep();
            if (_names.Count >= MaxEntries)
            {
                var oldest = _names.MinBy(pair => pair.Value.Max(e => e.ExpiresAt));
                _names.TryRemove(oldest.Key, out _);
            }
        }

        var previous = _names.TryGetValue(address, out var entries) ? entries : [];
        var live = previous.Where(e => e.ExpiresAt > _time.GetUtcNow() && e.Hostname != hostname).ToArray();
        // Bound aliases per IP too. Saturated evidence stays ambiguous until the latest TTL expires.
        if (live.Length >= 16)
        {
            _names[address] = [new Entry("", live.Max(e => e.ExpiresAt)), new Entry("?", expiresAt)];
            return;
        }
        _names[address] = [.. live, new Entry(hostname, expiresAt)];
    }

    /// <summary>
    /// Parses a DNS response and records every A and AAAA answer.
    /// </summary>
    /// <remarks>
    /// A deliberately small parser: it reads the question name, walks the answer section, and takes
    /// only A and AAAA records. Everything else — authority, additional, SRV, CNAME chains beyond the
    /// owner name — is skipped, because none of it changes which name to hand a SOCKS5 server.
    ///
    /// <para>
    /// Every offset is bounds-checked against the datagram that actually arrived, and compression
    /// pointers are followed with a hard jump limit. A DNS response is attacker-controlled input
    /// arriving in an elevated process, so a malformed one must produce "nothing learned", never a
    /// read past the buffer and never an infinite loop.
    /// </para>
    /// </remarks>
    public int IngestResponse(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < 12)
        {
            return 0;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(datagram[2..4]);
        var isResponse = (flags & 0x8000) != 0;
        var responseCode = flags & 0x000F;
        if (!isResponse || responseCode != 0 || (flags & 0x0200) != 0)
        {
            return 0;
        }

        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(datagram[4..6]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(datagram[6..8]);
        if (questionCount != 1 || answerCount == 0 || answerCount > 256)
        {
            return 0;
        }

        var offset = 12;

        if (!TryReadName(datagram, ref offset, out var questionName) || offset + 4 > datagram.Length ||
            !DomainPattern.TryNormalize(questionName, out questionName))
        {
            return 0;
        }

        if (BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(offset + 2, 2)) != 1)
        {
            return 0;
        }
        offset += 4;
        var addresses = new List<(string Owner, IPAddress Address, uint Ttl)>();
        var aliases = new Dictionary<string, (string Target, uint Ttl)>(StringComparer.Ordinal);

        for (var i = 0; i < answerCount; i++)
        {
            if (!TryReadName(datagram, ref offset, out var owner) || offset + 10 > datagram.Length ||
                !DomainPattern.TryNormalize(owner, out owner))
            {
                return 0;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(offset, 2));
            var recordClass = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(offset + 2, 2));
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(offset + 4, 4));
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(offset + 8, 2));
            offset += 10;

            if (offset + dataLength > datagram.Length)
            {
                return 0;
            }

            switch (recordClass == 1 ? type : 0)
            {
                case 1 when dataLength == 4:
                    addresses.Add((owner, new IPAddress(datagram.Slice(offset, 4)), ttl));
                    break;

                case 28 when dataLength == 16:
                    addresses.Add((owner, new IPAddress(datagram.Slice(offset, 16)), ttl));
                    break;

                case 5:
                    var cnameOffset = offset;
                    if (!TryReadName(datagram, ref cnameOffset, out var target) || cnameOffset != offset + dataLength ||
                        !DomainPattern.TryNormalize(target, out target))
                    {
                        return 0;
                    }
                    aliases[owner] = (target, ttl);
                    break;
            }

            offset += dataLength;
        }

        var reachable = new Dictionary<string, uint>(StringComparer.Ordinal) { [questionName] = uint.MaxValue };
        var current = questionName;
        var chainTtl = uint.MaxValue;
        for (var i = 0; i < 16 && aliases.TryGetValue(current, out var alias); i++)
        {
            if (reachable.ContainsKey(alias.Target))
            {
                return 0;
            }
            chainTtl = Math.Min(chainTtl, alias.Ttl);
            reachable[alias.Target] = chainTtl;
            current = alias.Target;
        }

        var learned = addresses.Where(a => reachable.ContainsKey(a.Owner)).ToArray();
        lock (_writeGate)
        {
            // Replace only the families answered, preserving an AAAA answer when A is refreshed.
            var families = learned.Select(a => a.Address.AddressFamily).ToHashSet();
            foreach (var (address, entries) in _names)
            {
                if (!families.Contains(address.AddressFamily))
                {
                    continue;
                }
                var kept = entries.Where(e => e.Hostname != questionName).ToArray();
                if (kept.Length == 0)
                {
                    _names.TryRemove(address, out _);
                }
                else
                {
                    _names[address] = kept;
                }
            }

            var now = _time.GetUtcNow();
            foreach (var answer in learned)
            {
                var seconds = Math.Min(answer.Ttl, reachable[answer.Owner]);
                var lifetime = TimeSpan.FromSeconds(Math.Min(seconds, EntryLifetime.TotalSeconds));
                Add(answer.Address, questionName, now + lifetime);
            }
        }
        return learned.Length;
    }

    /// <summary>Reads a possibly compressed DNS name, advancing past it in the wire stream.</summary>
    private static bool TryReadName(ReadOnlySpan<byte> datagram, ref int offset, out string name)
    {
        name = string.Empty;
        var builder = new StringBuilder();
        var cursor = offset;
        var jumps = 0;
        var advanced = false;

        while (true)
        {
            if (cursor >= datagram.Length)
            {
                return false;
            }

            var length = datagram[cursor];

            if (length == 0)
            {
                cursor++;
                if (!advanced)
                {
                    offset = cursor;
                }

                name = builder.ToString();
                return true;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= datagram.Length)
                {
                    return false;
                }

                // A pointer chain must terminate. Sixteen jumps is far beyond any real encoding and
                // bounds the work a hostile response can cause.
                if (++jumps > 16)
                {
                    return false;
                }

                var pointer = ((length & 0x3F) << 8) | datagram[cursor + 1];

                if (!advanced)
                {
                    offset = cursor + 2;
                    advanced = true;
                }

                if (pointer >= datagram.Length || pointer >= cursor)
                {
                    // Forward or self-referential pointers are malformed; only backward references
                    // are legal, and requiring that is what makes termination provable.
                    return false;
                }

                cursor = pointer;
                continue;
            }

            if ((length & 0xC0) != 0)
            {
                return false;
            }

            cursor++;
            if (cursor + length > datagram.Length)
            {
                return false;
            }

            if (builder.Length > 0)
            {
                builder.Append('.');
            }

            builder.Append(Encoding.ASCII.GetString(datagram.Slice(cursor, length)));
            cursor += length;

            if (builder.Length > 255)
            {
                return false;
            }
        }
    }
}
