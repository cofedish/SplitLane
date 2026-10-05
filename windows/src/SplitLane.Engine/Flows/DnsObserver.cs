using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using SplitLane.Core.Rules;

namespace SplitLane.Engine.Flows;

/// <summary>Which transport a DNS message travelled over.</summary>
public enum DnsTransport
{
    /// <summary>UDP, one message per datagram.</summary>
    Udp,

    /// <summary>TCP, length-prefixed messages.</summary>
    Tcp,
}

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
/// <b>A response is evidence only if it answers a query this machine was seen to send</b> (SL-SEC-003).
/// Its transport, both endpoints (reversed), transaction id, question name, type and class must match
/// a query observed less than <see cref="QueryLifetime"/> ago, and the query is consumed by the first
/// matching answer. A packet that merely comes from port 53 - forged by a local process on loopback, or
/// by a host on the LAN - teaches nothing. A resolver on loopback is believed only if Windows is
/// configured to use it (<see cref="IsConfiguredResolver"/>): on loopback a local process can play both
/// the client and the server.
/// </para>
/// <para>
/// What this does not and cannot establish: that the resolver told the truth, or that a name the
/// resolver vouched for belongs to whoever asked. A local process may still ask the real resolver about
/// a domain it controls; the answer is genuine DNS and is learned as such. When that makes one address
/// carry two names, <see cref="Lookup"/> reports neither.
/// </para>
/// <para>
/// It does <b>not</b> make DNS private. The query still left this machine in the clear. That
/// limitation is real, is the same one macOS has, and is documented rather than papered over.
/// </para>
/// </remarks>
public sealed class DnsObserver(TimeProvider? timeProvider = null)
{
    private const ushort TypeA = 1;
    private const ushort TypeCname = 5;
    private const ushort TypeAaaa = 28;
    private const ushort ClassIn = 1;

    private readonly ConcurrentDictionary<IPAddress, Entry[]> _names = new();
    private readonly Dictionary<string, HashSet<IPAddress>> _addressesByName = new(StringComparer.Ordinal);
    private readonly Queue<IPAddress> _insertionOrder = new();
    private readonly ConcurrentDictionary<QueryKey, DateTimeOffset> _pending = new();
    private readonly Queue<QueryKey> _pendingOrder = new();
    private readonly Lock _writeGate = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    private readonly record struct Entry(string Hostname, DateTimeOffset ExpiresAt);

    /// <summary>Everything a response has to match to be accepted as the answer to a query.</summary>
    private readonly record struct QueryKey(
        DnsTransport Transport,
        IPAddress Client,
        ushort ClientPort,
        IPAddress Server,
        ushort ServerPort,
        ushort Id,
        string Name,
        ushort Type,
        ushort Class);

    /// <summary>How long a remembered name is trusted.</summary>
    /// <remarks>
    /// Short on purpose. A stale mapping would send the upstream a name that no longer resolves to
    /// the address the application is trying to reach, which turns a working connection into a
    /// confusing failure. Ten minutes comfortably covers a page load without outliving a DNS change.
    /// </remarks>
    public TimeSpan EntryLifetime { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Upper bound on remembered names, so a hostile resolver cannot grow the table forever.</summary>
    public int MaxEntries { get; init; } = 8192;

    /// <summary>How long a query waits for its answer.</summary>
    /// <remarks>
    /// The Windows DNS client gives up on a server after a few seconds and retries with a new
    /// transaction id, so an answer older than this answers nothing anyone is still waiting for.
    /// </remarks>
    public TimeSpan QueryLifetime { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Upper bound on queries awaiting an answer.</summary>
    /// <remarks>
    /// Far beyond what a machine has in flight at once (the DNS client caches, and retries with
    /// backoff), and small enough that a flood of queries costs a bounded amount of memory. When full,
    /// expired queries are dropped first and then the oldest. A new query used to be refused instead,
    /// and then any local process sending a few thousand queries to any address kept every genuine
    /// answer from being learned, which turned domain rules off. Now a flood has to outpace the
    /// milliseconds a real answer takes - thousands of queries in that time - to push one out.
    /// </remarks>
    public int MaxPendingQueries { get; init; } = 4096;

    /// <summary>
    /// Whether a loopback address is one of the machine's configured DNS servers. When null, no
    /// loopback resolver is believed.
    /// </summary>
    public Func<IPAddress, bool>? IsConfiguredResolver { get; init; }

    /// <summary>Number of remembered addresses.</summary>
    public int Count => _names.Count;

    /// <summary>Number of queries waiting for an answer.</summary>
    public int PendingQueryCount => _pending.Count;

    /// <summary>Records that an address answers to a name.</summary>
    /// <remarks>Trusted input only: tests and diagnostics. Packets never reach this.</remarks>
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
            _addressesByName.Clear();
            _insertionOrder.Clear();
            _pending.Clear();
            _pendingOrder.Clear();
        }
    }

    /// <summary>Removes expired associations and queries periodically; readers see immutable arrays.</summary>
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
                    RemoveAddress(address);
                }
                else if (live.Length != entries.Length)
                {
                    foreach (var gone in entries.Where(e => e.ExpiresAt <= now))
                    {
                        Unindex(gone.Hostname, address);
                    }

                    _names[address] = live;
                }
            }

            SweepQueries(now);
        }
    }

    /// <summary>
    /// Notes a query on its way to a resolver, so that its answer can be recognised.
    /// </summary>
    /// <returns>Whether the query is now awaiting an answer.</returns>
    public bool ObserveQuery(DnsTransport transport, IPEndPoint client, IPEndPoint server, ReadOnlySpan<byte> message)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(server);

        if (!IsBelievableResolver(server.Address) ||
            !TryReadHeader(message, expectResponse: false, out var id, out var offset) ||
            !TryReadQuestion(message, ref offset, out var name, out var type, out var recordClass) ||
            recordClass != ClassIn || type is not (TypeA or TypeAaaa))
        {
            return false;
        }

        var key = new QueryKey(
            transport, client.Address, (ushort)client.Port, server.Address, (ushort)server.Port, id, name, type, recordClass);

        var now = _time.GetUtcNow();

        lock (_writeGate)
        {
            // The order queue is never shorter than the table, so it is a cheap first test.
            if (_pendingOrder.Count >= MaxPendingQueries && _pending.Count >= MaxPendingQueries)
            {
                SweepQueries(now);

                while (_pending.Count >= MaxPendingQueries && _pendingOrder.TryDequeue(out var oldest))
                {
                    _pending.TryRemove(oldest, out _);
                }
            }

            _pending[key] = now + QueryLifetime;
            _pendingOrder.Enqueue(key);

            if (_pendingOrder.Count > 2 * MaxPendingQueries)
            {
                // Answered queries leave their keys behind in the order; keep it bounded.
                CompactPendingOrder();
            }
        }

        return true;
    }

    /// <summary>
    /// Learns from a response, if and only if it answers a query observed with
    /// <see cref="ObserveQuery"/>.
    /// </summary>
    /// <returns>How many addresses were learned.</returns>
    /// <remarks>
    /// Every offset is bounds-checked against the message that actually arrived, and compression
    /// pointers are followed with a hard jump limit. A DNS response is attacker-controlled input
    /// arriving in an elevated process, so a malformed one must produce "nothing learned", never a
    /// read past the buffer and never an infinite loop.
    /// </remarks>
    public int IngestResponse(DnsTransport transport, IPEndPoint server, IPEndPoint client, ReadOnlySpan<byte> message)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(client);

        if (!TryReadHeader(message, expectResponse: true, out var id, out var offset))
        {
            return 0;
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..4]);
        var responseCode = flags & 0x000F;
        if (responseCode != 0 || (flags & 0x0200) != 0)
        {
            return 0;
        }

        if (!TryReadQuestion(message, ref offset, out var questionName, out var type, out var recordClass))
        {
            return 0;
        }

        var key = new QueryKey(
            transport, client.Address, (ushort)client.Port, server.Address, (ushort)server.Port, id, questionName, type, recordClass);

        // Consumed by the first matching answer: a second, possibly forged, "answer" to the same
        // query finds nothing to answer.
        if (!_pending.TryRemove(key, out var deadline) || deadline <= _time.GetUtcNow())
        {
            return 0;
        }

        return Learn(message, offset, questionName);
    }

    private bool IsBelievableResolver(IPAddress server) =>
        !IPAddress.IsLoopback(server) || (IsConfiguredResolver?.Invoke(server) ?? false);

    private static bool TryReadHeader(ReadOnlySpan<byte> message, bool expectResponse, out ushort id, out int offset)
    {
        id = 0;
        offset = 12;

        if (message.Length < 12)
        {
            return false;
        }

        id = BinaryPrimitives.ReadUInt16BigEndian(message[..2]);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..4]);
        var isResponse = (flags & 0x8000) != 0;
        var opcode = (flags >> 11) & 0x0F;
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(message[4..6]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(message[6..8]);

        if (isResponse != expectResponse || opcode != 0 || questionCount != 1)
        {
            return false;
        }

        return expectResponse ? answerCount is > 0 and <= 256 : answerCount == 0;
    }

    private static bool TryReadQuestion(
        ReadOnlySpan<byte> message, ref int offset, out string name, out ushort type, out ushort recordClass)
    {
        type = 0;
        recordClass = 0;

        if (!TryReadName(message, ref offset, out name) || offset + 4 > message.Length ||
            !DomainPattern.TryNormalize(name, out name))
        {
            return false;
        }

        type = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
        recordClass = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 2, 2));
        offset += 4;
        return true;
    }

    /// <summary>Walks the answer section of a response already matched to its query.</summary>
    private int Learn(ReadOnlySpan<byte> datagram, int offset, string questionName)
    {
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(datagram[6..8]);
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

            switch (recordClass == ClassIn ? type : 0)
            {
                case TypeA when dataLength == 4:
                    addresses.Add((owner, new IPAddress(datagram.Slice(offset, 4)), ttl));
                    break;

                case TypeAaaa when dataLength == 16:
                    addresses.Add((owner, new IPAddress(datagram.Slice(offset, 16)), ttl));
                    break;

                case TypeCname:
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
            // Replace only the families answered, preserving an AAAA answer when A is refreshed. The
            // index makes this proportional to what the name had, not to the whole table: a burst of
            // answers can no longer stall the packet loop that calls this.
            var families = learned.Select(a => a.Address.AddressFamily).ToHashSet();
            if (_addressesByName.TryGetValue(questionName, out var previous))
            {
                foreach (var address in previous.Where(a => families.Contains(a.AddressFamily)).ToArray())
                {
                    if (!_names.TryGetValue(address, out var entries))
                    {
                        continue;
                    }

                    var kept = entries.Where(e => e.Hostname != questionName).ToArray();
                    Unindex(questionName, address);

                    if (kept.Length == 0)
                    {
                        _names.TryRemove(address, out _);
                    }
                    else
                    {
                        _names[address] = kept;
                    }
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

    private void Add(IPAddress address, string hostname, DateTimeOffset expiresAt)
    {
        if (MaxEntries <= 0 || expiresAt <= _time.GetUtcNow())
        {
            return;
        }

        if (!_names.ContainsKey(address))
        {
            // Evict in insertion order rather than scanning for the oldest: constant work per add,
            // however full the table is.
            while (_names.Count >= MaxEntries && _insertionOrder.TryDequeue(out var oldest))
            {
                RemoveAddress(oldest);
            }

            _insertionOrder.Enqueue(address);

            // The queue can hold addresses already removed by expiry; keep it from outgrowing the table.
            if (_insertionOrder.Count > MaxEntries * 2)
            {
                var stillPresent = _insertionOrder.Where(_names.ContainsKey).Distinct().ToArray();
                _insertionOrder.Clear();
                foreach (var kept in stillPresent)
                {
                    _insertionOrder.Enqueue(kept);
                }

                if (!_insertionOrder.Contains(address))
                {
                    _insertionOrder.Enqueue(address);
                }
            }
        }

        var now = _time.GetUtcNow();
        var previous = _names.TryGetValue(address, out var entries) ? entries : [];
        var live = previous.Where(e => e.ExpiresAt > now && e.Hostname != hostname).ToArray();

        foreach (var expired in previous.Where(e => e.ExpiresAt <= now && e.Hostname != hostname))
        {
            Unindex(expired.Hostname, address);
        }

        // Bound aliases per IP too. Saturated evidence stays ambiguous until the latest TTL expires.
        if (live.Length >= 16)
        {
            foreach (var entry in previous)
            {
                Unindex(entry.Hostname, address);
            }

            _names[address] = [new Entry("", live.Max(e => e.ExpiresAt)), new Entry("?", expiresAt)];
            return;
        }

        _names[address] = [.. live, new Entry(hostname, expiresAt)];
        Index(hostname, address);
    }

    private void RemoveAddress(IPAddress address)
    {
        if (_names.TryRemove(address, out var entries))
        {
            foreach (var entry in entries)
            {
                Unindex(entry.Hostname, address);
            }
        }
    }

    private void Index(string hostname, IPAddress address)
    {
        if (!_addressesByName.TryGetValue(hostname, out var set))
        {
            _addressesByName[hostname] = set = [];
        }

        set.Add(address);
    }

    private void Unindex(string hostname, IPAddress address)
    {
        if (_addressesByName.TryGetValue(hostname, out var set) && set.Remove(address) && set.Count == 0)
        {
            _addressesByName.Remove(hostname);
        }
    }

    private void SweepQueries(DateTimeOffset now)
    {
        foreach (var (key, deadline) in _pending)
        {
            if (deadline <= now)
            {
                _pending.TryRemove(key, out _);
            }
        }

        CompactPendingOrder();
    }

    /// <summary>Drops keys of queries no longer pending from the order, keeping one per pending query.</summary>
    private void CompactPendingOrder()
    {
        var kept = new HashSet<QueryKey>();
        var count = _pendingOrder.Count;

        for (var i = 0; i < count; i++)
        {
            var key = _pendingOrder.Dequeue();
            if (_pending.ContainsKey(key) && kept.Add(key))
            {
                _pendingOrder.Enqueue(key);
            }
        }
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
