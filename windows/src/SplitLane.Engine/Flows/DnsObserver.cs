using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace SplitLane.Engine.Flows;

/// <summary>
/// Remembers which hostname an address was most recently resolved from.
/// </summary>
/// <remarks>
/// <para>
/// SplitLane never sees a hostname on Windows. The socket-layer event that carries the process id
/// carries an address, because resolution already happened — in a different process, the DNS Client
/// service, which is where the same limitation the macOS build documents comes from.
/// </para>
/// <para>
/// So the name is recovered rather than intercepted: DNS <i>responses</i> are sniffed, and the
/// answers are remembered. This is strictly an optimisation for the SOCKS5 request — it lets the
/// upstream resolve the name from its own vantage point instead of being handed a CDN edge address
/// the local resolver picked. It is never used for a routing decision, because a name is what the
/// application asked for and an address is where the packet goes.
/// </para>
/// <para>
/// It does <b>not</b> make DNS private. The query still left this machine in the clear. That
/// limitation is real, is the same one macOS has, and is documented rather than papered over.
/// </para>
/// </remarks>
public sealed class DnsObserver(TimeProvider? timeProvider = null)
{
    private readonly ConcurrentDictionary<string, Entry> _names = new(StringComparer.Ordinal);
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    private readonly record struct Entry(string Hostname, DateTimeOffset SeenAt);

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

        if (string.IsNullOrWhiteSpace(hostname))
        {
            return;
        }

        if (_names.Count >= MaxEntries)
        {
            _names.Clear();
        }

        _names[address.ToString()] = new Entry(hostname, _time.GetUtcNow());
    }

    /// <summary>Returns the remembered name for an address, or null.</summary>
    public string? Lookup(IPAddress? address)
    {
        if (address is null || !_names.TryGetValue(address.ToString(), out var entry))
        {
            return null;
        }

        if (_time.GetUtcNow() - entry.SeenAt > EntryLifetime)
        {
            _names.TryRemove(address.ToString(), out _);
            return null;
        }

        return entry.Hostname;
    }

    /// <summary>Forgets everything.</summary>
    public void Clear() => _names.Clear();

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
        if (!isResponse || responseCode != 0)
        {
            return 0;
        }

        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(datagram[4..6]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(datagram[6..8]);
        if (questionCount == 0 || answerCount == 0)
        {
            return 0;
        }

        var offset = 12;

        if (!TryReadName(datagram, ref offset, out var questionName))
        {
            return 0;
        }

        // QTYPE + QCLASS, plus any further questions, which are vanishingly rare and skipped whole.
        offset += 4;
        for (var i = 1; i < questionCount; i++)
        {
            if (!TryReadName(datagram, ref offset, out _))
            {
                return 0;
            }

            offset += 4;
        }

        var recorded = 0;

        for (var i = 0; i < answerCount; i++)
        {
            if (!TryReadName(datagram, ref offset, out _) || offset + 10 > datagram.Length)
            {
                break;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(offset, 2));
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(offset + 8, 2));
            offset += 10;

            if (offset + dataLength > datagram.Length)
            {
                break;
            }

            switch (type)
            {
                case 1 when dataLength == 4:
                    Record(new IPAddress(datagram.Slice(offset, 4)), questionName);
                    recorded++;
                    break;

                case 28 when dataLength == 16:
                    Record(new IPAddress(datagram.Slice(offset, 16)), questionName);
                    recorded++;
                    break;
            }

            offset += dataLength;
        }

        return recorded;
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
