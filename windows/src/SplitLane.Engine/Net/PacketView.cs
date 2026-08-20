using System.Buffers.Binary;

namespace SplitLane.Engine.Net;

/// <summary>
/// A parsed, editable view over one IP packet.
/// </summary>
/// <remarks>
/// <para>
/// This is the whole of SplitLane's packet handling, and it is deliberately a plain
/// <c>ref struct</c> over a <see cref="Span{T}"/> with no WinDivert types in it. Address rewriting
/// and checksum arithmetic are the two things in the divert path that are easy to get subtly wrong
/// and impossible to debug from a packet capture after the fact, so they live somewhere a unit test
/// can reach them without a driver, without elevation and without a network.
/// </para>
/// <para>
/// Only the shapes SplitLane actually rewrites are parsed: IPv4 and IPv6 carrying TCP or UDP, with
/// no IPv6 extension headers. Anything else fails to parse and is reinjected untouched, which is the
/// correct and safe outcome — an unparsed packet is a packet SplitLane did not interfere with.
/// </para>
/// </remarks>
public readonly ref struct PacketView
{
    private readonly Span<byte> _buffer;

    private PacketView(
        Span<byte> buffer,
        bool isIPv6,
        int transportOffset,
        byte protocol)
    {
        _buffer = buffer;
        IsIPv6 = isIPv6;
        TransportOffset = transportOffset;
        Protocol = protocol;
    }

    /// <summary>IP protocol number for TCP.</summary>
    public const byte ProtocolTcp = 6;

    /// <summary>IP protocol number for UDP.</summary>
    public const byte ProtocolUdp = 17;

    /// <summary>True for IPv6.</summary>
    public bool IsIPv6 { get; }

    /// <summary>True for IPv4.</summary>
    public bool IsIPv4 => !IsIPv6;

    /// <summary>Offset of the transport header within the packet.</summary>
    public int TransportOffset { get; }

    /// <summary>Transport protocol number.</summary>
    public byte Protocol { get; }

    /// <summary>True when the transport is one SplitLane can rewrite ports on.</summary>
    public bool HasPorts => Protocol is ProtocolTcp or ProtocolUdp;

    /// <summary>Length of the IP header.</summary>
    public int IpHeaderLength => IsIPv6 ? 40 : (_buffer[0] & 0x0F) * 4;

    /// <summary>Source address bytes: four for IPv4, sixteen for IPv6.</summary>
    public Span<byte> SourceAddress => IsIPv6 ? _buffer.Slice(8, 16) : _buffer.Slice(12, 4);

    /// <summary>Destination address bytes.</summary>
    public Span<byte> DestinationAddress => IsIPv6 ? _buffer.Slice(24, 16) : _buffer.Slice(16, 4);

    /// <summary>Source port, host byte order.</summary>
    public ushort SourcePort
    {
        get => BinaryPrimitives.ReadUInt16BigEndian(_buffer.Slice(TransportOffset, 2));
        set => BinaryPrimitives.WriteUInt16BigEndian(_buffer.Slice(TransportOffset, 2), value);
    }

    /// <summary>Destination port, host byte order.</summary>
    public ushort DestinationPort
    {
        get => BinaryPrimitives.ReadUInt16BigEndian(_buffer.Slice(TransportOffset + 2, 2));
        set => BinaryPrimitives.WriteUInt16BigEndian(_buffer.Slice(TransportOffset + 2, 2), value);
    }

    /// <summary>True when the TCP SYN flag is set and ACK is not — the first packet of a connection.</summary>
    public bool IsTcpSyn =>
        Protocol == ProtocolTcp &&
        _buffer.Length > TransportOffset + 13 &&
        (_buffer[TransportOffset + 13] & 0x02) != 0 &&
        (_buffer[TransportOffset + 13] & 0x10) == 0;

    /// <summary>True when the TCP RST flag is set.</summary>
    public bool IsTcpReset =>
        Protocol == ProtocolTcp &&
        _buffer.Length > TransportOffset + 13 &&
        (_buffer[TransportOffset + 13] & 0x04) != 0;

    /// <summary>The packet bytes.</summary>
    public Span<byte> Bytes => _buffer;

    /// <summary>
    /// Parses a packet, or fails.
    /// </summary>
    /// <remarks>
    /// Every length is checked against what actually arrived, including the IPv4 header length
    /// nibble, which is attacker-influenced on an inbound packet and would otherwise be an
    /// out-of-range slice.
    /// </remarks>
    public static bool TryParse(Span<byte> packet, out PacketView view)
    {
        view = default;

        if (packet.Length < 20)
        {
            return false;
        }

        var version = packet[0] >> 4;

        switch (version)
        {
            case 4:
                var ihl = (packet[0] & 0x0F) * 4;
                if (ihl < 20 || packet.Length < ihl)
                {
                    return false;
                }

                var v4Protocol = packet[9];
                if (!IsSupportedProtocol(v4Protocol) || packet.Length < ihl + MinimumTransportLength(v4Protocol))
                {
                    return false;
                }

                view = new PacketView(packet, isIPv6: false, ihl, v4Protocol);
                return true;

            case 6:
                if (packet.Length < 40)
                {
                    return false;
                }

                // Extension headers are not walked. A packet carrying one is not rewritten, which
                // means it is passed through untouched rather than mangled.
                var v6Protocol = packet[6];
                if (!IsSupportedProtocol(v6Protocol) || packet.Length < 40 + MinimumTransportLength(v6Protocol))
                {
                    return false;
                }

                view = new PacketView(packet, isIPv6: true, 40, v6Protocol);
                return true;

            default:
                return false;
        }
    }

    private static bool IsSupportedProtocol(byte protocol) => protocol is ProtocolTcp or ProtocolUdp;

    private static int MinimumTransportLength(byte protocol) => protocol == ProtocolTcp ? 20 : 8;

    /// <summary>Overwrites the source address. The new address must match the packet's family.</summary>
    public void SetSourceAddress(ReadOnlySpan<byte> address)
    {
        EnsureAddressWidth(address);
        address.CopyTo(SourceAddress);
    }

    /// <summary>Overwrites the destination address.</summary>
    public void SetDestinationAddress(ReadOnlySpan<byte> address)
    {
        EnsureAddressWidth(address);
        address.CopyTo(DestinationAddress);
    }

    private void EnsureAddressWidth(ReadOnlySpan<byte> address)
    {
        var expected = IsIPv6 ? 16 : 4;
        if (address.Length != expected)
        {
            throw new ArgumentException(
                $"Address must be {expected} bytes for this packet family", nameof(address));
        }
    }

    /// <summary>
    /// Recomputes the IP and transport checksums over the current contents.
    /// </summary>
    /// <remarks>
    /// <para>
    /// WinDivert offers <c>WinDivertHelperCalcChecksums</c>, and the engine could call it. It does
    /// not, for one reason: this implementation runs in a unit test. Reinjecting a packet with a
    /// wrong checksum produces a connection that hangs rather than an error, which is the single
    /// most expensive class of bug to diagnose in a packet path, so the arithmetic is kept somewhere
    /// it can be proven against known-good vectors.
    /// </para>
    /// <para>
    /// A UDP checksum of zero is legal in IPv4 and means "not computed". It is recomputed anyway
    /// rather than preserved, because SplitLane has just changed the addresses the pseudo-header is
    /// built from; leaving a stale zero would be correct only by accident. In IPv6 a zero checksum is
    /// illegal, and the all-ones representation is used as RFC 768 requires.
    /// </para>
    /// </remarks>
    public void RecomputeChecksums()
    {
        if (IsIPv4)
        {
            var header = _buffer[..IpHeaderLength];
            header[10] = 0;
            header[11] = 0;
            var checksum = OnesComplementSum(header, 0);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(10, 2), Fold(checksum));
        }

        var transport = _buffer[TransportOffset..];
        var checksumOffset = Protocol == ProtocolTcp ? 16 : 6;
        if (transport.Length < checksumOffset + 2)
        {
            return;
        }

        transport[checksumOffset] = 0;
        transport[checksumOffset + 1] = 0;

        var sum = PseudoHeaderSum(transport.Length);
        sum = OnesComplementSum(transport, sum);
        var folded = Fold(sum);

        // RFC 768: a computed UDP checksum of zero is transmitted as all ones, because zero means
        // "no checksum".
        if (Protocol == ProtocolUdp && folded == 0)
        {
            folded = 0xFFFF;
        }

        BinaryPrimitives.WriteUInt16BigEndian(transport.Slice(checksumOffset, 2), folded);
    }

    /// <summary>
    /// The pseudo-header contribution: the addresses, the protocol number and the transport length.
    /// </summary>
    /// <remarks>
    /// IPv4 (RFC 793) and IPv6 (RFC 8200 §8.1) lay the pseudo-header out differently — a 16-bit
    /// length and a zero pad in one, a 32-bit length and three zero pads in the other — but one's
    /// complement addition is commutative and the zero pads contribute nothing, so summing the
    /// addresses, the protocol and the length gives the same value for both. The addresses are
    /// always an even number of bytes, so they sum as whole 16-bit words with no tail.
    /// </remarks>
    private uint PseudoHeaderSum(int transportLength)
    {
        var sum = OnesComplementSum(SourceAddress, 0);
        sum = OnesComplementSum(DestinationAddress, sum);
        sum += Protocol;
        sum += (uint)((transportLength >> 16) & 0xFFFF);
        sum += (uint)(transportLength & 0xFFFF);
        return sum;
    }

    /// <summary>One's complement sum of a span, continuing from a running value.</summary>
    internal static uint OnesComplementSum(ReadOnlySpan<byte> data, uint seed)
    {
        var sum = seed;
        var index = 0;

        for (; index + 1 < data.Length; index += 2)
        {
            sum += (uint)((data[index] << 8) | data[index + 1]);
        }

        if (index < data.Length)
        {
            sum += (uint)(data[index] << 8);
        }

        return sum;
    }

    /// <summary>Folds carries into 16 bits and complements.</summary>
    internal static ushort Fold(uint sum)
    {
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }
}
