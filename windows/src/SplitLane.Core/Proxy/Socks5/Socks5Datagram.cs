using System.Buffers.Binary;

namespace SplitLane.Core.Proxy.Socks5;

/// <summary>
/// The header SOCKS5 wraps around every relayed datagram, and the reading of it.
/// </summary>
/// <remarks>
/// <para>
/// A UDP association does not carry a destination the way a TCP connection does. The association is
/// opened once and then every datagram says for itself where it is going, in ten or more bytes in
/// front of the payload: two reserved, one fragment number, then an address and a port in the same
/// encoding the rest of SOCKS5 uses. Replies come back with the same header, naming where they came
/// from, which is the only way to know who a datagram is an answer to.
/// </para>
/// <para>
/// Fragmentation is refused rather than reassembled. RFC 1928 allows a datagram to be split across
/// several with a fragment number, and no proxy in practice sends them - accepting a fragment would
/// mean holding partial datagrams from the network in memory, keyed on a field nothing verifies, on
/// the strength of a feature nobody uses.
/// </para>
/// <para>
/// Pure and separate from any socket, because a header that is off by one byte produces a datagram
/// the proxy silently discards, and there is nothing at either end that would say so.
/// </para>
/// </remarks>
public static class Socks5Datagram
{
    /// <summary>Bytes before the address: two reserved and one fragment.</summary>
    public const int PrefixLength = 3;

    /// <summary>Header length for an IPv4 destination.</summary>
    public const int IPv4HeaderLength = PrefixLength + 1 + 4 + 2;

    /// <summary>Wraps a payload for a destination, returning the datagram to send to the relay.</summary>
    public static byte[] Encode(Socks5Address destination, ushort port, ReadOnlySpan<byte> payload)
    {
        var address = destination.Encode();
        var datagram = new byte[PrefixLength + address.Length + 2 + payload.Length];

        // RSV RSV FRAG are all zero: no reserved meaning, and not a fragment.
        address.CopyTo(datagram.AsSpan(PrefixLength));

        BinaryPrimitives.WriteUInt16BigEndian(
            datagram.AsSpan(PrefixLength + address.Length, 2), port);

        payload.CopyTo(datagram.AsSpan(PrefixLength + address.Length + 2));
        return datagram;
    }

    /// <summary>
    /// Reads a datagram that came back from the relay.
    /// </summary>
    /// <param name="datagram">Everything the socket received.</param>
    /// <param name="sourceOctets">Where the reply came from, as address bytes.</param>
    /// <param name="sourcePort">The port it came from.</param>
    /// <param name="payloadOffset">Where the payload starts within <paramref name="datagram"/>.</param>
    /// <returns>False for anything malformed, fragmented, or of a kind this cannot map back.</returns>
    public static bool TryDecode(
        ReadOnlySpan<byte> datagram,
        out ReadOnlySpan<byte> sourceOctets,
        out ushort sourcePort,
        out int payloadOffset)
    {
        sourceOctets = default;
        sourcePort = 0;
        payloadOffset = 0;

        if (datagram.Length < PrefixLength + 1)
        {
            return false;
        }

        // A fragment. See the remarks: refused, not reassembled.
        if (datagram[2] != 0)
        {
            return false;
        }

        var type = (Socks5AddressType)datagram[PrefixLength];
        var addressLength = type switch
        {
            Socks5AddressType.IPv4 => 4,
            Socks5AddressType.IPv6 => 16,

            // A domain name in a reply would name a host this cannot turn back into the address the
            // application sent to, so there would be nothing to inject the answer as.
            _ => 0,
        };

        if (addressLength == 0)
        {
            return false;
        }

        var addressStart = PrefixLength + 1;
        var portStart = addressStart + addressLength;
        var end = portStart + 2;

        if (datagram.Length < end)
        {
            return false;
        }

        sourceOctets = datagram.Slice(addressStart, addressLength);
        sourcePort = BinaryPrimitives.ReadUInt16BigEndian(datagram.Slice(portStart, 2));
        payloadOffset = end;
        return true;
    }
}
