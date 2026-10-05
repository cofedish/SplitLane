using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace SplitLane.Engine.Tests.Security;

/// <summary>Raw IPv4/IPv6 packets for driving the packet classifier without a driver.</summary>
internal static class TestPackets
{
    public const byte Syn = 0x02;
    public const byte Ack = 0x10;
    public const byte Fin = 0x01;
    public const byte Rst = 0x04;
    public const byte Psh = 0x08;

    public static byte[] Udp(IPEndPoint source, IPEndPoint destination, ReadOnlySpan<byte> payload = default) =>
        Build(source, destination, udp: true, flags: 0, payload);

    public static byte[] Tcp(IPEndPoint source, IPEndPoint destination, byte flags, ReadOnlySpan<byte> payload = default) =>
        Build(source, destination, udp: false, flags, payload);

    /// <summary>A DNS message in TCP framing: a two-byte length prefix, then the message.</summary>
    public static byte[] TcpDns(ReadOnlySpan<byte> message)
    {
        var framed = new byte[message.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)message.Length);
        message.CopyTo(framed.AsSpan(2));
        return framed;
    }

    private static byte[] Build(IPEndPoint source, IPEndPoint destination, bool udp, byte flags, ReadOnlySpan<byte> payload)
    {
        var ipv6 = source.AddressFamily == AddressFamily.InterNetworkV6;
        var ipSize = ipv6 ? 40 : 20;
        var transportSize = udp ? 8 : 20;
        var packet = new byte[ipSize + transportSize + payload.Length];

        packet[0] = ipv6 ? (byte)0x60 : (byte)0x45;
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(ipv6 ? 4 : 2), (ushort)(ipv6 ? transportSize + payload.Length : packet.Length));
        packet[ipv6 ? 6 : 9] = udp ? (byte)17 : (byte)6;
        packet[ipv6 ? 7 : 8] = 64;
        source.Address.GetAddressBytes().CopyTo(packet, ipv6 ? 8 : 12);
        destination.Address.GetAddressBytes().CopyTo(packet, ipv6 ? 24 : 16);

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipSize), (ushort)source.Port);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipSize + 2), (ushort)destination.Port);

        if (udp)
        {
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipSize + 4), (ushort)(8 + payload.Length));
        }
        else
        {
            packet[ipSize + 12] = 0x50;
            packet[ipSize + 13] = flags;
        }

        payload.CopyTo(packet.AsSpan(ipSize + transportSize));
        return packet;
    }
}

/// <summary>Minimal DNS messages.</summary>
internal static class TestDns
{
    public static byte[] Query(string name, ushort id = 0x1234, ushort type = 1)
    {
        var message = new List<byte>
        {
            (byte)(id >> 8), (byte)id,
            0x01, 0x00,             // standard query, recursion desired
            0x00, 0x01,             // one question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        message.AddRange(EncodeName(name));
        message.AddRange([(byte)(type >> 8), (byte)type, 0x00, 0x01]);
        return [.. message];
    }

    public static byte[] Response(string name, IPAddress answer, ushort id = 0x1234, ushort type = 1, uint ttl = 300)
    {
        var message = new List<byte>
        {
            (byte)(id >> 8), (byte)id,
            0x81, 0x80,             // response, recursion available, no error
            0x00, 0x01,             // one question
            0x00, 0x01,             // one answer
            0x00, 0x00, 0x00, 0x00,
        };

        message.AddRange(EncodeName(name));
        message.AddRange([(byte)(type >> 8), (byte)type, 0x00, 0x01]);

        var data = answer.GetAddressBytes();
        var answerType = data.Length == 4 ? (ushort)1 : (ushort)28;
        message.AddRange([0xC0, 0x0C]);
        message.AddRange([(byte)(answerType >> 8), (byte)answerType, 0x00, 0x01]);
        message.AddRange([(byte)(ttl >> 24), (byte)(ttl >> 16), (byte)(ttl >> 8), (byte)ttl]);
        message.AddRange([(byte)(data.Length >> 8), (byte)data.Length]);
        message.AddRange(data);
        return [.. message];
    }

    public static byte[] EncodeName(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }

        bytes.Add(0);
        return [.. bytes];
    }

    /// <summary>
    /// The query a response answers: the same id and question, with the response bit and the answer
    /// count cleared. Null when the response is too malformed to have one.
    /// </summary>
    public static byte[]? QueryFor(ReadOnlySpan<byte> response)
    {
        if (response.Length < 12)
        {
            return null;
        }

        var offset = 12;
        while (offset < response.Length && response[offset] != 0)
        {
            if ((response[offset] & 0xC0) != 0)
            {
                return null;
            }

            offset += response[offset] + 1;
        }

        offset += 1 + 4;
        if (offset > response.Length)
        {
            return null;
        }

        var query = response[..offset].ToArray();
        query[2] &= 0x7F;
        query[3] &= 0x70;
        query[6] = 0;
        query[7] = 0;
        query[8] = query[9] = query[10] = query[11] = 0;
        return query;
    }
}
