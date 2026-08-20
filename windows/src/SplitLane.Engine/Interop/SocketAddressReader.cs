using System.Net;

namespace SplitLane.Engine.Interop;

/// <summary>
/// Turns the address words in a socket-layer event into <see cref="IPAddress"/> values.
/// </summary>
/// <remarks>
/// <para>
/// IPv4 is unpacked directly: the address sits in word 0 in host byte order, which is the same form
/// <c>WinDivertHelperFormatIPv4Address</c> takes, so there is nothing to guess.
/// </para>
/// <para>
/// IPv6 is <b>not</b> unpacked by hand. WinDivert stores the four words in an order that is an
/// implementation detail of the library, and reimplementing it from memory is precisely the sort of
/// mistake that yields a routing bug visible only on IPv6 and only on some networks. The library's
/// own formatter is authoritative, costs one call per connection rather than per packet, and cannot
/// drift from the struct it is reading.
/// </para>
/// </remarks>
public static class SocketAddressReader
{
    /// <summary>Reads the remote address of a socket-layer event.</summary>
    public static IPAddress ReadRemote(in WinDivertAddress address)
        => Read(address.IPv6,
            address.Socket.RemoteAddr0,
            address.Socket.RemoteAddr1,
            address.Socket.RemoteAddr2,
            address.Socket.RemoteAddr3);

    /// <summary>Reads the local address of a socket-layer event.</summary>
    public static IPAddress ReadLocal(in WinDivertAddress address)
        => Read(address.IPv6,
            address.Socket.LocalAddr0,
            address.Socket.LocalAddr1,
            address.Socket.LocalAddr2,
            address.Socket.LocalAddr3);

    private static unsafe IPAddress Read(bool isIPv6, uint word0, uint word1, uint word2, uint word3)
    {
        if (!isIPv6)
        {
            return FromHostOrderIPv4(word0);
        }

        var words = stackalloc uint[4] { word0, word1, word2, word3 };
        var buffer = stackalloc byte[64];

        if (WinDivertNative.FormatIPv6Address(words, buffer, 64))
        {
            var text = new string((sbyte*)buffer);
            if (IPAddress.TryParse(text, out var parsed))
            {
                return parsed;
            }
        }

        // A formatter failure should be impossible, but an unresolvable address must not throw on
        // the hot path. IPv6Any never matches a rule and never looks local, so it routes DIRECT.
        return IPAddress.IPv6Any;
    }

    /// <summary>Builds an IPv4 address from a host-byte-order word.</summary>
    public static IPAddress FromHostOrderIPv4(uint value) => new(new[]
    {
        (byte)((value >> 24) & 0xFF),
        (byte)((value >> 16) & 0xFF),
        (byte)((value >> 8) & 0xFF),
        (byte)(value & 0xFF),
    });
}
