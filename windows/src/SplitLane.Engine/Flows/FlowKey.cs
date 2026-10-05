using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace SplitLane.Engine.Flows;

/// <summary>
/// The local end of a TCP connection: address family, local address and local port.
/// </summary>
/// <remarks>
/// <para>
/// Routing state used to be keyed on the local port alone (SL-SEC-005). A port number is unique per
/// protocol, per address family and per local address - not globally - so any process could open a
/// socket on the same number in the other family, or on another of the machine's addresses, and its
/// CONNECT or CLOSE would overwrite or erase a selected application's decision.
/// </para>
/// <para>
/// The address is held as a 128-bit value rather than an <see cref="IPAddress"/>, so the packet loop
/// can build a key from a packet's bytes without allocating.
/// </para>
/// </remarks>
/// <param name="IPv6">Address family.</param>
/// <param name="Address">The local address, big-endian, IPv4 in the low 32 bits.</param>
/// <param name="Port">The local port.</param>
public readonly record struct FlowKey(bool IPv6, UInt128 Address, ushort Port)
{
    /// <summary>A key from a packet's source address bytes (4 or 16) and source port.</summary>
    public static FlowKey From(ReadOnlySpan<byte> address, ushort port) => address.Length switch
    {
        4 => new FlowKey(false, BinaryPrimitives.ReadUInt32BigEndian(address), port),
        16 => new FlowKey(true, BinaryPrimitives.ReadUInt128BigEndian(address), port),
        _ => throw new ArgumentException("An address is 4 or 16 bytes.", nameof(address)),
    };

    /// <summary>A key from an address and a port.</summary>
    public static FlowKey From(IPAddress address, ushort port)
    {
        ArgumentNullException.ThrowIfNull(address);

        // A dual-stack socket's IPv4 traffic carries IPv4 headers; key it the way its packets look.
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out var written))
        {
            throw new ArgumentException("The address could not be read.", nameof(address));
        }

        return From(bytes[..written], port);
    }

    /// <summary>The family-and-port slot this key occupies, which is all the redirect path can see.</summary>
    public PortSlot Slot => new(IPv6, Port);

    /// <inheritdoc />
    public override string ToString()
    {
        Span<byte> bytes = stackalloc byte[16];
        IPAddress address;

        if (IPv6)
        {
            BinaryPrimitives.WriteUInt128BigEndian(bytes, Address);
            address = new IPAddress(bytes);
            return $"[{address}]:{Port}";
        }

        BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)Address);
        address = new IPAddress(bytes[..4]);
        return $"{address}:{Port}";
    }
}

/// <summary>
/// An address family and a local port.
/// </summary>
/// <remarks>
/// What survives a redirect: the engine rewrites the application's address to loopback, so the redirect
/// listener and the reply path see only the family and the port. At most one redirected connection may
/// hold a slot at a time (<see cref="NatTable.Record"/>).
/// </remarks>
/// <param name="IPv6">Address family.</param>
/// <param name="Port">The local port.</param>
public readonly record struct PortSlot(bool IPv6, ushort Port)
{
    /// <summary>The slot of an accepted connection's remote end.</summary>
    public static PortSlot From(IPEndPoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var address = endpoint.Address.IsIPv4MappedToIPv6 ? endpoint.Address.MapToIPv4() : endpoint.Address;
        return new PortSlot(address.AddressFamily == AddressFamily.InterNetworkV6, (ushort)endpoint.Port);
    }
}
