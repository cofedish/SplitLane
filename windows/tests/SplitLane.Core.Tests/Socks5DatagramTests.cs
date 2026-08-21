using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Core.Tests;

/// <summary>The header wrapped around every relayed datagram.</summary>
public sealed class Socks5DatagramTests
{
    private static readonly byte[] Payload = [0xDE, 0xAD, 0xBE, 0xEF];

    [Fact]
    public void AnIPv4DestinationIsEncodedAsTheProtocolDescribesIt()
    {
        var datagram = Socks5Datagram.Encode(
            Socks5Address.FromIPv4([8, 8, 8, 8]), 53, Payload);

        Assert.Equal(Socks5Datagram.IPv4HeaderLength + Payload.Length, datagram.Length);

        // RSV RSV FRAG, then the address type.
        Assert.Equal(0, datagram[0]);
        Assert.Equal(0, datagram[1]);
        Assert.Equal(0, datagram[2]);
        Assert.Equal((byte)Socks5AddressType.IPv4, datagram[3]);
        Assert.Equal(new byte[] { 8, 8, 8, 8 }, datagram[4..8]);

        // Port, big endian, and then the payload untouched.
        Assert.Equal(0, datagram[8]);
        Assert.Equal(53, datagram[9]);
        Assert.Equal(Payload, datagram[10..]);
    }

    [Fact]
    public void WhatIsEncodedCanBeReadBack()
    {
        var datagram = Socks5Datagram.Encode(
            Socks5Address.FromIPv4([203, 0, 113, 7]), 19302, Payload);

        Assert.True(Socks5Datagram.TryDecode(datagram, out var source, out var port, out var offset));
        Assert.Equal(new byte[] { 203, 0, 113, 7 }, source.ToArray());
        Assert.Equal(19302, port);
        Assert.Equal(Payload, datagram[offset..]);
    }

    [Fact]
    public void AnIPv6ReplyIsRead()
    {
        byte[] datagram =
        [
            0, 0, 0, (byte)Socks5AddressType.IPv6,
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0x12, 0x34,
            9, 9,
        ];

        Assert.True(Socks5Datagram.TryDecode(datagram, out var source, out var port, out var offset));
        Assert.Equal(16, source.Length);
        Assert.Equal(0x1234, port);
        Assert.Equal(new byte[] { 9, 9 }, datagram[offset..]);
    }

    [Fact]
    public void AFragmentIsRefused()
    {
        // RFC 1928 allows it; no proxy sends it. Accepting one would mean holding partial datagrams
        // from the network, keyed on a field nothing verifies.
        byte[] datagram = [0, 0, 1, (byte)Socks5AddressType.IPv4, 8, 8, 8, 8, 0, 53, 1];

        Assert.False(Socks5Datagram.TryDecode(datagram, out _, out _, out _));
    }

    [Fact]
    public void ADomainNameInAReplyIsRefused()
    {
        // There would be nothing to inject the answer as: the application sent to an address, and a
        // name cannot be turned back into the one it used.
        byte[] datagram = [0, 0, 0, (byte)Socks5AddressType.Domain, 3, (byte)'a', (byte)'b', (byte)'c', 0, 53];

        Assert.False(Socks5Datagram.TryDecode(datagram, out _, out _, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(9)]
    public void ATruncatedHeaderIsRefused(int length)
    {
        byte[] full = [0, 0, 0, (byte)Socks5AddressType.IPv4, 8, 8, 8, 8, 0, 53, 0xFF];

        Assert.False(Socks5Datagram.TryDecode(full.AsSpan(0, length), out _, out _, out _));
    }

    [Fact]
    public void AnEmptyPayloadIsStillADatagram()
    {
        // Keep-alives and hole-punching probes are frequently empty, and voice will not connect
        // without them.
        var datagram = Socks5Datagram.Encode(Socks5Address.FromIPv4([1, 1, 1, 1]), 443, []);

        Assert.True(Socks5Datagram.TryDecode(datagram, out _, out var port, out var offset));
        Assert.Equal(443, port);
        Assert.Equal(datagram.Length, offset);
    }

    [Fact]
    public void TheHandshakeCanAskForAnAssociationRatherThanATunnel()
    {
        // Same state machine, same authentication, one different byte. Writing a second handshake
        // for UDP would mean two places that have to agree about how a proxy is greeted.
        var negotiator = new Socks5Negotiator(
            Socks5Address.FromIPv4([0, 0, 0, 0]), 0, credential: null, Socks5Command.UdpAssociate);

        var greeting = negotiator.Start();
        Assert.Equal(Socks5StepKind.Send, greeting.Kind);

        // The proxy chooses "no authentication", and the request follows.
        var next = negotiator.Receive([Socks5.Version, (byte)Socks5Method.NoAuthentication]);

        Assert.Equal(Socks5StepKind.Send, next.Kind);
        Assert.Equal(Socks5.Version, next.Bytes![0]);
        Assert.Equal((byte)Socks5Command.UdpAssociate, next.Bytes[1]);
    }

    [Fact]
    public void ConnectIsStillWhatIsAskedForByDefault()
    {
        var negotiator = new Socks5Negotiator(Socks5Address.FromIPv4([1, 1, 1, 1]), 443);
        negotiator.Start();

        var next = negotiator.Receive([Socks5.Version, (byte)Socks5Method.NoAuthentication]);

        Assert.Equal((byte)Socks5Command.Connect, next.Bytes![1]);
    }
}
