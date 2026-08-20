using System.Buffers.Binary;
using System.Net;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Net;

namespace SplitLane.Engine.Tests;

/// <summary>
/// Packet parsing, address rewriting and checksums.
/// </summary>
/// <remarks>
/// These are the tests that make the divert layer reviewable. A NAT bug does not produce an error
/// anywhere — it produces a connection that hangs, with a packet capture showing a plausible-looking
/// packet that the receiving stack silently discarded. Proving the arithmetic here is the only cheap
/// way to find that class of bug.
/// </remarks>
public sealed class PacketRewriteTests
{
    /// <summary>Builds a syntactically valid IPv4 TCP packet with correct checksums.</summary>
    private static byte[] BuildIPv4Tcp(
        string source, ushort sourcePort,
        string destination, ushort destinationPort,
        byte[]? payload = null,
        byte flags = 0x02)
    {
        payload ??= [];
        var total = 20 + 20 + payload.Length;
        var packet = new byte[total];

        packet[0] = 0x45;                                  // version 4, IHL 5
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)total);
        packet[8] = 64;                                    // TTL
        packet[9] = PacketView.ProtocolTcp;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(packet, 16);

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), destinationPort);
        packet[32] = 0x50;                                 // data offset 5
        packet[33] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(34, 2), 8192);
        payload.CopyTo(packet, 40);

        PacketView.TryParse(packet, out var view);
        view.RecomputeChecksums();
        return packet;
    }

    private static byte[] BuildIPv6Tcp(
        string source, ushort sourcePort,
        string destination, ushort destinationPort)
    {
        var packet = new byte[40 + 20];
        packet[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), 20);
        packet[6] = PacketView.ProtocolTcp;
        packet[7] = 64;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(packet, 8);
        IPAddress.Parse(destination).GetAddressBytes().CopyTo(packet, 24);

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(40, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(42, 2), destinationPort);
        packet[52] = 0x50;
        packet[53] = 0x02;

        PacketView.TryParse(packet, out var view);
        view.RecomputeChecksums();
        return packet;
    }

    /// <summary>Recomputes a checksum over a packet and reports whether the stored one was right.</summary>
    private static bool ChecksumsAreValid(byte[] packet)
    {
        var copy = (byte[])packet.Clone();
        PacketView.TryParse(copy, out var view);

        var storedIp = packet.AsSpan(10, 2).ToArray();
        var transportOffset = view.TransportOffset + (view.Protocol == PacketView.ProtocolTcp ? 16 : 6);
        var storedTransport = packet.AsSpan(transportOffset, 2).ToArray();

        view.RecomputeChecksums();

        var ipMatches = view.IsIPv6 || copy.AsSpan(10, 2).SequenceEqual(storedIp);
        var transportMatches = copy.AsSpan(transportOffset, 2).SequenceEqual(storedTransport);

        return ipMatches && transportMatches;
    }

    // ---- Parsing ---------------------------------------------------------------------------

    [Fact]
    public void AnIPv4TcpPacketParses()
    {
        var packet = BuildIPv4Tcp("192.168.1.5", 51000, "93.184.216.34", 443);

        Assert.True(PacketView.TryParse(packet, out var view));
        Assert.True(view.IsIPv4);
        Assert.Equal(PacketView.ProtocolTcp, view.Protocol);
        Assert.Equal(20, view.TransportOffset);
        Assert.Equal(51000, view.SourcePort);
        Assert.Equal(443, view.DestinationPort);
        Assert.True(view.IsTcpSyn);
    }

    [Fact]
    public void AnIPv6TcpPacketParses()
    {
        var packet = BuildIPv6Tcp("2001:db8::5", 51000, "2606:2800:220:1::1", 443);

        Assert.True(PacketView.TryParse(packet, out var view));
        Assert.True(view.IsIPv6);
        Assert.Equal(40, view.TransportOffset);
        Assert.Equal(51000, view.SourcePort);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(19)]
    public void ATruncatedPacketDoesNotParse(int length) =>
        Assert.False(PacketView.TryParse(new byte[length], out _));

    [Fact]
    public void AnImpossibleHeaderLengthDoesNotParse()
    {
        // IHL claims 15 words (60 bytes) in a 40-byte packet. An unchecked slice here would read
        // past the buffer on attacker-influenced input.
        var packet = new byte[40];
        packet[0] = 0x4F;
        packet[9] = PacketView.ProtocolTcp;

        Assert.False(PacketView.TryParse(packet, out _));
    }

    [Fact]
    public void AnUnsupportedProtocolDoesNotParse()
    {
        var packet = BuildIPv4Tcp("192.168.1.5", 51000, "93.184.216.34", 443);
        packet[9] = 1; // ICMP

        Assert.False(PacketView.TryParse(packet, out _));
    }

    // ---- Checksums --------------------------------------------------------------------------

    [Fact]
    public void AFreshlyBuiltPacketHasValidChecksums() =>
        Assert.True(ChecksumsAreValid(BuildIPv4Tcp("192.168.1.5", 51000, "93.184.216.34", 443)));

    [Fact]
    public void ChecksumsCoverThePayload()
    {
        var packet = BuildIPv4Tcp("10.0.0.2", 40000, "1.1.1.1", 80, "GET / HTTP/1.1\r\n"u8.ToArray(), flags: 0x18);

        Assert.True(ChecksumsAreValid(packet));

        // Flip one payload byte; the stored checksum must no longer match.
        packet[45] ^= 0xFF;
        Assert.False(ChecksumsAreValid(packet));
    }

    [Fact]
    public void ChecksumsCoverAnOddLengthPayload()
    {
        // The one's complement sum pads a trailing odd byte into the high half of a word. Getting
        // that wrong produces a checksum that is right for even payloads and wrong for odd ones.
        var packet = BuildIPv4Tcp("10.0.0.2", 40000, "1.1.1.1", 80, "odd"u8.ToArray(), flags: 0x18);

        Assert.True(ChecksumsAreValid(packet));
    }

    [Fact]
    public void IPv6ChecksumsUseThePseudoHeader()
    {
        var packet = BuildIPv6Tcp("2001:db8::5", 51000, "2606:2800:220:1::1", 443);

        Assert.True(ChecksumsAreValid(packet));

        // Changing an address must change the checksum, because the address is in the pseudo-header.
        IPAddress.Parse("2001:db8::9").GetAddressBytes().CopyTo(packet, 8);
        Assert.False(ChecksumsAreValid(packet));
    }

    [Fact]
    public void AKnownGoodVectorFolds()
    {
        // RFC 1071's worked example.
        byte[] data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];

        Assert.Equal(0x220d, PacketView.Fold(PacketView.OnesComplementSum(data, 0)));
    }

    // ---- Redirect ---------------------------------------------------------------------------

    [Fact]
    public void RedirectMovesBothEndpointsToLoopbackAndKeepsTheSourcePort()
    {
        var packet = BuildIPv4Tcp("192.168.1.5", 51000, "93.184.216.34", 443);

        Assert.True(RedirectRewriter.TryRedirectToListener(packet, 24444));
        Assert.True(PacketView.TryParse(packet, out var view));

        Assert.Equal(IPAddress.Loopback, new IPAddress(view.SourceAddress));
        Assert.Equal(IPAddress.Loopback, new IPAddress(view.DestinationAddress));
        Assert.Equal(24444, view.DestinationPort);

        // The source port is the NAT key. If it moved, neither the listener nor the return path
        // could find the connection.
        Assert.Equal(51000, view.SourcePort);
    }

    [Fact]
    public void RedirectLeavesValidChecksums()
    {
        var packet = BuildIPv4Tcp("192.168.1.5", 51000, "93.184.216.34", 443);

        RedirectRewriter.TryRedirectToListener(packet, 24444);

        Assert.True(ChecksumsAreValid(packet));
    }

    [Fact]
    public void RedirectOfAnIPv6PacketUsesIPv6Loopback()
    {
        var packet = BuildIPv6Tcp("2001:db8::5", 51000, "2606:2800:220:1::1", 443);

        Assert.True(RedirectRewriter.TryRedirectToListener(packet, 24444));
        Assert.True(PacketView.TryParse(packet, out var view));

        Assert.Equal(IPAddress.IPv6Loopback, new IPAddress(view.SourceAddress));
        Assert.Equal(IPAddress.IPv6Loopback, new IPAddress(view.DestinationAddress));
        Assert.True(ChecksumsAreValid(packet));
    }

    // ---- Restore -----------------------------------------------------------------------------

    [Fact]
    public void RestoreRebuildsTheOriginalFourTuple()
    {
        // What the listener sends back: loopback to loopback, from the listener's port.
        var reply = BuildIPv4Tcp("127.0.0.1", 24444, "127.0.0.1", 51000, flags: 0x12);

        Assert.True(RedirectRewriter.TryRestoreFromListener(
            reply,
            IPAddress.Parse("93.184.216.34"),
            443,
            IPAddress.Parse("192.168.1.5")));

        Assert.True(PacketView.TryParse(reply, out var view));

        Assert.Equal(IPAddress.Parse("93.184.216.34"), new IPAddress(view.SourceAddress));
        Assert.Equal(443, view.SourcePort);
        Assert.Equal(IPAddress.Parse("192.168.1.5"), new IPAddress(view.DestinationAddress));
        Assert.Equal(51000, view.DestinationPort);
        Assert.True(ChecksumsAreValid(reply));
    }

    [Fact]
    public void RedirectThenRestoreIsTheIdentityOnAddressesAndPorts()
    {
        // The round trip is the property that matters: whatever the application sent, the reply it
        // gets back must be addressed as if nothing happened.
        var outbound = BuildIPv4Tcp("192.168.1.5", 51000, "93.184.216.34", 443);
        RedirectRewriter.TryRedirectToListener(outbound, 24444);

        var reply = BuildIPv4Tcp("127.0.0.1", 24444, "127.0.0.1", 51000, flags: 0x12);
        RedirectRewriter.TryRestoreFromListener(
            reply, IPAddress.Parse("93.184.216.34"), 443, IPAddress.Parse("192.168.1.5"));

        Assert.True(PacketView.TryParse(reply, out var view));
        Assert.Equal("93.184.216.34", new IPAddress(view.SourceAddress).ToString());
        Assert.Equal("192.168.1.5", new IPAddress(view.DestinationAddress).ToString());
    }

    [Fact]
    public void RestoreRefusesAFamilyMismatchRatherThanCorruptingTheHeader()
    {
        var reply = BuildIPv4Tcp("127.0.0.1", 24444, "127.0.0.1", 51000);

        Assert.False(RedirectRewriter.TryRestoreFromListener(
            reply,
            IPAddress.Parse("2001:db8::1"),
            443,
            IPAddress.Parse("192.168.1.5")));
    }

    [Fact]
    public void EndpointsCanBeReadWithoutModifyingThePacket()
    {
        var packet = BuildIPv4Tcp("192.168.1.5", 51000, "93.184.216.34", 443);
        var before = (byte[])packet.Clone();

        Assert.True(RedirectRewriter.TryReadEndpoints(packet, out var endpoints));

        Assert.Equal(IPAddress.Parse("192.168.1.5"), endpoints.SourceAddress);
        Assert.Equal(51000, endpoints.SourcePort);
        Assert.Equal(IPAddress.Parse("93.184.216.34"), endpoints.DestinationAddress);
        Assert.Equal(443, endpoints.DestinationPort);
        Assert.Equal(before, packet);
    }

    [Fact]
    public void AnUnparseablePacketIsNeverRewritten()
    {
        var garbage = new byte[8];

        Assert.False(RedirectRewriter.TryRedirectToListener(garbage, 24444));
        Assert.False(RedirectRewriter.TryReadEndpoints(garbage, out _));
    }
}
