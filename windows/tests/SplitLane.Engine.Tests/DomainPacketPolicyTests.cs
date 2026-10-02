using System.Buffers.Binary;
using System.Net;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests;

public sealed class DomainPacketPolicyTests
{
    [Theory]
    [InlineData(RouteAction.Direct, false)]
    [InlineData(RouteAction.Block, false)]
    [InlineData(RouteAction.ProxyOnly, false)]
    [InlineData(RouteAction.Direct, true)]
    [InlineData(RouteAction.Block, true)]
    [InlineData(RouteAction.ProxyOnly, true)]
    public async Task TcpDomainPolicyControlsActualPacketDisposition(RouteAction action, bool ipv6)
    {
        var remote = IPAddress.Parse(ipv6 ? "2001:db8::10" : "203.0.113.10");
        var source = IPAddress.Parse(ipv6 ? "2001:db8::20" : "192.0.2.20");
        var engine = Engine(action);
        var nat = new NatTable();
        await using var pipeline = new DivertPipeline(nat, new DnsObserver(), new ProcessResolver(), new EngineStatistics(), () => engine);
        var flow = new FlowDescriptor(42, @"C:\Tests\client.exe", remote.ToString(), 443, FlowProtocol.Tcp, "api.example.com");
        pipeline.RecordTcpDecision(45000, source, remote, flow, engine.Decide(flow), null, engine);
        var packet = Packet(source, remote, false);
        var original = packet.ToArray();
        var address = new WinDivertAddress { Outbound = true, IPv6 = ipv6 };

        var expected = action switch
        {
            RouteAction.Direct => DivertPipeline.PacketAction.Forward,
            RouteAction.Block => DivertPipeline.PacketAction.Drop,
            _ => DivertPipeline.PacketAction.Rewritten,
        };
        Assert.Equal(expected, pipeline.Classify(packet, ref address));
        if (expected == DivertPipeline.PacketAction.Forward)
        {
            Assert.Equal(original, packet);
        }
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(true, false)]
    public async Task UnattributedUdpHoldsProtectedDestinationButPreservesUnrelatedTraffic(bool ipv6, bool protectedDestination)
    {
        var remote = IPAddress.Parse(ipv6 ? "2001:db8::10" : "203.0.113.10");
        var source = IPAddress.Parse(ipv6 ? "2001:db8::20" : "192.0.2.20");
        var dns = new DnsObserver();
        dns.Record(remote, protectedDestination ? "api.example.com" : "unrelated.test");
        var engine = Engine(RouteAction.ProxyOnly);
        await using var pipeline = new DivertPipeline(new NatTable(), dns, new ProcessResolver(), new EngineStatistics(), () => engine);
        var packet = Packet(source, remote, true);
        var address = new WinDivertAddress { Outbound = true, IPv6 = ipv6 };

        Assert.Equal(protectedDestination ? DivertPipeline.PacketAction.Drop : DivertPipeline.PacketAction.Forward,
            pipeline.Classify(packet, ref address));
    }

    [Fact]
    public async Task StrictLateDecisionDropsEstablishedPacketsInsteadOfLeaking()
    {
        var remote = IPAddress.Parse("203.0.113.10");
        var source = IPAddress.Parse("192.0.2.20");
        var engine = Engine(RouteAction.ProxyOnly);
        var nat = new NatTable();
        await using var pipeline = new DivertPipeline(nat, new DnsObserver(), new ProcessResolver(), new EngineStatistics(), () => engine);
        var flow = new FlowDescriptor(42, @"C:\Tests\client.exe", remote.ToString(), 443, FlowProtocol.Tcp, "api.example.com");
        pipeline.RecordTcpDecision(45000, source, remote, flow, engine.Decide(flow), null, engine);
        var packet = Packet(source, remote, false);
        packet[33] = 0x10; // ACK without a previously redirected SYN.
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(packet, ref address));
    }

    private static RuleEngine Engine(RouteAction action) => new(new RuntimeConfiguration
    {
        DomainRules = [new DomainRule { Pattern = "*.example.com", Action = action }],
    });

    [Fact]
    public async Task LostAttributionDoesNotForwardFinalPacketsOfKnownStrictDomain()
    {
        var remote = IPAddress.Parse("203.0.113.10");
        var dns = new DnsObserver();
        dns.Record(remote, "api.example.com");
        var engine = Engine(RouteAction.ProxyOnly);
        await using var pipeline = new DivertPipeline(new NatTable(), dns, new ProcessResolver(), new EngineStatistics(), () => engine);
        var packet = Packet(IPAddress.Parse("192.0.2.20"), remote, false);
        packet[33] = 0x11;
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(packet, ref address));
    }

    [Fact]
    public async Task StrictSocketCloseStillDropsFinalFinAck()
    {
        var remote = IPAddress.Parse("203.0.113.10");
        var source = IPAddress.Parse("192.0.2.20");
        var engine = Engine(RouteAction.ProxyOnly);
        var nat = new NatTable();
        await using var pipeline = new DivertPipeline(nat, new DnsObserver(), new ProcessResolver(), new EngineStatistics(), () => engine);
        var flow = new FlowDescriptor(42, @"C:\Tests\client.exe", remote.ToString(), 443, FlowProtocol.Tcp, "api.example.com");
        pipeline.RecordTcpDecision(45000, source, remote, flow, engine.Decide(flow), null, engine);
        nat.Close(45000);
        var packet = Packet(source, remote, false);
        packet[33] = 0x11;
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(packet, ref address));
        nat.RecordDirect(45000, remote, 443);
        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(packet, ref address));
    }

    private static byte[] Packet(IPAddress source, IPAddress destination, bool udp)
    {
        var ipv6 = source.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        var ipSize = ipv6 ? 40 : 20;
        var transportSize = udp ? 8 : 20;
        var packet = new byte[ipSize + transportSize];
        packet[0] = ipv6 ? (byte)0x60 : (byte)0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipv6 ? 4 : 2), (ushort)(ipv6 ? transportSize : packet.Length));
        packet[ipv6 ? 6 : 9] = udp ? (byte)17 : (byte)6;
        packet[ipv6 ? 7 : 8] = 64;
        source.GetAddressBytes().CopyTo(packet, ipv6 ? 8 : 12);
        destination.GetAddressBytes().CopyTo(packet, ipv6 ? 24 : 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipSize), 45000);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipSize + 2), 443);
        if (udp)
        {
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipSize + 4), 8);
        }
        else
        {
            packet[ipSize + 12] = 0x50;
            packet[ipSize + 13] = 0x02;
        }

        return packet;
    }
}
