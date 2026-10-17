using System.Net;
using System.Net.Sockets;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

public sealed class DhcpBootstrapTests
{
    internal static readonly (string Source, int SourcePort, string Destination, int DestinationPort)[] Exchanges =
    [
        ("0.0.0.0", 68, "255.255.255.255", 67), // DISCOVER/REQUEST before an address exists
        ("192.168.1.20", 68, "255.255.255.255", 67), // rebind
        ("192.168.1.20", 68, "192.168.1.1", 67), // unicast renew/release
        ("192.168.1.1", 67, "255.255.255.255", 68),
        ("192.168.1.1", 67, "192.168.1.20", 68),
        ("fe80::20", 546, "ff02::1:2", 547), // DHCPv6 solicit/rebind
        ("fe80::20", 546, "fe80::1", 547), // unicast renew
        ("fe80::1", 547, "fe80::20", 546),
        ("2001:db8::20", 546, "2001:db8::1", 547),
    ];

    public static IEnumerable<object[]> Cases()
    {
        foreach (var (source, sourcePort, destination, destinationPort) in Exchanges)
        foreach (var action in new[] { RouteAction.Block, RouteAction.Proxy, RouteAction.ProxyOnly })
        foreach (var knownOwner in new[] { false, true })
            yield return [source, sourcePort, destination, destinationPort, action, knownOwner];
    }

    private static RuleEngine Protecting() => new(new RuntimeConfiguration
    {
        Rules = [new AppRule
        {
            Identity = new AppIdentity { ExecutablePath = @"C:\Apps\selected.exe", DisplayName = "selected" },
            MatchMode = MatchMode.Exact,
            Action = RouteAction.Block,
        }],
    });

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task AddressConfigurationNeverWaitsForAnOwnerOrEntersAProxy(
        string source, int sourcePort, string destination, int destinationPort, RouteAction action, bool knownOwner)
    {
        var ownerLookups = 0;
        var engine = Protecting();
        await using var pipeline = new DivertPipeline(new NatTable(), new DnsObserver(), new ProcessResolver(),
            new EngineStatistics(), () => engine)
        {
            UdpOwnerLookup = (_, _) => { ownerLookups++; return null; },
        };
        var local = new IPEndPoint(IPAddress.Parse(source), sourcePort);
        var remote = new IPEndPoint(IPAddress.Parse(destination), destinationPort);
        var ipv6 = local.AddressFamily == AddressFamily.InterNetworkV6;
        if (knownOwner)
            pipeline.RecordUdpDecision(new PortSlot(ipv6, (ushort)sourcePort), 1, false,
                new FlowDescriptor(7, @"C:\Apps\selected.exe", destination, (ushort)destinationPort, FlowProtocol.Udp),
                action, pending: null);
        var packet = TestPackets.Udp(local, remote, new byte[300]);
        var original = packet.ToArray();
        var address = new WinDivertAddress { Outbound = true, IPv6 = ipv6 };
        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(packet, ref address));
        Assert.Equal(original, packet);
        Assert.Equal(0, ownerLookups);
    }

    [Theory]
    [InlineData(false, 68, 443)]
    [InlineData(false, 40000, 67)]
    [InlineData(false, 67, 67)]
    [InlineData(false, 68, 68)]
    [InlineData(false, 546, 547)] // v6 ports must not bypass IPv4 policy
    [InlineData(true, 546, 443)]
    [InlineData(true, 40000, 547)]
    [InlineData(true, 547, 547)]
    [InlineData(true, 68, 67)] // v4 ports must not bypass IPv6 policy
    public async Task OtherDatagramsRemainBlocked(bool ipv6, int sourcePort, int destinationPort)
    {
        var engine = Protecting();
        await using var pipeline = new DivertPipeline(new NatTable(), new DnsObserver(), new ProcessResolver(),
            new EngineStatistics(), () => engine) { UdpOwnerLookup = (_, _) => null };
        var local = new IPEndPoint(IPAddress.Parse(ipv6 ? "2001:db8::20" : "192.0.2.20"), sourcePort);
        var remote = new IPEndPoint(IPAddress.Parse(ipv6 ? "2001:db8::1" : "203.0.113.1"), destinationPort);
        pipeline.RecordUdpDecision(new PortSlot(ipv6, (ushort)sourcePort), 1, false,
            new FlowDescriptor(7, @"C:\Apps\selected.exe", remote.Address.ToString(), (ushort)destinationPort, FlowProtocol.Udp),
            RouteAction.Block, pending: null);
        var address = new WinDivertAddress { Outbound = true, IPv6 = ipv6 };
        Assert.Equal(DivertPipeline.PacketAction.Drop,
            pipeline.Classify(TestPackets.Udp(local, remote, [1, 2, 3]), ref address));
    }
}
