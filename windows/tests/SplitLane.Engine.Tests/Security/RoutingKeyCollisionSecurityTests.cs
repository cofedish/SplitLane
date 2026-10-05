using System.Net;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-005: routing state is no longer keyed on a bare port number. A socket on the same number in
/// the other address family, on another local address, or simply another socket, cannot overwrite or
/// erase a selected application's decision.
/// </summary>
[Trait("Category", "Security")]
public sealed class RoutingKeyCollisionSecurityTests
{
    private const ushort Port = 51000;
    private const ulong Victim = 0x1111;
    private const ulong Attacker = 0x2222;

    private static readonly IPAddress VictimAddress = IPAddress.Parse("192.168.0.84");
    private static readonly IPAddress OtherAddress = IPAddress.Parse("172.27.240.1");
    private static readonly IPAddress Destination = IPAddress.Parse("203.0.113.10");

    private static readonly FlowKey VictimKey = FlowKey.From(VictimAddress, Port);

    private static NatEntry Proxied(ulong endpoint) => NatTable.EntryFor(
        VictimAddress, Destination, 443, 4242, @"C:\Apps\selected.exe", null, null, DateTimeOffset.UtcNow)
        with { EndpointId = endpoint };

    // ---- NAT table -------------------------------------------------------------------------------

    [Fact]
    public void IPv4_and_IPv6_on_the_same_port_are_separate_rows()
    {
        var nat = new NatTable();
        var v6 = FlowKey.From(IPAddress.Parse("2001:db8::84"), Port);

        Assert.True(nat.Record(VictimKey, Proxied(Victim)));
        nat.RecordDirect(v6, Destination, 443, Attacker);
        nat.Close(v6, Attacker);

        Assert.True(nat.TryGet(VictimKey, out var entry));
        Assert.Equal(Victim, entry.EndpointId);
    }

    [Fact]
    public void Another_local_address_on_the_same_port_is_a_separate_row()
    {
        var nat = new NatTable();
        var other = FlowKey.From(OtherAddress, Port);

        nat.RecordVerdict(VictimKey, Destination, 443, NatVerdict.Block, Victim);
        nat.RecordDirect(other, Destination, 443, Attacker);
        nat.Close(other, Attacker);

        Assert.True(nat.TryGetVerdict(VictimKey, out _, out _, out var verdict));
        Assert.Equal(NatVerdict.Block, verdict);
    }

    [Fact]
    public void A_close_from_another_socket_erases_nothing()
    {
        var nat = new NatTable();
        nat.Record(VictimKey, Proxied(Victim));

        nat.Close(VictimKey, Attacker);
        Assert.True(nat.TryGet(VictimKey, out _));

        nat.Close(VictimKey, Victim);
        Assert.False(nat.TryGet(VictimKey, out _));
    }

    [Theory]
    [InlineData(NatVerdict.Block)]
    [InlineData(NatVerdict.Pending)]
    public void A_leave_alone_from_another_socket_never_replaces_a_refusal(NatVerdict refusal)
    {
        var nat = new NatTable();
        nat.RecordVerdict(VictimKey, Destination, 443, refusal, Victim);

        nat.RecordDirect(VictimKey, Destination, 443, Attacker);

        Assert.True(nat.TryGetVerdict(VictimKey, out _, out _, out var verdict));
        Assert.Equal(refusal, verdict);
    }

    [Fact]
    public void A_second_redirected_connection_on_the_same_family_and_port_is_refused()
    {
        var nat = new NatTable();
        Assert.True(nat.Record(VictimKey, Proxied(Victim)));

        // Same family and port from another address: indistinguishable after the rewrite.
        Assert.False(nat.Record(FlowKey.From(OtherAddress, Port), Proxied(Attacker)));

        Assert.True(nat.TryGetRedirected(new PortSlot(false, Port), out var entry));
        Assert.Equal(Victim, entry.EndpointId);
    }

    [Fact]
    public async Task A_refused_second_redirect_is_dropped_never_forwarded()
    {
        var nat = new NatTable();
        var engine = new RuleEngine(RuntimeConfiguration.Empty);
        await using var pipeline = Pipeline(nat);
        var flow = new FlowDescriptor(7, @"C:\Apps\selected.exe", Destination.ToString(), 443, FlowProtocol.Tcp);
        var proxy = new RouteDecision(RouteAction.Proxy, RouteReasonKind.ExactRule, "rule", flow.ExecutablePath);

        pipeline.RecordTcpDecision(Port, VictimAddress, Destination, flow, proxy, null, engine, Victim);
        pipeline.RecordTcpDecision(Port, OtherAddress, Destination, flow, proxy, null, engine, Attacker);

        var syn = TestPackets.Tcp(new IPEndPoint(OtherAddress, Port), new IPEndPoint(Destination, 443), TestPackets.Syn);
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(syn, ref address));
    }

    // ---- Socket events through the pipeline ------------------------------------------------------

    [Fact]
    public async Task A_tcp_close_on_the_same_port_from_another_address_keeps_the_selected_connection()
    {
        var nat = new NatTable();
        await using var pipeline = Pipeline(nat);
        nat.Record(VictimKey, Proxied(Victim));

        var close = SocketEvent(WinDivertEvent.SocketClose, 6, OtherAddress, Port, Attacker);
        pipeline.HandleSocketEvent(close);

        Assert.True(nat.TryGet(VictimKey, out _));
    }

    [Fact]
    public async Task A_tcp_close_from_another_socket_on_the_same_local_end_keeps_the_selected_connection()
    {
        var nat = new NatTable();
        await using var pipeline = Pipeline(nat);
        nat.Record(VictimKey, Proxied(Victim));

        pipeline.HandleSocketEvent(SocketEvent(WinDivertEvent.SocketClose, 6, VictimAddress, Port, Attacker));
        Assert.True(nat.TryGet(VictimKey, out _));

        pipeline.HandleSocketEvent(SocketEvent(WinDivertEvent.SocketClose, 6, VictimAddress, Port, Victim));
        Assert.False(nat.TryGet(VictimKey, out _));
    }

    [Fact]
    public async Task Loopback_socket_events_from_other_processes_are_ignored()
    {
        var nat = new NatTable();
        await using var pipeline = Pipeline(nat);
        var loopbackKey = FlowKey.From(IPAddress.Loopback, Port);
        nat.RecordVerdict(loopbackKey, Destination, 443, NatVerdict.Block, Victim);

        pipeline.HandleSocketEvent(SocketEvent(WinDivertEvent.SocketClose, 6, IPAddress.Loopback, Port, Victim));

        Assert.True(nat.TryGetVerdict(loopbackKey, out _, out _, out _));
    }

    [Fact]
    public async Task A_udp_close_in_the_other_family_does_not_release_a_selected_socket()
    {
        await using var pipeline = Pipeline(new NatTable());
        var v4 = new PortSlot(false, Port);
        pipeline.RecordUdpDecision(v4, Victim, dualStack: false, UdpFlow(7), RouteAction.Block, pending: null);

        // The attacker's IPv6 socket on the same number binds and closes.
        pipeline.RecordUdpDecision(new PortSlot(true, Port), Attacker, dualStack: false, UdpFlow(9), RouteAction.Direct, pending: null);
        pipeline.CloseUdp(new PortSlot(true, Port), Attacker);

        var datagram = TestPackets.Udp(new IPEndPoint(VictimAddress, Port), new IPEndPoint(Destination, 443), [1, 2, 3]);
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(datagram, ref address));
    }

    [Fact]
    public async Task A_udp_close_from_another_socket_does_not_release_a_selected_socket()
    {
        await using var pipeline = Pipeline(new NatTable());
        var slot = new PortSlot(false, Port);
        pipeline.RecordUdpDecision(slot, Victim, dualStack: false, UdpFlow(7), RouteAction.Block, pending: null);

        pipeline.CloseUdp(slot, Attacker);

        var datagram = TestPackets.Udp(new IPEndPoint(VictimAddress, Port), new IPEndPoint(Destination, 443), [1, 2, 3]);
        var address = new WinDivertAddress { Outbound = true };
        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(datagram, ref address));

        pipeline.CloseUdp(slot, Victim);
        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(datagram, ref address));
    }

    [Fact]
    public async Task A_less_strict_bind_from_another_socket_does_not_replace_a_selected_socket()
    {
        await using var pipeline = Pipeline(new NatTable());
        var slot = new PortSlot(false, Port);

        Assert.True(pipeline.RecordUdpDecision(slot, Victim, false, UdpFlow(7), RouteAction.Block, pending: null));
        Assert.False(pipeline.RecordUdpDecision(slot, Attacker, false, UdpFlow(9), RouteAction.Direct, pending: null));

        var datagram = TestPackets.Udp(new IPEndPoint(VictimAddress, Port), new IPEndPoint(Destination, 443), [1]);
        var address = new WinDivertAddress { Outbound = true };
        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(datagram, ref address));
    }

    [Fact]
    public async Task A_dual_stack_socket_still_covers_its_IPv4_datagrams()
    {
        await using var pipeline = Pipeline(new NatTable());
        pipeline.RecordUdpDecision(new PortSlot(true, Port), Victim, dualStack: true, UdpFlow(7), RouteAction.Block, pending: null);

        var datagram = TestPackets.Udp(new IPEndPoint(VictimAddress, Port), new IPEndPoint(Destination, 443), [1]);
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(datagram, ref address));
    }

    private static FlowDescriptor UdpFlow(uint pid) =>
        new(pid, @"C:\Apps\app.exe", "203.0.113.1", 0, FlowProtocol.Udp);

    private static DivertPipeline Pipeline(NatTable nat)
    {
        var engine = new RuleEngine(RuntimeConfiguration.Empty);
        return new DivertPipeline(nat, new DnsObserver(), new ProcessResolver(), new EngineStatistics(), () => engine);
    }

    private static WinDivertAddress SocketEvent(WinDivertEvent kind, byte protocol, IPAddress local, ushort port, ulong endpoint)
    {
        var bytes = local.GetAddressBytes();
        var address = new WinDivertAddress { Event = kind, Layer = WinDivertLayer.Socket };
        address.Socket.Protocol = protocol;
        address.Socket.LocalPort = port;
        address.Socket.EndpointId = endpoint;
        address.Socket.ProcessId = 4321;
        address.Socket.LocalAddr0 = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
        return address;
    }
}
