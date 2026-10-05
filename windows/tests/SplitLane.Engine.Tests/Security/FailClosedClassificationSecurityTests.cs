using System.Net;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-009: while anything could be protected, no packet leaves DIRECT merely because its decision
/// is not ready. Undecided SYNs and datagrams are dropped (and retried by the application), and a late
/// proxy decision terminates the connection instead of leaving it DIRECT. With no rules at all, nothing
/// is held.
/// </summary>
[Trait("Category", "Security")]
public sealed class FailClosedClassificationSecurityTests
{
    private static readonly IPEndPoint App = new(IPAddress.Parse("192.168.0.84"), 52000);
    private static readonly IPEndPoint Remote = new(IPAddress.Parse("203.0.113.10"), 443);

    /// <summary>A rule set with one selected application - enough that any flow might be protected.</summary>
    private static RuleEngine Protecting()
    {
        var engine = new RuleEngine(ConfigurationValidator.Sanitize(new RuntimeConfiguration
        {
            Rules =
            [
                new AppRule
                {
                    Identity = new AppIdentity
                    {
                        ExecutablePath = @"C:\Apps\selected.exe",
                        DisplayName = "selected",
                        FileSha256 = new string('a', 64),
                    },
                },
            ],
        }));

        Assert.True(engine.Snapshot.MayProtectTraffic);
        return engine;
    }

    private static RuleEngine Unprotected()
    {
        var engine = new RuleEngine(RuntimeConfiguration.Empty);
        Assert.False(engine.Snapshot.MayProtectTraffic);
        return engine;
    }

    private static DivertPipeline Pipeline(RuleEngine engine, NatTable? nat = null, Func<bool, ushort, UdpEndpointOwner?>? owners = null) =>
        new(nat ?? new NatTable(), new DnsObserver(), new ProcessResolver(), new EngineStatistics(), () => engine)
        {
            UdpOwnerLookup = owners ?? ((_, _) => null),
        };

    // ---- TCP --------------------------------------------------------------------------------------

    [Fact]
    public async Task A_protected_initial_SYN_without_a_decision_is_not_sent_DIRECT()
    {
        await using var pipeline = Pipeline(Protecting());
        var syn = TestPackets.Tcp(App, Remote, TestPackets.Syn);
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(syn, ref address));
        Assert.Equal(1, pipeline.UndecidedDropped);
    }

    [Fact]
    public async Task With_nothing_to_protect_an_undecided_SYN_is_left_alone()
    {
        await using var pipeline = Pipeline(Unprotected());
        var syn = TestPackets.Tcp(App, Remote, TestPackets.Syn);
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(syn, ref address));
    }

    [Fact]
    public async Task A_decided_DIRECT_SYN_is_not_held()
    {
        var nat = new NatTable();
        await using var pipeline = Pipeline(Protecting(), nat);
        nat.RecordDirect(FlowKey.From(App.Address, (ushort)App.Port), Remote.Address, (ushort)Remote.Port);

        var syn = TestPackets.Tcp(App, Remote, TestPackets.Syn);
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(syn, ref address));
    }

    [Fact]
    public async Task A_proxy_decision_that_arrives_after_its_SYN_terminates_the_connection_instead_of_leaving_it_DIRECT()
    {
        var nat = new NatTable();
        var engine = Protecting();
        await using var pipeline = Pipeline(engine, nat);

        var flow = new FlowDescriptor(7, @"C:\Apps\selected.exe", Remote.Address.ToString(), (ushort)Remote.Port, FlowProtocol.Tcp);
        var proxy = new RouteDecision(RouteAction.Proxy, RouteReasonKind.ExactRule, "selected", flow.ExecutablePath);
        pipeline.RecordTcpDecision((ushort)App.Port, App.Address, Remote.Address, flow, proxy, null, engine);

        // The SYN got out before the decision: the next segment is ACK/data, and SynRedirected is false.
        var data = TestPackets.Tcp(App, Remote, TestPackets.Ack | TestPackets.Psh, [1, 2, 3]);
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(data, ref address));
    }

    // ---- UDP --------------------------------------------------------------------------------------

    [Fact]
    public async Task A_protected_first_datagram_from_an_unknown_socket_is_not_sent_DIRECT()
    {
        await using var pipeline = Pipeline(Protecting());
        var datagram = TestPackets.Udp(App, Remote, [1, 2, 3]);
        var address = new WinDivertAddress { Outbound = true };

        // No BIND seen, and nobody could be found owning the port: classification timed out.
        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(datagram, ref address));
        Assert.Equal(1, pipeline.UndecidedDropped);
    }

    [Fact]
    public async Task A_socket_opened_before_the_engine_is_decided_by_its_owner_not_assumed_DIRECT()
    {
        // The owner lookup finds a process; this one cannot be resolved (as for a protected process
        // the engine may not open), so it is not a selected application - and its traffic flows.
        var lookups = 0;
        await using var pipeline = Pipeline(
            Protecting(), owners: (_, _) => { lookups++; return new UdpEndpointOwner(0x7FFFFFF0, DualStack: false); });

        var datagram = TestPackets.Udp(App, Remote, [1]);
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(datagram, ref address));
        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(datagram, ref address));
        Assert.Equal(1, lookups); // once per socket, not per datagram
    }

    [Fact]
    public async Task A_dual_stack_socket_of_an_unresolvable_owner_carries_IPv4_and_is_looked_up_once()
    {
        // System, a protected process or one that already exited: nothing to decide on, nothing selected.
        // Its IPv4 datagrams through an IPv6 wildcard socket used to be dropped, each after a wait and two
        // table lookups on the packet thread.
        var lookups = 0;
        await using var pipeline = Pipeline(
            Protecting(), owners: (_, _) => { lookups++; return new UdpEndpointOwner(0x7FFFFFF0, DualStack: true); });

        var datagram = TestPackets.Udp(App, Remote, [1]);
        var address = new WinDivertAddress { Outbound = true };

        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(datagram, ref address));
        }

        Assert.Equal(1, lookups);
    }

    [Fact]
    public async Task A_failed_owner_lookup_is_not_repeated_for_every_datagram()
    {
        var lookups = 0;
        await using var pipeline = Pipeline(Protecting(), owners: (_, _) => { lookups++; return null; });
        var datagram = TestPackets.Udp(App, Remote, [1]);
        var address = new WinDivertAddress { Outbound = true };

        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(datagram, ref address));
        }

        Assert.Equal(1, lookups);
    }

    [Fact]
    public async Task A_selected_socket_found_by_owner_lookup_is_refused_not_forwarded()
    {
        // The owner is "selected": recorded as Block, the way a held or refused selected socket is,
        // because this test has no relay to carry it.
        await using var pipeline = Pipeline(Protecting());
        var slot = new PortSlot(false, (ushort)App.Port);
        pipeline.RecordUdpDecision(slot, 0, false,
            new FlowDescriptor(7, @"C:\Apps\selected.exe", "203.0.113.1", 0, FlowProtocol.Udp), RouteAction.Proxy, pending: null);

        var datagram = TestPackets.Udp(App, Remote, [1]);
        var address = new WinDivertAddress { Outbound = true };

        Assert.NotEqual(DivertPipeline.PacketAction.Forward, pipeline.Classify(datagram, ref address));
    }

    [Fact]
    public void The_owner_table_reports_the_process_that_owns_a_UDP_port()
    {
        using var v4 = new System.Net.Sockets.UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = (ushort)((IPEndPoint)v4.Client.LocalEndPoint!).Port;

        var owner = UdpEndpointOwners.Find(ipv6: false, port);

        Assert.NotNull(owner);
        Assert.Equal((uint)Environment.ProcessId, owner.Value.ProcessId);
        Assert.False(owner.Value.DualStack);
    }

    [Fact]
    public void A_dual_stack_socket_owns_its_IPv4_port_in_the_owner_table()
    {
        using var socket = new System.Net.Sockets.Socket(
            System.Net.Sockets.AddressFamily.InterNetworkV6, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp)
        {
            DualMode = true,
        };
        socket.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        var port = (ushort)((IPEndPoint)socket.LocalEndPoint!).Port;

        // Windows lists a dual-mode socket in the IPv4 table as well, so its IPv4 datagrams are owned
        // either way; what matters is that the owner is found, not which table said so.
        var owner = UdpEndpointOwners.Find(ipv6: false, port);

        Assert.NotNull(owner);
        Assert.Equal((uint)Environment.ProcessId, owner.Value.ProcessId);
    }

    [Fact]
    public async Task With_nothing_to_protect_an_unknown_socket_is_left_alone_without_a_lookup()
    {
        var lookups = 0;
        await using var pipeline = Pipeline(Unprotected(), owners: (_, _) => { lookups++; return null; });
        var datagram = TestPackets.Udp(App, Remote, [1]);
        var address = new WinDivertAddress { Outbound = true };

        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(datagram, ref address));
        Assert.Equal(0, lookups);
    }
}
