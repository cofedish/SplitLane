using System.Net;
using Microsoft.Extensions.Time.Testing;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-003: a DNS answer teaches the engine a hostname only if it answers a query this machine was
/// seen to send - same transport, endpoints, transaction id and question. A packet that merely comes
/// from port 53 teaches nothing.
/// </summary>
[Trait("Category", "Security")]
public sealed class DnsCorrelationSecurityTests
{
    private static readonly IPEndPoint Client = new(IPAddress.Parse("192.168.0.84"), 50000);
    private static readonly IPEndPoint Resolver = new(IPAddress.Parse("8.8.8.8"), 53);
    private static readonly IPAddress Answer = IPAddress.Parse("93.184.216.34");

    private static DnsObserver Observer(TimeProvider? time = null) => new(time);

    private static void Ask(DnsObserver observer, string name = "example.com", ushort id = 0x1234, ushort type = 1) =>
        Assert.True(observer.ObserveQuery(DnsTransport.Udp, Client, Resolver, TestDns.Query(name, id, type)));

    [Fact]
    public void An_unsolicited_answer_teaches_nothing()
    {
        var observer = Observer();

        Assert.Equal(0, observer.IngestResponse(DnsTransport.Udp, Resolver, Client, TestDns.Response("example.com", Answer)));
        Assert.Null(observer.Lookup(Answer));
    }

    [Fact]
    public void A_matching_answer_is_learned()
    {
        var observer = Observer();
        Ask(observer);

        Assert.Equal(1, observer.IngestResponse(DnsTransport.Udp, Resolver, Client, TestDns.Response("example.com", Answer)));
        Assert.Equal("example.com", observer.Lookup(Answer));
    }

    [Fact]
    public void An_answer_with_the_wrong_transaction_id_is_ignored()
    {
        var observer = Observer();
        Ask(observer, id: 0x1234);

        Assert.Equal(0, observer.IngestResponse(DnsTransport.Udp, Resolver, Client, TestDns.Response("example.com", Answer, id: 0x4321)));
        Assert.Null(observer.Lookup(Answer));
    }

    [Theory]
    [InlineData("evil.example", 1)]
    [InlineData("example.com", 28)]
    public void An_answer_to_a_different_question_is_ignored(string name, ushort type)
    {
        var observer = Observer();
        Ask(observer, "example.com", type: 1);

        Assert.Equal(0, observer.IngestResponse(
            DnsTransport.Udp, Resolver, Client, TestDns.Response(name, Answer, type: type)));
        Assert.Null(observer.Lookup(Answer));
    }

    [Theory]
    [InlineData("1.1.1.1", 53, 50000)]   // another resolver
    [InlineData("8.8.8.8", 5353, 50000)] // the resolver's address, another port
    [InlineData("8.8.8.8", 53, 50001)]   // the right resolver, another client port
    public void An_answer_between_the_wrong_endpoints_is_ignored(string server, int serverPort, int clientPort)
    {
        var observer = Observer();
        Ask(observer);

        Assert.Equal(0, observer.IngestResponse(
            DnsTransport.Udp,
            new IPEndPoint(IPAddress.Parse(server), serverPort),
            new IPEndPoint(Client.Address, clientPort),
            TestDns.Response("example.com", Answer)));
        Assert.Null(observer.Lookup(Answer));
    }

    [Fact]
    public void An_answer_over_another_transport_is_ignored()
    {
        var observer = Observer();
        Ask(observer);

        Assert.Equal(0, observer.IngestResponse(DnsTransport.Tcp, Resolver, Client, TestDns.Response("example.com", Answer)));
    }

    [Fact]
    public void An_answer_after_the_query_expired_is_ignored()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-06T00:00:00Z"));
        var observer = Observer(time);
        Ask(observer);

        time.Advance(observer.QueryLifetime + TimeSpan.FromSeconds(1));

        Assert.Equal(0, observer.IngestResponse(DnsTransport.Udp, Resolver, Client, TestDns.Response("example.com", Answer)));
        Assert.Null(observer.Lookup(Answer));
    }

    [Fact]
    public void Only_the_first_answer_to_a_query_counts()
    {
        var observer = Observer();
        Ask(observer);

        Assert.Equal(1, observer.IngestResponse(DnsTransport.Udp, Resolver, Client, TestDns.Response("example.com", Answer)));

        // A second "answer" to the same query - a race the forger hopes to win late - finds nothing.
        var forged = IPAddress.Parse("203.0.113.66");
        Assert.Equal(0, observer.IngestResponse(DnsTransport.Udp, Resolver, Client, TestDns.Response("example.com", forged)));
        Assert.Null(observer.Lookup(forged));
        Assert.Equal("example.com", observer.Lookup(Answer));
    }

    [Fact]
    public void Malformed_messages_are_rejected_without_state()
    {
        var observer = Observer();
        var random = new Random(3);

        for (var i = 0; i < 2000; i++)
        {
            var bytes = new byte[random.Next(64)];
            random.NextBytes(bytes);
            observer.ObserveQuery(DnsTransport.Udp, Client, Resolver, bytes);
            Assert.Equal(0, observer.IngestResponse(DnsTransport.Udp, Resolver, Client, bytes));
        }

        Assert.Equal(0, observer.Count);
    }

    [Fact]
    public void Pending_queries_are_bounded()
    {
        var observer = new DnsObserver { MaxPendingQueries = 16 };

        for (ushort i = 0; i < 200; i++)
        {
            observer.ObserveQuery(DnsTransport.Udp, Client, Resolver, TestDns.Query($"h{i}.example", i));
        }

        Assert.True(observer.PendingQueryCount <= 16);
    }

    [Fact]
    public void A_flood_of_unanswered_queries_does_not_stop_a_genuine_answer_being_learned()
    {
        // Any local process can send queries to any address. A full table used to refuse every new
        // query, so no answer was learned and domain rules matched nothing.
        var observer = new DnsObserver { MaxPendingQueries = 16 };
        var flooder = new IPEndPoint(Client.Address, 61000);

        for (ushort i = 0; i < 200; i++)
        {
            observer.ObserveQuery(DnsTransport.Udp, flooder, new IPEndPoint(IPAddress.Parse("198.51.100.99"), 53), TestDns.Query($"f{i}.example", i));
        }

        Assert.True(observer.ObserveQuery(DnsTransport.Udp, Client, Resolver, TestDns.Query("example.com")));
        Assert.Equal(1, observer.IngestResponse(DnsTransport.Udp, Resolver, Client, TestDns.Response("example.com", Answer)));
        Assert.Equal("example.com", observer.Lookup(Answer));
        Assert.True(observer.PendingQueryCount <= 16);
    }

    [Fact]
    public void A_loopback_resolver_the_machine_does_not_use_is_not_believed()
    {
        var local = new IPEndPoint(IPAddress.Loopback, 53);
        var client = new IPEndPoint(IPAddress.Loopback, 50000);
        var observer = new DnsObserver { IsConfiguredResolver = _ => false };

        Assert.False(observer.ObserveQuery(DnsTransport.Udp, client, local, TestDns.Query("example.com")));
        Assert.Equal(0, observer.IngestResponse(DnsTransport.Udp, local, client, TestDns.Response("example.com", Answer)));
        Assert.Null(observer.Lookup(Answer));
    }

    [Fact]
    public void A_configured_loopback_resolver_is_believed()
    {
        var local = new IPEndPoint(IPAddress.Loopback, 53);
        var client = new IPEndPoint(IPAddress.Loopback, 50000);
        var observer = new DnsObserver { IsConfiguredResolver = a => a.Equals(IPAddress.Loopback) };

        Assert.True(observer.ObserveQuery(DnsTransport.Udp, client, local, TestDns.Query("example.com")));
        Assert.Equal(1, observer.IngestResponse(DnsTransport.Udp, local, client, TestDns.Response("example.com", Answer)));
    }

    // ---- Through the packet classifier ---------------------------------------------------------

    [Fact]
    public async Task A_forged_loopback_answer_through_the_classifier_teaches_nothing()
    {
        var dns = new DnsObserver { IsConfiguredResolver = _ => false };
        await using var pipeline = Pipeline(dns);

        var packet = TestPackets.Udp(
            new IPEndPoint(IPAddress.Loopback, 53), new IPEndPoint(IPAddress.Loopback, 61000),
            TestDns.Response("evil.example", Answer));
        var address = new WinDivertAddress { Outbound = true, Loopback = true };

        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(packet, ref address));
        Assert.Null(dns.Lookup(Answer));
    }

    [Fact]
    public async Task A_forged_inbound_answer_through_the_classifier_teaches_nothing()
    {
        var dns = new DnsObserver();
        await using var pipeline = Pipeline(dns);

        var packet = TestPackets.Udp(Resolver, Client, TestDns.Response("evil.example", Answer));
        var address = new WinDivertAddress { Outbound = false };

        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(packet, ref address));
        Assert.Null(dns.Lookup(Answer));
    }

    [Fact]
    public async Task A_real_exchange_through_the_classifier_is_learned()
    {
        var dns = new DnsObserver();
        await using var pipeline = Pipeline(dns);

        var query = TestPackets.Udp(Client, Resolver, TestDns.Query("example.com"));
        var outbound = new WinDivertAddress { Outbound = true };
        pipeline.Classify(query, ref outbound);

        var answer = TestPackets.Udp(Resolver, Client, TestDns.Response("example.com", Answer));
        var inbound = new WinDivertAddress { Outbound = false };
        pipeline.Classify(answer, ref inbound);

        Assert.Equal("example.com", dns.Lookup(Answer));
    }

    [Fact]
    public async Task A_real_exchange_over_tcp_through_the_classifier_is_learned()
    {
        var dns = new DnsObserver();
        await using var pipeline = Pipeline(dns);

        var query = TestPackets.Tcp(Client, Resolver, TestPackets.Ack | TestPackets.Psh, TestPackets.TcpDns(TestDns.Query("example.com")));
        var outbound = new WinDivertAddress { Outbound = true };
        pipeline.Classify(query, ref outbound);

        var answer = TestPackets.Tcp(Resolver, Client, TestPackets.Ack | TestPackets.Psh, TestPackets.TcpDns(TestDns.Response("example.com", Answer)));
        var inbound = new WinDivertAddress { Outbound = false };
        pipeline.Classify(answer, ref inbound);

        Assert.Equal("example.com", dns.Lookup(Answer));
    }

    [Fact]
    public void The_filter_captures_queries_to_a_loopback_resolver()
    {
        var filter = DivertPipeline.NetworkFilter(40000);
        Assert.Contains("loopback and udp and udp.DstPort = 53", filter, StringComparison.Ordinal);
        Assert.Contains("loopback and tcp and tcp.DstPort = 53", filter, StringComparison.Ordinal);
    }

    private static DivertPipeline Pipeline(DnsObserver dns)
    {
        var engine = new RuleEngine(SplitLane.Core.Models.RuntimeConfiguration.Empty);
        return new DivertPipeline(new NatTable(), dns, new ProcessResolver(), new EngineStatistics(), () => engine);
    }
}
