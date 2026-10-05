using System.Net;
using Microsoft.Extensions.Time.Testing;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-004: a redirected connection that is in use is never forgotten; an idle one is, sooner once it
/// is closing; and whatever ends it, its late packets are dropped, never sent DIRECT.
/// </summary>
[Trait("Category", "Security")]
public sealed class FlowLifetimeSecurityTests
{
    private static readonly IPEndPoint App = new(IPAddress.Parse("192.168.0.84"), 53000);
    private static readonly IPEndPoint Remote = new(IPAddress.Parse("203.0.113.10"), 443);
    private static readonly FlowKey Key = FlowKey.From(App.Address, (ushort)App.Port);

    private static NatEntry Entry(DateTimeOffset now, RouteAction action = RouteAction.Proxy) => NatTable.EntryFor(
        App.Address, Remote.Address, (ushort)Remote.Port, 7, @"C:\Apps\selected.exe", null, null, now) with { Action = action };

    [Fact]
    public void Traffic_keeps_a_connection_alive_past_the_old_five_minute_limit()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-06T00:00:00Z"));
        var nat = new NatTable(time);
        var entry = Entry(time.GetUtcNow());
        nat.Record(Key, entry);

        for (var minute = 0; minute < 60; minute++)
        {
            time.Advance(TimeSpan.FromMinutes(1));
            nat.Touch(entry);
            nat.Sweep();
            Assert.True(nat.TryGet(Key, out _), $"forgotten after {minute + 1} busy minutes");
        }
    }

    [Fact]
    public void A_quiet_connection_is_not_expired_while_it_is_relayed()
    {
        // An HTTP/2 or WebSocket connection can be silent for far longer than the idle limit, and
        // Windows sends no keepalive by default. Expiring it would send its next segment DIRECT.
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-06T00:00:00Z"));
        var nat = new NatTable(time);
        var entry = Entry(time.GetUtcNow());
        nat.Record(Key, entry);
        nat.BeginRelay(entry);

        time.Advance(TimeSpan.FromHours(3));
        nat.Sweep();
        Assert.True(nat.TryGet(Key, out _));
        Assert.False(nat.IsClosedStrict(Key, Remote.Address, (ushort)Remote.Port));

        // Once the relay ends, the idle limit counts from then.
        nat.EndRelay(entry);
        time.Advance(nat.EntryLifetime - TimeSpan.FromSeconds(1));
        Assert.True(nat.TryGet(Key, out _));
        time.Advance(TimeSpan.FromSeconds(2));
        Assert.False(nat.TryGet(Key, out _));
        Assert.True(nat.IsClosedStrict(Key, Remote.Address, (ushort)Remote.Port));
    }

    [Fact]
    public void An_idle_connection_expires()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-06T00:00:00Z"));
        var nat = new NatTable(time);
        nat.Record(Key, Entry(time.GetUtcNow()));

        time.Advance(nat.EntryLifetime + TimeSpan.FromSeconds(1));

        Assert.False(nat.TryGet(Key, out _));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void A_FIN_or_RST_shortens_the_idle_limit(bool fin, bool rst)
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-06T00:00:00Z"));
        var nat = new NatTable(time);
        var entry = Entry(time.GetUtcNow());
        nat.Record(Key, entry);

        nat.Touch(entry, closing: fin || rst);
        time.Advance(nat.ClosingLifetime + TimeSpan.FromSeconds(1));

        Assert.False(nat.TryGet(Key, out _));
    }

    [Fact]
    public void A_close_removes_the_connection()
    {
        var nat = new NatTable();
        nat.Record(Key, Entry(DateTimeOffset.UtcNow) with { EndpointId = 5 });

        nat.Close(Key, 5);

        Assert.False(nat.TryGet(Key, out _));
    }

    [Fact]
    public async Task A_busy_connection_is_still_redirected_after_ten_minutes()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-06T00:00:00Z"));
        var nat = new NatTable(time);
        await using var pipeline = Pipeline(nat);
        Record(pipeline);

        var address = new WinDivertAddress { Outbound = true };
        var syn = TestPackets.Tcp(App, Remote, TestPackets.Syn);
        Assert.Equal(DivertPipeline.PacketAction.Rewritten, pipeline.Classify(syn, ref address));

        for (var i = 0; i < 20; i++)
        {
            time.Advance(TimeSpan.FromSeconds(30));
            nat.Sweep();
            var data = TestPackets.Tcp(App, Remote, TestPackets.Ack | TestPackets.Psh, [1]);
            Assert.Equal(DivertPipeline.PacketAction.Rewritten, pipeline.Classify(data, ref address));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_late_packet_after_expiry_or_close_is_dropped_never_forwarded(bool closeInsteadOfExpire)
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-06T00:00:00Z"));
        var nat = new NatTable(time);
        await using var pipeline = Pipeline(nat);
        Record(pipeline, endpointId: 9);

        var address = new WinDivertAddress { Outbound = true };
        pipeline.Classify(TestPackets.Tcp(App, Remote, TestPackets.Syn), ref address);

        if (closeInsteadOfExpire)
        {
            nat.Close(Key, 9);
        }
        else
        {
            time.Advance(nat.EntryLifetime + TimeSpan.FromSeconds(1));
            nat.Sweep();
        }

        var late = TestPackets.Tcp(App, Remote, TestPackets.Ack | TestPackets.Fin, []);
        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(late, ref address));
    }

    [Fact]
    public async Task Cleanup_and_traffic_racing_never_leave_an_active_connection_unprotected()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-10-06T00:00:00Z"));
        var nat = new NatTable(time);
        var entry = Entry(time.GetUtcNow());
        nat.Record(Key, entry);

        var stop = false;
        var sweeper = Task.Run(() =>
        {
            while (!Volatile.Read(ref stop))
            {
                nat.Sweep();
            }
        });

        for (var i = 0; i < 10_000; i++)
        {
            nat.Touch(entry);
            if (i % 100 == 0)
            {
                time.Advance(TimeSpan.FromSeconds(1));
            }

            // Either still the live entry, or - never - absent without a tombstone.
            Assert.True(
                nat.TryGet(Key, out _) || nat.IsClosedStrict(Key, Remote.Address, (ushort)Remote.Port),
                "an active connection was left with neither its entry nor a refusal");
        }

        Volatile.Write(ref stop, true);
        await sweeper;
        Assert.True(nat.TryGet(Key, out _));
    }

    private static DivertPipeline Pipeline(NatTable nat)
    {
        var engine = new RuleEngine(RuntimeConfiguration.Empty);
        return new DivertPipeline(nat, new DnsObserver(), new ProcessResolver(), new EngineStatistics(), () => engine);
    }

    private static void Record(DivertPipeline pipeline, ulong endpointId = 0)
    {
        var engine = new RuleEngine(RuntimeConfiguration.Empty);
        var flow = new FlowDescriptor(7, @"C:\Apps\selected.exe", Remote.Address.ToString(), (ushort)Remote.Port, FlowProtocol.Tcp);
        var proxy = new RouteDecision(RouteAction.Proxy, RouteReasonKind.ExactRule, "selected", flow.ExecutablePath);
        pipeline.RecordTcpDecision((ushort)App.Port, App.Address, Remote.Address, flow, proxy, null, engine, endpointId);
    }
}
