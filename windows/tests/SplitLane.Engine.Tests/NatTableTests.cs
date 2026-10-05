using System.Net;
using Microsoft.Extensions.Time.Testing;
using SplitLane.Core.Models;
using SplitLane.Engine.Flows;

namespace SplitLane.Engine.Tests;

/// <summary>The table that remembers where a redirected connection was really going.</summary>
public sealed class NatTableTests
{
    /// <summary>A local end on the address the entries say the application bound.</summary>
    private static FlowKey K(int port) => FlowKey.From(IPAddress.Parse("192.168.1.5"), (ushort)port);

    [Fact]
    public void StrictPolicyDoesNotExpireIntoDirectWhileSocketIsOpen()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var table = new NatTable(time);
        table.Record(K(51000), Entry(time.GetUtcNow()) with { Action = RouteAction.ProxyOnly });
        table.RecordVerdict(K(51001), IPAddress.Parse("203.0.113.10"), 443, NatVerdict.Block);
        time.Advance(TimeSpan.FromHours(1));

        Assert.Equal(0, table.Sweep());
        Assert.True(table.TryGet(K(51000), out _));
        Assert.True(table.TryGetVerdict(K(51001), out _, out _, out var verdict));
        Assert.Equal(NatVerdict.Block, verdict);
        table.Remove(K(51000));
        table.Remove(K(51001));
        Assert.False(table.TryGet(K(51000), out _));
        Assert.False(table.TryGetVerdict(K(51001), out _, out _, out _));
    }

    private static NatEntry Entry(DateTimeOffset now, string destination = "93.184.216.34") => new(
        IPAddress.Parse("192.168.1.5"),
        IPAddress.Parse(destination),
        443,
        4242,
        @"C:\Program Files\Codex\Codex.exe",
        "Codex",
        "example.com",
        now);

    [Fact]
    public void ARecordedEntryCanBeFound()
    {
        var table = new NatTable();
        table.Record(K(51000), Entry(DateTimeOffset.UtcNow));

        Assert.True(table.TryGet(K(51000), out var entry));
        Assert.Equal(443, entry.OriginalDestinationPort);
        Assert.Equal("example.com", entry.Hostname);
    }

    [Fact]
    public void AnUnknownPortIsNotFound()
    {
        var table = new NatTable();

        Assert.False(table.TryGet(K(51000), out _));
    }

    [Theory]
    [InlineData(NatVerdict.Block)]
    [InlineData(NatVerdict.Pending)]
    public void ARefusalIsRecordedAsARefusalNotAsLeaveAlone(NatVerdict verdict)
    {
        // A TCP Block used to be recorded as a plain "leave alone" and went out DIRECT.
        var table = new NatTable();
        var destination = IPAddress.Parse("93.184.216.34");

        table.RecordVerdict(K(51000), destination, 443, verdict);

        Assert.True(table.TryGetVerdict(K(51000), out var recorded, out var port, out var found));
        Assert.Equal(verdict, found);
        Assert.Equal(destination, recorded);
        Assert.Equal(443, port);
    }

    [Fact]
    public void ALeaveAloneDecisionStillReadsAsDirect()
    {
        var table = new NatTable();
        table.RecordDirect(K(51000), IPAddress.Parse("93.184.216.34"), 443);

        Assert.True(table.TryGetVerdict(K(51000), out _, out _, out var verdict));
        Assert.Equal(NatVerdict.Direct, verdict);
    }

    [Fact]
    public void AHeldConnectionIsResolvedOnlyWhileItIsStillTheOneHeld()
    {
        var table = new NatTable();
        var destination = IPAddress.Parse("93.184.216.34");
        table.RecordVerdict(K(51000), destination, 443, NatVerdict.Pending);

        Assert.False(table.TryResolvePending(K(51000), IPAddress.Parse("10.0.0.1"), 443));
        Assert.False(table.TryResolvePending(K(51000), destination, 80));
        Assert.True(table.TryResolvePending(K(51000), destination, 443));
        Assert.False(table.TryResolvePending(K(51000), destination, 443));
    }

    [Fact]
    public void AClosedSocketIsNotResolvedIntoANewDecision()
    {
        var table = new NatTable();
        var destination = IPAddress.Parse("93.184.216.34");
        table.RecordVerdict(K(51000), destination, 443, NatVerdict.Pending);
        table.Remove(K(51000));

        Assert.False(table.TryResolvePending(K(51000), destination, 443));
    }

    [Fact]
    public void RecordingTwiceOnAPortReplacesTheOlderEntry()
    {
        var table = new NatTable();
        var now = DateTimeOffset.UtcNow;

        table.Record(K(51000), Entry(now, "1.1.1.1"));
        table.Record(K(51000), Entry(now, "8.8.8.8"));

        Assert.True(table.TryGet(K(51000), out var entry));
        Assert.Equal(IPAddress.Parse("8.8.8.8"), entry.OriginalDestination);
    }

    [Fact]
    public void RemovingForgetsTheConnection()
    {
        var table = new NatTable();
        table.Record(K(51000), Entry(DateTimeOffset.UtcNow));

        Assert.True(table.Remove(K(51000)));
        Assert.False(table.TryGet(K(51000), out _));
    }

    [Fact]
    public void AnExpiredEntryIsTreatedAsAbsent()
    {
        // This is the property that stops one application's traffic reaching another's lane when
        // Windows recycles an ephemeral port.
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(5) };

        table.Record(K(51000), Entry(time.GetUtcNow()));
        Assert.True(table.TryGet(K(51000), out _));

        time.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        Assert.False(table.TryGet(K(51000), out _));
    }

    [Fact]
    public void ALookupOfAnExpiredEntryAlsoDropsIt()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(1) };

        table.Record(K(51000), Entry(time.GetUtcNow()));
        time.Advance(TimeSpan.FromMinutes(2));
        table.TryGet(K(51000), out _);

        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void SweepRemovesOnlyExpiredEntries()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(5) };

        table.Record(K(51000), Entry(time.GetUtcNow()));
        time.Advance(TimeSpan.FromMinutes(4));
        table.Record(K(51001), Entry(time.GetUtcNow()));
        time.Advance(TimeSpan.FromMinutes(2));

        Assert.Equal(1, table.Sweep());
        Assert.False(table.TryGet(K(51000), out _));
        Assert.True(table.TryGet(K(51001), out _));
    }

    [Fact]
    public void ClearEmptiesTheTable()
    {
        var table = new NatTable();
        table.Record(K(51000), Entry(DateTimeOffset.UtcNow));
        table.Record(K(51001), Entry(DateTimeOffset.UtcNow));

        table.Clear();

        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void ConcurrentRecordingAndLookupIsSafe()
    {
        var table = new NatTable();
        var now = DateTimeOffset.UtcNow;

        Parallel.For(0, 2000, i =>
        {
            var port = (ushort)(20000 + (i % 500));
            table.Record(K(port), Entry(now));
            table.TryGet(K(port), out _);
        });

        Assert.Equal(500, table.Count);
    }

    [Fact]
    public void RecordDirect_MakesTheDecisionVisibleWithoutARedirect()
    {
        var table = new NatTable();

        table.RecordDirect(K(51000), IPAddress.Parse("93.184.216.34"), 443);

        Assert.True(table.TryGetDirect(K(51000), out var destination, out var port));
        Assert.Equal(IPAddress.Parse("93.184.216.34"), destination);
        Assert.Equal(443, port);

        // It is a decision, not a redirect. Nothing may be rewritten on the strength of it.
        Assert.False(table.TryGet(K(51000), out _));
        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void RecordDirect_ExpiresLikeAnyOtherRow()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(5) };

        table.RecordDirect(K(51000), IPAddress.Loopback, 80);
        time.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        Assert.False(table.TryGetDirect(K(51000), out _, out _));
    }

    [Fact]
    public void Remove_ForgetsBothHalves()
    {
        // A close that forgot one half would leave it to answer for whichever connection inherits
        // the port next - and a stale "leave alone" is the answer that lets a SYN escape unrouted.
        var table = new NatTable();
        table.RecordDirect(K(51000), IPAddress.Parse("10.0.0.9"), 80);

        Assert.True(table.Remove(K(51000)));
        Assert.False(table.TryGetDirect(K(51000), out _, out _));
    }

    [Fact]
    public void Sweep_DropsExpiredDirectDecisions()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(5) };

        table.RecordDirect(K(51000), IPAddress.Loopback, 80);
        table.RecordDirect(K(51001), IPAddress.Loopback, 80);
        time.Advance(TimeSpan.FromMinutes(6));

        Assert.Equal(2, table.Sweep());
        Assert.False(table.TryGetDirect(K(51000), out _, out _));
    }

    [Fact]
    public void Clear_ForgetsDirectDecisionsToo()
    {
        var table = new NatTable();
        table.RecordDirect(K(51000), IPAddress.Loopback, 80);

        table.Clear();

        Assert.False(table.TryGetDirect(K(51000), out _, out _));
    }
}
