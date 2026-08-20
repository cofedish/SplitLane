using System.Net;
using Microsoft.Extensions.Time.Testing;
using SplitLane.Engine.Flows;

namespace SplitLane.Engine.Tests;

/// <summary>The table that remembers where a redirected connection was really going.</summary>
public sealed class NatTableTests
{
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
        table.Record(51000, Entry(DateTimeOffset.UtcNow));

        Assert.True(table.TryGet(51000, out var entry));
        Assert.Equal(443, entry.OriginalDestinationPort);
        Assert.Equal("example.com", entry.Hostname);
    }

    [Fact]
    public void AnUnknownPortIsNotFound()
    {
        var table = new NatTable();

        Assert.False(table.TryGet(51000, out _));
    }

    [Fact]
    public void RecordingTwiceOnAPortReplacesTheOlderEntry()
    {
        var table = new NatTable();
        var now = DateTimeOffset.UtcNow;

        table.Record(51000, Entry(now, "1.1.1.1"));
        table.Record(51000, Entry(now, "8.8.8.8"));

        Assert.True(table.TryGet(51000, out var entry));
        Assert.Equal(IPAddress.Parse("8.8.8.8"), entry.OriginalDestination);
    }

    [Fact]
    public void RemovingForgetsTheConnection()
    {
        var table = new NatTable();
        table.Record(51000, Entry(DateTimeOffset.UtcNow));

        Assert.True(table.Remove(51000));
        Assert.False(table.TryGet(51000, out _));
    }

    [Fact]
    public void AnExpiredEntryIsTreatedAsAbsent()
    {
        // This is the property that stops one application's traffic reaching another's lane when
        // Windows recycles an ephemeral port.
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(5) };

        table.Record(51000, Entry(time.GetUtcNow()));
        Assert.True(table.TryGet(51000, out _));

        time.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        Assert.False(table.TryGet(51000, out _));
    }

    [Fact]
    public void ALookupOfAnExpiredEntryAlsoDropsIt()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(1) };

        table.Record(51000, Entry(time.GetUtcNow()));
        time.Advance(TimeSpan.FromMinutes(2));
        table.TryGet(51000, out _);

        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void SweepRemovesOnlyExpiredEntries()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(5) };

        table.Record(51000, Entry(time.GetUtcNow()));
        time.Advance(TimeSpan.FromMinutes(4));
        table.Record(51001, Entry(time.GetUtcNow()));
        time.Advance(TimeSpan.FromMinutes(2));

        Assert.Equal(1, table.Sweep());
        Assert.False(table.TryGet(51000, out _));
        Assert.True(table.TryGet(51001, out _));
    }

    [Fact]
    public void ClearEmptiesTheTable()
    {
        var table = new NatTable();
        table.Record(51000, Entry(DateTimeOffset.UtcNow));
        table.Record(51001, Entry(DateTimeOffset.UtcNow));

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
            table.Record(port, Entry(now));
            table.TryGet(port, out _);
        });

        Assert.Equal(500, table.Count);
    }

    [Fact]
    public void RecordDirect_MakesTheDecisionVisibleWithoutARedirect()
    {
        var table = new NatTable();

        table.RecordDirect(51000, IPAddress.Parse("93.184.216.34"), 443);

        Assert.True(table.TryGetDirect(51000, out var destination, out var port));
        Assert.Equal(IPAddress.Parse("93.184.216.34"), destination);
        Assert.Equal(443, port);

        // It is a decision, not a redirect. Nothing may be rewritten on the strength of it.
        Assert.False(table.TryGet(51000, out _));
        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void RecordDirect_ExpiresLikeAnyOtherRow()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(5) };

        table.RecordDirect(51000, IPAddress.Loopback, 80);
        time.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        Assert.False(table.TryGetDirect(51000, out _, out _));
    }

    [Fact]
    public void Remove_ForgetsBothHalves()
    {
        // A close that forgot one half would leave it to answer for whichever connection inherits
        // the port next - and a stale "leave alone" is the answer that lets a SYN escape unrouted.
        var table = new NatTable();
        table.RecordDirect(51000, IPAddress.Parse("10.0.0.9"), 80);

        Assert.True(table.Remove(51000));
        Assert.False(table.TryGetDirect(51000, out _, out _));
    }

    [Fact]
    public void Sweep_DropsExpiredDirectDecisions()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var table = new NatTable(time) { EntryLifetime = TimeSpan.FromMinutes(5) };

        table.RecordDirect(51000, IPAddress.Loopback, 80);
        table.RecordDirect(51001, IPAddress.Loopback, 80);
        time.Advance(TimeSpan.FromMinutes(6));

        Assert.Equal(2, table.Sweep());
        Assert.False(table.TryGetDirect(51000, out _, out _));
    }

    [Fact]
    public void Clear_ForgetsDirectDecisionsToo()
    {
        var table = new NatTable();
        table.RecordDirect(51000, IPAddress.Loopback, 80);

        table.Clear();

        Assert.False(table.TryGetDirect(51000, out _, out _));
    }
}
