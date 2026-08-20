using System.Net;
using Microsoft.Extensions.Time.Testing;
using SplitLane.Engine.Flows;

namespace SplitLane.Engine.Tests;

/// <summary>
/// Hostname recovery from sniffed DNS answers.
/// </summary>
/// <remarks>
/// The parser reads attacker-controlled bytes in an elevated process, so the malformed cases matter
/// at least as much as the well-formed one: every one of them must produce "nothing learned" rather
/// than a read past the buffer or a loop that never ends.
/// </remarks>
public sealed class DnsObserverTests
{
    /// <summary>Builds a DNS response for one name with the given answers.</summary>
    private static byte[] BuildResponse(
        string name,
        (ushort Type, byte[] Data)[] answers,
        bool useCompression = true,
        ushort responseCode = 0)
    {
        var message = new List<byte>
        {
            0x12, 0x34,                                     // transaction id
            (byte)(0x81 | (responseCode >> 8)), (byte)(0x80 | responseCode),
            0x00, 0x01,                                     // one question
            (byte)(answers.Length >> 8), (byte)answers.Length,
            0x00, 0x00,                                     // no authority
            0x00, 0x00,                                     // no additional
        };

        var questionOffset = message.Count;
        message.AddRange(EncodeName(name));
        message.AddRange([0x00, 0x01, 0x00, 0x01]);         // A, IN

        foreach (var (type, data) in answers)
        {
            if (useCompression)
            {
                message.Add((byte)(0xC0 | (questionOffset >> 8)));
                message.Add((byte)(questionOffset & 0xFF));
            }
            else
            {
                message.AddRange(EncodeName(name));
            }

            message.AddRange([(byte)(type >> 8), (byte)type]);
            message.AddRange([0x00, 0x01]);                 // IN
            message.AddRange([0x00, 0x00, 0x01, 0x2C]);     // TTL 300
            message.AddRange([(byte)(data.Length >> 8), (byte)data.Length]);
            message.AddRange(data);
        }

        return [.. message];
    }

    private static byte[] EncodeName(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }

        bytes.Add(0);
        return [.. bytes];
    }

    [Fact]
    public void AnARecordIsRemembered()
    {
        var observer = new DnsObserver();
        var response = BuildResponse("example.com", [(1, [93, 184, 216, 34])]);

        Assert.Equal(1, observer.IngestResponse(response));
        Assert.Equal("example.com", observer.Lookup(IPAddress.Parse("93.184.216.34")));
    }

    [Fact]
    public void AnAaaaRecordIsRemembered()
    {
        var observer = new DnsObserver();
        var address = IPAddress.Parse("2606:2800:220:1::1");
        var response = BuildResponse("example.com", [(28, address.GetAddressBytes())]);

        Assert.Equal(1, observer.IngestResponse(response));
        Assert.Equal("example.com", observer.Lookup(address));
    }

    [Fact]
    public void EveryAnswerInAMultiAddressResponseIsRemembered()
    {
        var observer = new DnsObserver();
        var response = BuildResponse("cdn.example.com",
        [
            (1, [1, 2, 3, 4]),
            (1, [5, 6, 7, 8]),
            (1, [9, 10, 11, 12]),
        ]);

        Assert.Equal(3, observer.IngestResponse(response));
        Assert.Equal("cdn.example.com", observer.Lookup(IPAddress.Parse("5.6.7.8")));
    }

    [Fact]
    public void UncompressedNamesParseToo()
    {
        var observer = new DnsObserver();
        var response = BuildResponse("example.com", [(1, [93, 184, 216, 34])], useCompression: false);

        Assert.Equal(1, observer.IngestResponse(response));
    }

    [Fact]
    public void RecordTypesOtherThanAddressesAreSkipped()
    {
        var observer = new DnsObserver();
        var response = BuildResponse("example.com",
        [
            (5, EncodeName("real.example.com")),  // CNAME
            (1, [93, 184, 216, 34]),
        ]);

        Assert.Equal(1, observer.IngestResponse(response));
        Assert.Equal("example.com", observer.Lookup(IPAddress.Parse("93.184.216.34")));
    }

    [Fact]
    public void AQueryIsIgnoredBecauseItCarriesNoAnswers()
    {
        var observer = new DnsObserver();
        var query = BuildResponse("example.com", [(1, [1, 2, 3, 4])]);
        query[2] = 0x01; // clear the response bit

        Assert.Equal(0, observer.IngestResponse(query));
    }

    [Fact]
    public void AnErrorResponseIsIgnored()
    {
        var observer = new DnsObserver();
        var response = BuildResponse("example.com", [(1, [1, 2, 3, 4])]);
        response[3] = 0x83; // NXDOMAIN

        Assert.Equal(0, observer.IngestResponse(response));
    }

    // ---- Malformed input ----------------------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(11)]
    public void ATruncatedHeaderIsIgnored(int length) =>
        Assert.Equal(0, new DnsObserver().IngestResponse(new byte[length]));

    [Fact]
    public void ATruncatedAnswerSectionStopsCleanly()
    {
        var observer = new DnsObserver();
        var response = BuildResponse("example.com", [(1, [93, 184, 216, 34])]);

        for (var cut = 12; cut < response.Length; cut++)
        {
            // Whatever it learns, it must not throw and must not hang.
            observer.IngestResponse(response.AsSpan(0, cut));
        }
    }

    [Fact]
    public void ASelfReferentialCompressionPointerTerminates()
    {
        // A pointer at offset 12 pointing to offset 12. A naive parser loops forever here.
        var response = new byte[]
        {
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x0C,
        };

        Assert.Equal(0, new DnsObserver().IngestResponse(response));
    }

    [Fact]
    public void AForwardCompressionPointerIsRejected()
    {
        var response = new byte[]
        {
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x20,   // points past itself
            0x00, 0x01, 0x00, 0x01,
        };

        Assert.Equal(0, new DnsObserver().IngestResponse(response));
    }

    [Fact]
    public void AnAnswerClaimingMoreDataThanArrivedIsIgnored()
    {
        var observer = new DnsObserver();
        var response = BuildResponse("example.com", [(1, [93, 184, 216, 34])]);

        // Overstate RDLENGTH.
        response[^6] = 0xFF;
        response[^5] = 0xFF;

        Assert.Equal(0, observer.IngestResponse(response));
    }

    // ---- Expiry and bounds ----------------------------------------------------------------------

    [Fact]
    public void ARememberedNameExpires()
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        var observer = new DnsObserver(time) { EntryLifetime = TimeSpan.FromMinutes(10) };

        observer.Record(IPAddress.Parse("1.2.3.4"), "example.com");
        Assert.Equal("example.com", observer.Lookup(IPAddress.Parse("1.2.3.4")));

        time.Advance(TimeSpan.FromMinutes(11));

        Assert.Null(observer.Lookup(IPAddress.Parse("1.2.3.4")));
    }

    [Fact]
    public void AnUnknownAddressReturnsNull() =>
        Assert.Null(new DnsObserver().Lookup(IPAddress.Parse("203.0.113.1")));

    [Fact]
    public void ANullAddressReturnsNull() => Assert.Null(new DnsObserver().Lookup(null));

    [Fact]
    public void TheTableIsBounded()
    {
        var observer = new DnsObserver { MaxEntries = 100 };

        for (var i = 0; i < 500; i++)
        {
            observer.Record(new IPAddress([10, 0, (byte)(i / 256), (byte)(i % 256)]), $"host{i}.example");
        }

        Assert.True(observer.Count <= 100);
    }

    [Fact]
    public void AMostRecentAnswerWinsForTheSameAddress()
    {
        var observer = new DnsObserver();

        observer.Record(IPAddress.Parse("1.2.3.4"), "first.example");
        observer.Record(IPAddress.Parse("1.2.3.4"), "second.example");

        Assert.Equal("second.example", observer.Lookup(IPAddress.Parse("1.2.3.4")));
    }
}
