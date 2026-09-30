using System.Text;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy;
using SplitLane.Core.Proxy.Http;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Core.Tests;

/// <summary>
/// HTTP CONNECT as pure functions: the request, the answer's head, the 407's body and its challenges.
/// </summary>
/// <remarks>
/// The engine's client is I/O around these. Every split point of a response, every framing of a 407
/// body and every shape of <c>Proxy-Authenticate</c> is reachable here without a socket.
/// </remarks>
public sealed class HttpProxyProtocolTests
{
    private static byte[] Ascii(string text) => Encoding.ASCII.GetBytes(text);

    // ---- The request -------------------------------------------------------------------------

    [Fact]
    public void ConnectRequestIsAuthorityFormWithHostAndCrlf()
    {
        var request = Encoding.ASCII.GetString(HttpConnectRequest.Build("example.com:443", null));

        Assert.Equal(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Connection: Keep-Alive\r\n\r\n",
            request);
    }

    [Fact]
    public void AuthorizationIsSentOnlyWhenGiven()
    {
        var request = Encoding.ASCII.GetString(HttpConnectRequest.Build("example.com:443", "Basic abc="));

        Assert.Contains("\r\nProxy-Authorization: Basic abc=\r\n", request);
        Assert.EndsWith("\r\n\r\n", request);
        Assert.DoesNotContain("Proxy-Authorization", Encoding.ASCII.GetString(HttpConnectRequest.Build("example.com:443", null)));
    }

    [Fact]
    public void AnIPv6DestinationIsBracketed()
        => Assert.Equal("[2001:db8::1]:443", HttpConnectRequest.Authority("2001:db8::1", 443));

    [Theory]
    [InlineData("example.com")]
    [InlineData("chatgpt.com")]
    [InlineData("_dmarc.example.com")]
    [InlineData("93.184.216.34")]
    [InlineData("2001:db8::1")]
    public void OrdinaryHostsAreValid(string host) => Assert.True(HttpConnectRequest.IsValidHost(host));

    [Theory]
    [InlineData("example.com\r\nX-Injected: 1")]
    [InlineData("example.com\n")]
    [InlineData("exa mple.com")]
    [InlineData("example.com:443")]
    [InlineData("fe80::1%12")]
    [InlineData("")]
    public void AHostThatCouldBreakTheRequestLineIsRefused(string host)
    {
        // Hostnames arrive from sniffed DNS answers, whose labels may hold any byte.
        Assert.False(HttpConnectRequest.IsValidHost(host));
        Assert.Throws<ArgumentException>(() => HttpConnectRequest.Authority(host, 443));
    }

    [Fact]
    public void AnAuthorizationWithALineBreakIsRefused()
        => Assert.Throws<ArgumentException>(() => HttpConnectRequest.Build("example.com:443", "Basic x\r\nX-Evil: 1"));

    [Fact]
    public void BasicIsBase64OfUtf8UserColonPassword()
    {
        Assert.Equal("Basic dXNlcjpww6Rzcw==", HttpConnectRequest.BasicAuthorization("user", "päss"));
    }

    [Fact]
    public void BasicRefusesAUsernameWithAColon()
        => Assert.Throws<ArgumentException>(() => HttpConnectRequest.BasicAuthorization("dom:user", "x"));

    // ---- The answer's head -------------------------------------------------------------------

    [Fact]
    public void TwoHundredEndsAtTheBlankLineAndLeavesTheRestForTheTunnel()
    {
        var data = Ascii("HTTP/1.1 200 Connection established\r\n\r\n\x16\x03\x01");

        var status = HttpResponseHead.TryParse(data, out var head, out var length);

        Assert.Equal(HttpHeadParseStatus.Complete, status);
        Assert.True(head!.IsSuccess);
        Assert.Equal(data.Length - 3, length);
    }

    [Fact]
    public void AContentLengthOnTwoHundredDoesNotMakeItWaitForABody()
    {
        // RFC 9110 §9.3.6: a 2xx to CONNECT is a tunnel from the blank line; framing headers are
        // ignored. A parser that honoured this one would wait for 100 bytes that belong to the
        // destination - the "established tunnel turns into a timeout" failure.
        var data = Ascii("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");

        Assert.Equal(HttpHeadParseStatus.Complete, HttpResponseHead.TryParse(data, out _, out var length));
        Assert.Equal(data.Length, length);
    }

    [Fact]
    public void EveryTruncationOfAHeadAsksForMore()
    {
        var data = Ascii("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\n\r\n");

        for (var cut = 0; cut < data.Length; cut++)
        {
            Assert.Equal(HttpHeadParseStatus.NeedMoreBytes, HttpResponseHead.TryParse(data.AsSpan(0, cut), out _, out _));
        }

        Assert.Equal(HttpHeadParseStatus.Complete, HttpResponseHead.TryParse(data, out var head, out _));
        Assert.Equal(407, head!.StatusCode);
        Assert.Equal("Proxy Authentication Required", head.ReasonPhrase);
    }

    [Fact]
    public void BareLineFeedsAreAccepted()
    {
        Assert.Equal(HttpHeadParseStatus.Complete, HttpResponseHead.TryParse(Ascii("HTTP/1.0 200 OK\nVia: x\n\n"), out var head, out var length));
        Assert.Equal(200, head!.StatusCode);
        Assert.Equal(24, length);
    }

    [Fact]
    public void ASocksReplyIsRecognisedAtOnceNotAfterATimeout()
    {
        // A SOCKS5 server sends two bytes and waits. Waiting for a blank line would never end.
        Assert.Equal(HttpHeadParseStatus.NotHttp, HttpResponseHead.TryParse(new byte[] { 0x05, 0xFF }, out _, out _));
    }

    [Theory]
    [InlineData("HTTP/1.1 20 OK\r\n\r\n")]
    [InlineData("HTTP/2.0 200 OK\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nBad Header\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nName : value\r\n\r\n")]
    public void MalformedHeadsAreReported(string text)
        => Assert.Equal(HttpHeadParseStatus.Malformed, HttpResponseHead.TryParse(Ascii(text), out _, out _));

    [Fact]
    public void AHeadWithNoEndIsTooLarge()
    {
        var data = Ascii("HTTP/1.1 200 OK\r\nX: " + new string('a', HttpResponseHead.MaxHeadBytes) + "\r\n");

        Assert.Equal(HttpHeadParseStatus.TooLarge, HttpResponseHead.TryParse(data, out _, out _));
    }

    [Fact]
    public void RepeatedHeadersAreAllKept()
    {
        HttpResponseHead.TryParse(
            Ascii("HTTP/1.1 407 x\r\nProxy-Authenticate: Negotiate\r\nproxy-authenticate: NTLM\r\n\r\n"),
            out var head, out _);

        Assert.Equal(["Negotiate", "NTLM"], head!.Values("Proxy-Authenticate"));
    }

    [Theory]
    [InlineData("HTTP/1.1 407 x\r\n\r\n", false)]
    [InlineData("HTTP/1.1 407 x\r\nConnection: close\r\n\r\n", true)]
    [InlineData("HTTP/1.1 407 x\r\nProxy-Connection: close\r\n\r\n", true)]
    [InlineData("HTTP/1.0 407 x\r\n\r\n", true)]
    [InlineData("HTTP/1.0 407 x\r\nProxy-Connection: Keep-Alive\r\n\r\n", false)]
    public void ConnectionPersistenceFollowsTheVersionAndHeaders(string text, bool closes)
    {
        HttpResponseHead.TryParse(Ascii(text), out var head, out _);
        Assert.Equal(closes, head!.ClosesConnection);
    }

    [Fact]
    public void ABodyWithNoFramingIsDelimitedByClose()
    {
        HttpResponseHead.TryParse(Ascii("HTTP/1.1 407 x\r\n\r\n"), out var head, out _);
        Assert.Null(head!.BodyReader());
    }

    [Fact]
    public void ConflictingContentLengthsAreRefused()
    {
        HttpResponseHead.TryParse(Ascii("HTTP/1.1 407 x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"), out var head, out _);
        Assert.Throws<FormatException>(() => head!.BodyReader());
    }

    // ---- A 407's body ------------------------------------------------------------------------

    [Fact]
    public void AFixedLengthBodyStopsAtItsLength()
    {
        var reader = HttpBodyReader.ForLength(5);

        Assert.Equal(3, reader.Consume(Ascii("abc")));
        Assert.False(reader.IsComplete);
        Assert.Equal(2, reader.Consume(Ascii("deHTTP/1.1")));
        Assert.True(reader.IsComplete);
    }

    [Fact]
    public void AChunkedBodyIsReadThroughExtensionsAndTrailersAtEverySplit()
    {
        var body = Ascii("4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: y\r\n\r\n");
        var next = Ascii("HTTP/1.1 200 OK\r\n\r\n");
        var stream = body.Concat(next).ToArray();

        for (var split = 0; split <= body.Length; split++)
        {
            var reader = HttpBodyReader.Chunked();
            var used = reader.Consume(stream.AsSpan(0, split));
            used += reader.Consume(stream.AsSpan(used));

            Assert.True(reader.IsComplete);
            Assert.Equal(body.Length, used);
            Assert.Equal(9, reader.BodyBytes);
        }
    }

    [Fact]
    public void ABadChunkSizeIsReported()
        => Assert.Throws<FormatException>(() => HttpBodyReader.Chunked().Consume(Ascii("zz\r\n")));

    // ---- Challenges --------------------------------------------------------------------------

    [Fact]
    public void OneHeaderCanListSeveralSchemes()
    {
        var challenges = ProxyAuthenticationChallenge.Parse(["Negotiate, NTLM, Basic realm=\"corp, main\""]);

        Assert.Equal(["Negotiate", "NTLM", "Basic"], challenges.Select(c => c.Scheme));
        Assert.Equal("corp, main", challenges[2].Parameters["realm"]);
    }

    [Fact]
    public void AToken68WithPaddingIsATokenNotAParameter()
    {
        var challenge = Assert.Single(ProxyAuthenticationChallenge.Parse(["NTLM TlRMTVNTUAACAAAADAAMADgAAAA="]));

        Assert.True(challenge.Is("ntlm"));
        Assert.Equal("TlRMTVNTUAACAAAADAAMADgAAAA=", challenge.Token);
    }

    [Fact]
    public void ParametersStayWithTheirScheme()
    {
        var challenges = ProxyAuthenticationChallenge.Parse(
            ["Digest realm=\"corp\", qop=\"auth\", nonce=\"abc\", Basic realm=\"b\""]);

        Assert.Equal(2, challenges.Count);
        Assert.Equal("auth", challenges[0].Parameters["qop"]);
        Assert.Equal("abc", challenges[0].Parameters["nonce"]);
        Assert.Equal("b", challenges[1].Parameters["realm"]);
    }

    [Fact]
    public void AnUnreadableElementDoesNotHideAUsableScheme()
    {
        var challenges = ProxyAuthenticationChallenge.Parse(["\"junk\", Basic realm=\"x\""]);

        Assert.Equal("Basic", Assert.Single(challenges).Scheme);
    }

    // ---- Categories, stages, UDP -------------------------------------------------------------

    [Fact]
    public void ADestinationTheSocksProxyCouldNotReachIsNotTheProxyBeingUnreachable()
    {
        var ex = new Socks5Exception(Socks5ErrorCode.RequestRejected, "x") { ReplyCode = Socks5ReplyCode.HostUnreachable };

        Assert.Equal(ConnectionErrorCategory.DestinationUnreachable, ex.ToCategory());
        Assert.Equal(ConnectionErrorCategory.UpstreamUnreachable, Socks5ErrorCode.TransportFailure.ToCategory());
    }

    [Fact]
    public void AnHttpProxyAnsweringASocksGreetingIsAProtocolMismatch()
    {
        Assert.Equal(ConnectionErrorCategory.ProtocolMismatch, Socks5ErrorCode.UnexpectedVersion.ToCategory());
        Assert.Equal(ConnectionErrorCategory.AuthenticationRequired, Socks5ErrorCode.AuthenticationRequired.ToCategory());
    }

    [Fact]
    public void AFailureDescriptionNamesTheStageProxyDestinationStatusAndScheme()
    {
        var ex = new UpstreamProxyException(
            ConnectionErrorCategory.AuthenticationFailed, UpstreamStage.Authentication, "The proxy rejected the Basic credentials")
        {
            Protocol = ProxyProtocolType.Http,
            Endpoint = "proxy.corp:3128",
            Destination = "chatgpt.com:443",
            ElapsedMilliseconds = 12.4,
            StatusCode = 407,
            AuthenticationScheme = "Basic",
        };

        Assert.Equal(
            "proxy.auth failed: The proxy rejected the Basic credentials " +
            "[HTTP proxy proxy.corp:3128, destination chatgpt.com:443, 12 ms, HTTP 407, scheme Basic]",
            ex.Describe());
    }

    [Fact]
    public void AnHttpUpstreamCarriesNoDatagrams()
    {
        var http = new RuntimeConfiguration { Proxy = ProxyConfiguration.Default with { Type = ProxyProtocolType.Http } };

        Assert.True(http.ProxiesUdp);
        Assert.False(http.RelaysUdp);
        Assert.True(RuntimeConfiguration.Empty.RelaysUdp);
    }

    [Fact]
    public void TheProxyTypeRoundTripsThroughStoredConfiguration()
    {
        var configuration = new RuntimeConfiguration
        {
            Proxy = ProxyConfiguration.Default with
            {
                Type = ProxyProtocolType.Http,
                Endpoint = new ProxyEndpoint { Host = "proxy.corp", Port = 3128 },
                Credential = new CredentialReference { Username = @"CORP\alice" },
            },
        };

        var json = ConfigurationCodec.EncodeToJson(configuration);
        var decoded = ConfigurationCodec.DecodeFromJson(json);

        Assert.Contains("\"type\": \"Http\"", json);
        Assert.Equal(ProxyProtocolType.Http, decoded.Proxy.Type);
        Assert.Equal(@"CORP\alice", decoded.Proxy.Credential!.Username);
    }
}
