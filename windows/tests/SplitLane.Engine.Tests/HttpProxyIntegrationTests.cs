using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy;
using SplitLane.Core.Proxy.Socks5;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Relay;
using SplitLane.Engine.Runtime;
using SplitLane.Testbed.Socks5;

namespace SplitLane.Engine.Tests;

/// <summary>
/// The HTTP CONNECT upstream, end to end, against a proxy that behaves like the real ones.
/// </summary>
/// <remarks>
/// <para>
/// The first test is the bug: a corporate HTTP proxy configured as SOCKS5 is silent until the
/// timeout, and the timeout used to be all anyone saw. The rest prove the HTTP path - through the
/// redirect listener with bytes both ways, Basic and NTLM authentication, and every refusal reported
/// as its own stage and category rather than as "Timed out".
/// </para>
/// <para>
/// Credentials here are test fixtures for a proxy that exists only inside the test.
/// </para>
/// </remarks>
public sealed class HttpProxyIntegrationTests
{
    private const string User = "alice";
    private const string Password = "correct horse";

    /// <summary>Echoes upper-cased, so a reply cannot be mistaken for the request.</summary>
    private sealed class EchoServer : IAsyncDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private readonly CancellationTokenSource _stopping = new();

        public EchoServer()
        {
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen(16);
            Port = (ushort)((IPEndPoint)_listener.LocalEndPoint!).Port;
            _ = Task.Run(async () =>
            {
                while (!_stopping.IsCancellationRequested)
                {
                    Socket client;
                    try
                    {
                        client = await _listener.AcceptAsync(_stopping.Token);
                    }
                    catch (Exception)
                    {
                        return;
                    }

                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            var buffer = new byte[4096];
                            try
                            {
                                int read;
                                while ((read = await client.ReceiveAsync(buffer, _stopping.Token)) > 0)
                                {
                                    var upper = Encoding.UTF8.GetString(buffer, 0, read).ToUpperInvariant();
                                    await client.SendAsync(Encoding.UTF8.GetBytes(upper), _stopping.Token);
                                }
                            }
                            catch (Exception)
                            {
                            }
                        }
                    });
                }
            });
        }

        public ushort Port { get; }

        public ValueTask DisposeAsync()
        {
            _stopping.Cancel();
            _listener.Dispose();
            _stopping.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>Answers whatever it is sent with a fixed reply, once, then closes.</summary>
    private sealed class OneShotServer : IAsyncDisposable
    {
        private readonly Socket _listener = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        public OneShotServer(byte[] reply)
        {
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen(4);
            Port = (ushort)((IPEndPoint)_listener.LocalEndPoint!).Port;
            _ = Task.Run(async () =>
            {
                try
                {
                    using var client = await _listener.AcceptAsync();
                    await client.ReceiveAsync(new byte[1024]);
                    await client.SendAsync(reply);
                    await Task.Delay(500);
                }
                catch (Exception)
                {
                }
            });
        }

        public ushort Port { get; }

        public ValueTask DisposeAsync()
        {
            _listener.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>Everything logged while active, at every level.</summary>
    private sealed class CapturingSink : ILogSink
    {
        private readonly List<string> _lines = [];
        private volatile bool _active = true;

        public IReadOnlyList<string> Lines
        {
            get
            {
                lock (_lines)
                {
                    return [.. _lines];
                }
            }
        }

        public void Stop() => _active = false;

        public void Write(LogLevel level, string category, string message)
        {
            if (_active)
            {
                lock (_lines)
                {
                    _lines.Add(message);
                }
            }
        }
    }

    private static ProxyConfiguration Http(ushort port, int timeoutMilliseconds = 5000) => ProxyConfiguration.Default with
    {
        Type = ProxyProtocolType.Http,
        Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = port },
        HandshakeTimeoutMilliseconds = timeoutMilliseconds,
    };

    private static ushort ClosedPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (ushort)((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private static async Task<string> RoundTripAsync(Socket socket, string message)
    {
        await socket.SendAsync(Encoding.UTF8.GetBytes(message), SocketFlags.None);
        var buffer = new byte[1024];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var read = await socket.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    private static async Task<UpstreamProxyException> FailsAsync(
        ProxyConfiguration proxy, ushort destinationPort, Socks5Credential? credential = null, string host = "127.0.0.1")
    {
        var connector = new UpstreamConnector();
        return await Assert.ThrowsAsync<UpstreamProxyException>(
            () => connector.ConnectAsync(proxy, host, destinationPort, credential, CancellationToken.None));
    }

    // ---- The bug -----------------------------------------------------------------------------

    [Fact]
    public async Task AnHttpProxyConfiguredAsSocks5TimesOutAtTheGreetingAndSaysWhy()
    {
        // The reported failure, reproduced: the proxy reads the SOCKS5 greeting as the start of an
        // HTTP request, waits for the rest, and says nothing. The timeout is unavoidable - there is
        // no answer to act on - but it now names the greeting and says what to change.
        await using var proxy = new HttpProxyTestServer();
        var socks = Http(proxy.Port, timeoutMilliseconds: 600) with { Type = ProxyProtocolType.Socks5 };

        var ex = await FailsAsync(socks, 443);

        Assert.Equal(ConnectionErrorCategory.TimedOut, ex.Category);
        Assert.Equal(UpstreamStage.Greeting, ex.Stage);
        Assert.Contains("set the proxy type to HTTP", ex.Message);
    }

    [Fact]
    public async Task TheSameProxyConfiguredAsHttpOpensTheTunnel()
    {
        await using var echo = new EchoServer();
        await using var proxy = new HttpProxyTestServer();

        using var tunnel = await new UpstreamConnector().ConnectAsync(Http(proxy.Port), "127.0.0.1", echo.Port, null, CancellationToken.None);

        Assert.Equal("PING", await RoundTripAsync(tunnel.Socket, "ping"));
        Assert.Equal([$"CONNECT 127.0.0.1:{echo.Port} | 127.0.0.1:{echo.Port} | none"], proxy.Requests);
    }

    [Fact]
    public async Task AnHttpProxyThatAnswersASocksGreetingIsAMismatchNotATimeout()
    {
        await using var proxy = new OneShotServer(Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\n\r\n"));
        var socks = Http(proxy.Port) with { Type = ProxyProtocolType.Socks5 };

        var ex = await FailsAsync(socks, 443);

        Assert.Equal(ConnectionErrorCategory.ProtocolMismatch, ex.Category);
        Assert.Contains("set the proxy type to HTTP", ex.Message);
    }

    [Fact]
    public async Task ASocksProxyConfiguredAsHttpIsAMismatchNotATimeout()
    {
        await using var proxy = new OneShotServer([0x05, 0xFF]);

        var ex = await FailsAsync(Http(proxy.Port), 443);

        Assert.Equal(ConnectionErrorCategory.ProtocolMismatch, ex.Category);
        Assert.Contains("set the proxy type to SOCKS5", ex.Message);
    }

    // ---- The whole path ----------------------------------------------------------------------

    [Fact]
    public async Task ASelectedApplicationReachesItsDestinationThroughAnAuthenticatingHttpProxy()
    {
        // client -> redirect listener -> HTTP proxy (Basic) -> destination, and back.
        await using var echo = new EchoServer();
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { Basic = (User, Password) });

        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(
            nat, statistics, () => Http(proxy.Port), () => new Socks5Credential(User, Password));
        listener.Start(0);

        for (var i = 0; i < 3; i++)
        {
            using var client = await ConnectThroughListenerAsync(listener, nat, echo.Port);
            Assert.Equal($"HELLO {i}", await RoundTripAsync(client, $"hello {i}"));
        }

        // The first connection learnt the scheme from a 407; the next two sent it with the request.
        Assert.Equal(4, proxy.Requests.Count);
        Assert.EndsWith("| none", proxy.Requests[0]);
        Assert.All(proxy.Requests.Skip(1), request => Assert.EndsWith("| Basic", request));
    }

    [Fact]
    public async Task AWrongPasswordFailsTheConnectionAsRejectedCredentialsVisibleInActivity()
    {
        await using var echo = new EchoServer();
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { Basic = (User, Password) });

        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(
            nat, statistics, () => Http(proxy.Port), () => new Socks5Credential(User, "wrong"));
        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, echo.Port);
        var buffer = new byte[16];
        using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        // Closed, not left hanging and not sent anywhere else.
        Assert.Equal(0, await client.ReceiveAsync(buffer, SocketFlags.None, wait.Token));

        var failed = await WaitForAsync(() => statistics.RecentActivity(10)
            .FirstOrDefault(e => e.State == ConnectionState.Failed));

        Assert.Equal(ConnectionErrorCategory.AuthenticationFailed, failed.Error);
        Assert.Contains("proxy.auth", failed.ErrorDetail);
        Assert.Contains("HTTP 407", failed.ErrorDetail);
        Assert.DoesNotContain("wrong", failed.ErrorDetail);
    }

    [Fact]
    public async Task NoPasswordOrAuthorizationValueReachesTheLogOrActivity()
    {
        // Every log level, through a success, a Basic refusal and an NTLM exchange. What must never
        // appear: the password, or the base64 that is the password in a Basic header, or an NTLM blob.
        await using var echo = new EchoServer();
        await using var basic = new HttpProxyTestServer(new HttpProxyTestServerOptions { Basic = (User, Password) });
        await using var ntlm = new HttpProxyTestServer(new HttpProxyTestServerOptions { NtlmUsername = User });

        var sink = new CapturingSink();
        SplitLaneLog.AddSink(sink);
        var level = SplitLaneLog.MinimumLevel;
        SplitLaneLog.MinimumLevel = LogLevel.Debug;
        var statistics = new EngineStatistics();

        try
        {
            foreach (var (proxyPort, password) in new[] { (basic.Port, Password), (basic.Port, "wrong-secret"), (ntlm.Port, Password) })
            {
                var nat = new NatTable();
                await using var listener = new RedirectListener(
                    nat, statistics, () => Http(proxyPort), () => new Socks5Credential(User, password));
                listener.Start(0);

                using var client = await ConnectThroughListenerAsync(listener, nat, echo.Port);
                using var wait = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try
                {
                    await client.SendAsync(Encoding.ASCII.GetBytes("x"), SocketFlags.None);
                    await client.ReceiveAsync(new byte[16], SocketFlags.None, wait.Token);
                }
                catch (SocketException)
                {
                    // The refused connection is reset rather than closed. That is the fail-closed
                    // path, and what is being checked here is what it wrote down.
                }
            }

            await WaitForAsync(() => statistics.RecentActivity(10).Count(e => e.IsTerminal) >= 3 ? "done" : null);
        }
        finally
        {
            SplitLaneLog.MinimumLevel = level;
            sink.Stop();
        }

        var written = sink.Lines
            .Concat(statistics.RecentActivity(10).Select(e => e.ErrorDetail ?? string.Empty))
            .ToList();
        Assert.Contains(written, line => line.Contains("proxy.auth", StringComparison.Ordinal));

        foreach (var secret in new[]
        {
            Password,
            "wrong-secret",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{User}:{Password}")),
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{User}:wrong-secret")),
            "TlRMTVNT", // the base64 prefix of every NTLM message
        })
        {
            Assert.DoesNotContain(written, line => line.Contains(secret, StringComparison.Ordinal));
        }
    }

    // ---- Authentication ----------------------------------------------------------------------

    [Fact]
    public async Task BasicIsRetriedOnTheSameConnectionWhenTheProxyKeepsIt()
    {
        await using var echo = new EchoServer();
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { Basic = (User, Password), Chunked407 = true });

        using var tunnel = await new UpstreamConnector().ConnectAsync(
            Http(proxy.Port), "127.0.0.1", echo.Port, new Socks5Credential(User, Password), CancellationToken.None);

        Assert.Equal("Basic", tunnel.AuthenticationScheme);
        Assert.Equal("OK", await RoundTripAsync(tunnel.Socket, "ok"));
        Assert.Equal(1, proxy.AcceptedConnections);
        Assert.Equal(2, proxy.Requests.Count);
    }

    [Fact]
    public async Task BasicReconnectsWhenTheProxyClosesAfterItsChallenge()
    {
        await using var echo = new EchoServer();
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { Basic = (User, Password), CloseAfter407 = true });

        using var tunnel = await new UpstreamConnector().ConnectAsync(
            Http(proxy.Port), "127.0.0.1", echo.Port, new Socks5Credential(User, Password), CancellationToken.None);

        Assert.Equal("OK", await RoundTripAsync(tunnel.Socket, "ok"));
        Assert.Equal(2, proxy.AcceptedConnections);
    }

    [Fact]
    public async Task WrongCredentialsAreAnAuthenticationFailureNotATimeout()
    {
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { Basic = (User, Password) });
        var stopwatch = Stopwatch.StartNew();

        var ex = await FailsAsync(Http(proxy.Port, timeoutMilliseconds: 10_000), 443, new Socks5Credential(User, "wrong"));

        Assert.Equal(ConnectionErrorCategory.AuthenticationFailed, ex.Category);
        Assert.Equal(UpstreamStage.Authentication, ex.Stage);
        Assert.Equal(407, ex.StatusCode);
        Assert.Equal("Basic", ex.AuthenticationScheme);
        Assert.True(stopwatch.ElapsedMilliseconds < 5000, $"took {stopwatch.ElapsedMilliseconds} ms");

        // Exactly one retry: the same credentials again would only lock the account sooner.
        Assert.Equal(2, proxy.Requests.Count);
    }

    [Fact]
    public async Task A407WithNoCredentialsConfiguredSaysCredentialsAreNeeded()
    {
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { Basic = (User, Password) });

        var ex = await FailsAsync(Http(proxy.Port), 443);

        Assert.Equal(ConnectionErrorCategory.AuthenticationRequired, ex.Category);
        Assert.Equal(407, ex.StatusCode);
        Assert.Contains("Basic", ex.Message);
    }

    [Theory]
    [InlineData("Digest realm=\"corp\", qop=\"auth\", nonce=\"abc\"", "Digest")]
    [InlineData("Bearer realm=\"corp\"", "Bearer")]
    public async Task AnUnsupportedSchemeIsNamed(string challenge, string scheme)
    {
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { OfferOnly = [challenge] });

        var ex = await FailsAsync(Http(proxy.Port), 443, new Socks5Credential(User, Password));

        Assert.Equal(ConnectionErrorCategory.AuthenticationUnsupported, ex.Category);
        Assert.Contains($"Unsupported proxy authentication scheme: {scheme}", ex.Message);
        Assert.Single(proxy.Requests);
    }

    [Fact]
    public async Task NtlmCompletesOnOneConnectionWithTheConfiguredDomainAccount()
    {
        // A real SSPI exchange: the proxy's challenge is made by the server side of NTLM, and the
        // answer is the client's genuine AUTHENTICATE message, carrying the configured account.
        await using var echo = new EchoServer();
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { NtlmUsername = User });

        using var tunnel = await new UpstreamConnector().ConnectAsync(
            Http(proxy.Port), "127.0.0.1", echo.Port, new Socks5Credential(@"CORP\" + User, Password), CancellationToken.None);

        Assert.Equal("NTLM", tunnel.AuthenticationScheme);
        Assert.Equal("NTLM", await RoundTripAsync(tunnel.Socket, "ntlm"));
        Assert.Equal(1, proxy.AcceptedConnections);
        Assert.Equal(["none", "NTLM", "NTLM"], proxy.Requests.Select(r => r.Split(" | ")[2]));
        Assert.Equal(User, proxy.LastNtlmUser);
        Assert.Equal("CORP", proxy.LastNtlmDomain);
    }

    [Fact]
    public async Task NtlmFailsClearlyWhenTheProxyDropsTheConnectionMidHandshake()
    {
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { NtlmUsername = User, CloseOnNtlmNegotiate = true });

        var ex = await FailsAsync(Http(proxy.Port, timeoutMilliseconds: 10_000), 443, new Socks5Credential(User, Password));

        Assert.Equal(UpstreamStage.Authentication, ex.Stage);
        Assert.Equal(ConnectionErrorCategory.UpstreamUnreachable, ex.Category);
        Assert.Equal("NTLM", ex.AuthenticationScheme);
        Assert.Contains("closed the connection", ex.Message);
    }

    [Fact]
    public async Task ARefusedNegotiateFallsBackToTheNtlmTheProxyAlsoOffers()
    {
        await using var echo = new EchoServer();
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { NtlmUsername = User, OfferNegotiate = true });

        using var tunnel = await new UpstreamConnector().ConnectAsync(
            Http(proxy.Port), "127.0.0.1", echo.Port, new Socks5Credential(User, Password), CancellationToken.None);

        Assert.Equal("NTLM", tunnel.AuthenticationScheme);
        Assert.Equal("OK", await RoundTripAsync(tunnel.Socket, "ok"));
        Assert.Equal(User, proxy.LastNtlmUser);

        var schemes = proxy.Requests.Select(r => r.Split(" | ")[2]).ToList();
        Assert.Equal("none", schemes[0]);
        Assert.Contains("Negotiate", schemes);
        Assert.Equal(["NTLM", "NTLM"], schemes[^2..]);
    }

    [Fact]
    public async Task AChallengeThatIsNotBase64IsAnAuthenticationFailureNotAnInternalError()
    {
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { OfferOnly = ["NTLM abc-._~"] });

        var ex = await FailsAsync(Http(proxy.Port), 443, new Socks5Credential(User, Password));

        Assert.Equal(ConnectionErrorCategory.AuthenticationFailed, ex.Category);
        Assert.Equal(UpstreamStage.Authentication, ex.Stage);
        Assert.Contains("base64", ex.Message);
    }

    // ---- The proxy test ----------------------------------------------------------------------

    [Theory]
    [InlineData(403, true)]
    [InlineData(502, true)]
    [InlineData(503, true)]
    [InlineData(504, true)]
    [InlineData(400, false)]
    [InlineData(405, false)]
    [InlineData(501, false)]
    public async Task TheProxyTestPassesOnlyOnARefusalAProxyWouldGive(int status, bool healthy)
    {
        // A web server or an admin port answers CONNECT with 400/405/501. Passing the test on that
        // would point every real connection at something that is not a proxy.
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { RespondWith = status });

        var ex = await FailsAsync(Http(proxy.Port), 443, host: "splitlane.invalid");

        Assert.Equal(healthy, EngineRuntime.IsHealthyRefusal(ex));
    }

    [Fact]
    public void TheProxyTestFailsOnAnythingBeforeTheTunnelRequest()
    {
        var authentication = new UpstreamProxyException(ConnectionErrorCategory.AuthenticationFailed, UpstreamStage.Authentication, "x") { StatusCode = 407 };
        var socksRuleset = new UpstreamProxyException(ConnectionErrorCategory.RejectedByProxy, UpstreamStage.Connect, "x");

        Assert.False(EngineRuntime.IsHealthyRefusal(authentication));
        Assert.True(EngineRuntime.IsHealthyRefusal(socksRuleset));
    }

    // ---- The tunnel --------------------------------------------------------------------------

    [Fact]
    public async Task BytesGluedToTheTwoHundredReachTheApplicationAndTheTunnelDoesNotWaitForABody()
    {
        // A server that speaks first (SMTP, SSH) can land in the proxy's segment; and a 200 with a
        // Content-Length must not be read as a body to wait for.
        await using var echo = new EchoServer();
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions
        {
            CoalesceWith200 = Encoding.ASCII.GetBytes("220 ready\r\n"),
            ContentLengthOn200 = true,
        });

        using var tunnel = await new UpstreamConnector().ConnectAsync(Http(proxy.Port, 2000), "127.0.0.1", echo.Port, null, CancellationToken.None);

        Assert.Equal("220 ready\r\n", Encoding.ASCII.GetString(tunnel.LeftoverBytes));
        Assert.Equal("STILL OPEN", await RoundTripAsync(tunnel.Socket, "still open"));
    }

    [Fact]
    public async Task AHostnameIsSentAsTheConnectTarget()
    {
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { RespondWith = 503 });

        await FailsAsync(Http(proxy.Port), 443, host: "chatgpt.com");

        Assert.StartsWith("CONNECT chatgpt.com:443 | chatgpt.com:443 |", Assert.Single(proxy.Requests));
    }

    [Fact]
    public void AHostnameThatCouldInjectHeadersIsReplacedByTheAddress()
    {
        var proxy = Http(3128);

        Assert.Equal("93.184.216.34", UpstreamConnector.TargetHost(proxy, "evil.com\r\nX-Injected: 1", "93.184.216.34"));
        Assert.Equal("example.com", UpstreamConnector.TargetHost(proxy, "example.com", "93.184.216.34"));
        Assert.Equal("93.184.216.34", UpstreamConnector.TargetHost(proxy with { PreferHostnames = false }, "example.com", "93.184.216.34"));
    }

    // ---- Whose fault -------------------------------------------------------------------------

    [Fact]
    public async Task AnUnreachableProxyIsReportedAtTcpConnect()
    {
        var ex = await FailsAsync(Http(ClosedPort()), 443);

        Assert.Equal(ConnectionErrorCategory.UpstreamUnreachable, ex.Category);
        Assert.Equal(UpstreamStage.TcpConnect, ex.Stage);
        Assert.Equal(nameof(SocketError.ConnectionRefused), ex.OsError);
    }

    [Fact]
    public async Task AProxyNameThatDoesNotResolveIsReportedAtResolve()
    {
        var proxy = Http(3128) with { Endpoint = new ProxyEndpoint { Host = "splitlane-proxy.invalid", Port = 3128 } };

        var ex = await FailsAsync(proxy, 443);

        Assert.Equal(ConnectionErrorCategory.UpstreamUnreachable, ex.Category);
        Assert.Equal(UpstreamStage.Resolve, ex.Stage);
    }

    [Fact]
    public async Task AnUnreachableDestinationIsNotTheProxyBeingUnreachable()
    {
        // The testbed really dials, and the port is closed, so the proxy answers 502.
        await using var proxy = new HttpProxyTestServer();

        var ex = await FailsAsync(Http(proxy.Port), ClosedPort());

        Assert.Equal(ConnectionErrorCategory.DestinationUnreachable, ex.Category);
        Assert.Equal(UpstreamStage.Connect, ex.Stage);
        Assert.Equal(502, ex.StatusCode);
    }

    [Theory]
    [InlineData(504, ConnectionErrorCategory.DestinationUnreachable)]
    [InlineData(403, ConnectionErrorCategory.RejectedByProxy)]
    [InlineData(405, ConnectionErrorCategory.RejectedByProxy)]
    public async Task EachRefusalHasItsOwnCategory(int status, ConnectionErrorCategory expected)
    {
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { RespondWith = status });

        var ex = await FailsAsync(Http(proxy.Port), 443);

        Assert.Equal(expected, ex.Category);
        Assert.Equal(status, ex.StatusCode);
    }

    [Fact]
    public async Task ATimeoutNamesTheStageItHappenedIn()
    {
        await using var silent = new HttpProxyTestServer(new HttpProxyTestServerOptions { StallOnConnect = true });
        var connect = await FailsAsync(Http(silent.Port, timeoutMilliseconds: 400), 443);

        await using var silentAfterAuth = new HttpProxyTestServer(new HttpProxyTestServerOptions
        {
            Basic = (User, Password),
            StallOnAuthenticated = true,
        });
        var auth = await FailsAsync(Http(silentAfterAuth.Port, timeoutMilliseconds: 400), 443, new Socks5Credential(User, Password));

        Assert.Equal((ConnectionErrorCategory.TimedOut, UpstreamStage.Connect), (connect.Category, connect.Stage));
        Assert.Equal((ConnectionErrorCategory.TimedOut, UpstreamStage.Authentication), (auth.Category, auth.Stage));
        Assert.Contains("proxy.connect failed", connect.Describe());
    }

    [Fact]
    public async Task ARemovedPasswordMakesTheNextConnectionAskAgainRatherThanReuseTheScheme()
    {
        await using var echo = new EchoServer();
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { Basic = (User, Password) });
        var connector = new UpstreamConnector();

        using (await connector.ConnectAsync(Http(proxy.Port), "127.0.0.1", echo.Port, new Socks5Credential(User, Password), CancellationToken.None))
        {
        }

        var ex = await Assert.ThrowsAsync<UpstreamProxyException>(() =>
            connector.ConnectAsync(Http(proxy.Port), "127.0.0.1", echo.Port, new Socks5Credential(User, "changed"), CancellationToken.None));
        Assert.Equal(ConnectionErrorCategory.AuthenticationFailed, ex.Category);

        // Forgotten after the refusal: the next attempt starts by asking.
        using (await connector.ConnectAsync(Http(proxy.Port), "127.0.0.1", echo.Port, new Socks5Credential(User, Password), CancellationToken.None))
        {
        }

        Assert.EndsWith("| none", proxy.Requests[^2]);
    }

    // ---- UDP ---------------------------------------------------------------------------------

    [Fact]
    public async Task AnHttpUpstreamRefusesAUdpAssociationAtOnce()
    {
        await using var proxy = new HttpProxyTestServer(new HttpProxyTestServerOptions { StallOnConnect = true });

        var ex = await Assert.ThrowsAsync<Socks5Exception>(() =>
            UdpAssociation.OpenAsync(Http(proxy.Port), null, _ => { }, CancellationToken.None));

        Assert.Contains("cannot relay datagrams", ex.Message);
        Assert.Equal(0, proxy.AcceptedConnections);
    }

    // ---- Helpers -----------------------------------------------------------------------------

    private static async Task<Socket> ConnectThroughListenerAsync(RedirectListener listener, NatTable nat, ushort echoPort)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var sourcePort = (ushort)((IPEndPoint)client.LocalEndPoint!).Port;

        nat.Record(FlowKey.From(IPAddress.Loopback, sourcePort), new NatEntry(
            IPAddress.Loopback,
            IPAddress.Loopback,
            echoPort,
            (uint)Environment.ProcessId,
            @"C:\Program Files\Codex\Codex.exe",
            "Codex",
            null,
            DateTimeOffset.UtcNow));

        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.Port));
        return client;
    }

    private static async Task<T> WaitForAsync<T>(Func<T?> probe)
        where T : class
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (probe() is { } value)
            {
                return value;
            }

            await Task.Delay(20);
        }

        throw new TimeoutException("condition not met");
    }
}
