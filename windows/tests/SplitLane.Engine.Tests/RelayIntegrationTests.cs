using System.Net;
using System.Net.Sockets;
using System.Text;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Relay;
using SplitLane.Engine.Runtime;
using SplitLane.Testbed.Socks5;

namespace SplitLane.Engine.Tests;

/// <summary>
/// The relay path, end to end, against a real SOCKS5 server and a real echo server.
/// </summary>
/// <remarks>
/// Everything here except the packet rewrite is exercised for real: the redirect listener accepts, it
/// finds the NAT entry, it performs a genuine RFC 1928 handshake, and bytes travel in both
/// directions. The only part simulated is the divert layer, which is replaced by connecting to the
/// listener directly from a socket whose source port has been recorded in the NAT table — exactly the
/// state the rewrite produces.
/// </remarks>
public sealed class RelayIntegrationTests
{
    /// <summary>A TCP server that echoes whatever it is sent, upper-cased.</summary>
    private sealed class EchoServer : IAsyncDisposable
    {
        private readonly Socket _listener;
        private readonly CancellationTokenSource _stopping = new();
        private readonly Task _loop;

        public EchoServer()
        {
            _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen(16);
            Port = (ushort)((IPEndPoint)_listener.LocalEndPoint!).Port;
            _loop = Task.Run(AcceptAsync);
        }

        public ushort Port { get; }

        private async Task AcceptAsync()
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
                    var buffer = new byte[4096];
                    try
                    {
                        while (true)
                        {
                            var read = await client.ReceiveAsync(buffer, _stopping.Token);
                            if (read == 0)
                            {
                                break;
                            }

                            var text = Encoding.UTF8.GetString(buffer, 0, read).ToUpperInvariant();
                            await client.SendAsync(Encoding.UTF8.GetBytes(text), _stopping.Token);
                        }
                    }
                    catch (Exception)
                    {
                    }
                    finally
                    {
                        client.Dispose();
                    }
                });
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _stopping.CancelAsync();
            _listener.Dispose();
            try
            {
                await _loop;
            }
            catch (OperationCanceledException)
            {
            }

            _stopping.Dispose();
        }
    }

    private static ProxyConfiguration ProxyOn(ushort port, CredentialReference? credential = null) =>
        ProxyConfiguration.Default with
        {
            Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = port },
            Credential = credential,
            HandshakeTimeoutMilliseconds = 5000,
        };

    private static NatEntry EntryFor(ushort echoPort, string? hostname = null) => new(
        IPAddress.Loopback,
        IPAddress.Loopback,
        echoPort,
        (uint)Environment.ProcessId,
        @"C:\Program Files\Codex\Codex.exe",
        "Codex",
        hostname,
        DateTimeOffset.UtcNow);

    /// <summary>Connects to the listener and registers the resulting source port in the NAT table.</summary>
    private static async Task<Socket> ConnectThroughListenerAsync(
        RedirectListener listener, NatTable nat, NatEntry entry)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };

        // Bind explicitly so the source port is known before the connection exists, which is what
        // the divert layer guarantees by recording the entry at socket-connect time.
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var sourcePort = (ushort)((IPEndPoint)client.LocalEndPoint!).Port;
        nat.Record(sourcePort, entry);

        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.Port));
        return client;
    }

    private static async Task<string> RoundTripAsync(Socket socket, string message)
    {
        await socket.SendAsync(Encoding.UTF8.GetBytes(message), SocketFlags.None);

        var buffer = new byte[1024];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var read = await socket.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);
        return Encoding.UTF8.GetString(buffer, 0, read);
    }

    // ---- Happy path --------------------------------------------------------------------------

    [Fact]
    public async Task BytesTravelThroughTheProxyInBothDirections()
    {
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer();

        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(
            nat, statistics, () => ProxyOn(proxy.Port), () => null);

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port));

        Assert.Equal("HELLO SPLITLANE", await RoundTripAsync(client, "hello splitlane"));
        Assert.Equal(1, proxy.AcceptedConnections);
        Assert.Equal(echo.Port, proxy.LastRequestedPort);
    }

    [Fact]
    public async Task ByteCountersReflectWhatWasRelayed()
    {
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer();

        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(
            nat, statistics, () => ProxyOn(proxy.Port), () => null);

        listener.Start(0);

        using (var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port)))
        {
            await RoundTripAsync(client, "0123456789");
            client.Shutdown(SocketShutdown.Both);
        }

        await WaitForAsync(() => statistics.BytesSent >= 10 && statistics.BytesReceived >= 10);

        Assert.Equal(10UL, statistics.BytesSent);
        Assert.Equal(10UL, statistics.BytesReceived);
    }

    [Fact]
    public async Task ALargeTransferSurvivesIntact()
    {
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer();

        var nat = new NatTable();
        await using var listener = new RedirectListener(
            nat, new EngineStatistics(), () => ProxyOn(proxy.Port), () => null);

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port));

        var payload = new string('a', 200_000);
        await client.SendAsync(Encoding.UTF8.GetBytes(payload), SocketFlags.None);

        var received = new StringBuilder();
        var buffer = new byte[16 * 1024];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        while (received.Length < payload.Length)
        {
            var read = await client.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);
            if (read == 0)
            {
                break;
            }

            received.Append(Encoding.UTF8.GetString(buffer, 0, read));
        }

        Assert.Equal(payload.Length, received.Length);
        Assert.Equal(new string('A', 200_000), received.ToString());
    }

    // ---- Hostname preference -------------------------------------------------------------------

    [Fact]
    public async Task AKnownHostnameIsSentAsAtypDomainSoTheUpstreamResolvesIt()
    {
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer();

        var nat = new NatTable();
        await using var listener = new RedirectListener(
            nat, new EngineStatistics(), () => ProxyOn(proxy.Port), () => null);

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port, "localhost"));
        await RoundTripAsync(client, "x");

        Assert.Equal(0x03, proxy.LastRequestedAddressType);
        Assert.Equal("localhost", proxy.LastRequestedHost);
    }

    [Fact]
    public async Task WithoutAKnownHostnameTheAddressIsSentAsALiteral()
    {
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer();

        var nat = new NatTable();
        await using var listener = new RedirectListener(
            nat, new EngineStatistics(), () => ProxyOn(proxy.Port), () => null);

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port));
        await RoundTripAsync(client, "x");

        Assert.Equal(0x01, proxy.LastRequestedAddressType);
        Assert.Equal("127.0.0.1", proxy.LastRequestedHost);
    }

    [Fact]
    public async Task HostnamePreferenceCanBeTurnedOff()
    {
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer();

        var nat = new NatTable();
        await using var listener = new RedirectListener(
            nat,
            new EngineStatistics(),
            () => ProxyOn(proxy.Port) with { PreferHostnames = false },
            () => null);

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port, "localhost"));
        await RoundTripAsync(client, "x");

        Assert.Equal(0x01, proxy.LastRequestedAddressType);
    }

    // ---- Authentication ---------------------------------------------------------------------

    [Fact]
    public async Task AuthenticationSucceedsWithTheRightCredential()
    {
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer(new Socks5TestServerOptions
        {
            RequireAuthentication = true,
            Username = "user",
            Password = "pass",
        });

        var nat = new NatTable();
        await using var listener = new RedirectListener(
            nat,
            new EngineStatistics(),
            () => ProxyOn(proxy.Port, new CredentialReference { Username = "user" }),
            () => new Socks5Credential("user", "pass"));

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port));

        Assert.Equal("AUTH OK", await RoundTripAsync(client, "auth ok"));
    }

    [Fact]
    public async Task AuthenticationFailureFailsClosedRatherThanFallingBackToDirect()
    {
        // The defining behaviour of the product. A selected application whose proxy rejects it must
        // see a dead connection, not a working one that quietly went direct.
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer(new Socks5TestServerOptions
        {
            RequireAuthentication = true,
            Username = "user",
            Password = "correct",
        });

        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(
            nat,
            statistics,
            () => ProxyOn(proxy.Port, new CredentialReference { Username = "user" }),
            () => new Socks5Credential("user", "wrong"));

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port));
        await client.SendAsync("hello"u8.ToArray(), SocketFlags.None);

        var buffer = new byte[64];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var read = 0;
        try
        {
            read = await client.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);
        }
        catch (SocketException)
        {
            // A reset is an equally valid way for the connection to die.
        }

        Assert.Equal(0, read);

        await WaitForAsync(() => statistics.RecentActivity(10)
            .Any(c => c.State == ConnectionState.Failed));

        var failure = statistics.RecentActivity(10).First(c => c.State == ConnectionState.Failed);
        Assert.Equal(ConnectionErrorCategory.AuthenticationFailed, failure.Error);
    }

    // ---- Failure paths ------------------------------------------------------------------------

    [Fact]
    public async Task AConnectionFromAnUnknownPortIsRefusedRatherThanProxied()
    {
        // Without this, the redirect listener would be an open proxy for every local process.
        await using var proxy = new Socks5TestServer();

        var nat = new NatTable();
        await using var listener = new RedirectListener(
            nat, new EngineStatistics(), () => ProxyOn(proxy.Port), () => null);

        listener.Start(0);

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.Port));

        var buffer = new byte[16];
        var read = 0;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            read = await client.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);
        }
        catch (SocketException)
        {
        }

        Assert.Equal(0, read);
        Assert.Equal(0, proxy.AcceptedConnections);
    }

    [Fact]
    public async Task AnUnreachableProxyIsReportedAsUnreachable()
    {
        var nat = new NatTable();
        var statistics = new EngineStatistics();

        // Port 1 on loopback: nothing listens there.
        await using var listener = new RedirectListener(
            nat, statistics, () => ProxyOn(1), () => null);

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(9999));

        await WaitForAsync(() => statistics.RecentActivity(10).Any(c => c.State == ConnectionState.Failed));

        var failure = statistics.RecentActivity(10).First(c => c.State == ConnectionState.Failed);
        Assert.Equal(ConnectionErrorCategory.UpstreamUnreachable, failure.Error);
    }

    [Fact]
    public async Task AProxyThatRejectsTheDestinationIsReportedAsSuch()
    {
        await using var proxy = new Socks5TestServer(new Socks5TestServerOptions { RejectWith = 0x02 });

        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(
            nat, statistics, () => ProxyOn(proxy.Port), () => null);

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(9999));

        await WaitForAsync(() => statistics.RecentActivity(10).Any(c => c.State == ConnectionState.Failed));

        var failure = statistics.RecentActivity(10).First(c => c.State == ConnectionState.Failed);
        Assert.Equal(ConnectionErrorCategory.RejectedByProxy, failure.Error);
    }

    [Fact]
    public async Task AStallingProxyTimesOutRatherThanHangingForever()
    {
        await using var proxy = new Socks5TestServer(new Socks5TestServerOptions { StallAfterGreeting = true });

        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(
            nat,
            statistics,
            () => ProxyOn(proxy.Port) with { HandshakeTimeoutMilliseconds = 500 },
            () => null);

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(9999));

        await WaitForAsync(() => statistics.RecentActivity(10).Any(c => c.State == ConnectionState.Failed));

        var failure = statistics.RecentActivity(10).First(c => c.State == ConnectionState.Failed);
        Assert.Equal(ConnectionErrorCategory.TimedOut, failure.Error);
    }

    [Fact]
    public async Task BytesCoalescedWithTheConnectReplyAreDeliveredNotDropped()
    {
        // The subtle one: a server that puts the first response bytes in the same segment as its
        // CONNECT reply. Dropping them looks like a rare, unreproducible truncation.
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer(new Socks5TestServerOptions
        {
            CoalesceWithReply = "PREFIX:"u8.ToArray(),
        });

        var nat = new NatTable();
        await using var listener = new RedirectListener(
            nat, new EngineStatistics(), () => ProxyOn(proxy.Port), () => null);

        listener.Start(0);

        using var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port));

        var buffer = new byte[64];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var read = await client.ReceiveAsync(buffer, SocketFlags.None, timeout.Token);

        Assert.Equal("PREFIX:", Encoding.UTF8.GetString(buffer, 0, read));
    }

    // ---- Activity bookkeeping -------------------------------------------------------------------

    [Fact]
    public async Task ASuccessfulConnectionIsRecordedAsClosedWithItsByteCounts()
    {
        await using var echo = new EchoServer();
        await using var proxy = new Socks5TestServer();

        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(
            nat, statistics, () => ProxyOn(proxy.Port), () => null);

        listener.Start(0);

        using (var client = await ConnectThroughListenerAsync(listener, nat, EntryFor(echo.Port, "localhost")))
        {
            await RoundTripAsync(client, "abc");
            client.Shutdown(SocketShutdown.Both);
        }

        await WaitForAsync(() => statistics.RecentActivity(10).Any(c => c.State == ConnectionState.Closed));

        var record = statistics.RecentActivity(10).First(c => c.State == ConnectionState.Closed);
        Assert.Equal("Codex", record.ApplicationName);
        Assert.Equal("localhost", record.DestinationHost);
        Assert.Equal(RouteAction.Proxy, record.Route);
        Assert.Equal(3UL, record.BytesSent);
        Assert.NotNull(record.Duration);
        Assert.Equal(0, statistics.ActiveProxiedFlows);
    }

    private static async Task WaitForAsync(Func<bool> condition, int timeoutMilliseconds = 15000)
    {
        var deadline = Environment.TickCount64 + timeoutMilliseconds;
        while (Environment.TickCount64 < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(25);
        }

        Assert.Fail("Condition was not met before the timeout");
    }
}
