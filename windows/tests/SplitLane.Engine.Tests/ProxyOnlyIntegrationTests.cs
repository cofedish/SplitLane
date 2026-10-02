using System.Net;
using System.Net.Sockets;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Relay;
using SplitLane.Engine.Runtime;
using SplitLane.Testbed.Socks5;

namespace SplitLane.Engine.Tests;

public sealed class ProxyOnlyIntegrationTests
{
    [Theory]
    [InlineData("unreachable")]
    [InlineData("timeout")]
    [InlineData("authentication")]
    [InlineData("rejected")]
    [InlineData("closed")]
    public async Task ProxyFailureNeverConnectsDirectlyToListeningOrigin(string scenario)
    {
        // A reachable origin would expose a fallback as a pending accepted connection, even if
        // the client subsequently times out. This tests the relay, not driver interception.
        using var origin = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        origin.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        origin.Listen(8);
        var originPort = (ushort)((IPEndPoint)origin.LocalEndPoint!).Port;

        await using var proxy = new Socks5TestServer(new Socks5TestServerOptions
        {
            StallAfterGreeting = scenario == "timeout",
            RequireAuthentication = scenario == "authentication",
            Username = "test-user",
            Password = "correct-test-password",
            RejectWith = scenario == "rejected" ? (byte)0x02 : null,
        });
        using var unavailable = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        unavailable.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        // Reserved but not listening: no assumed fixed port and no unrelated local server.
        using var closingProxy = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        closingProxy.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        closingProxy.Listen(1);
        var closeTask = scenario == "closed" ? CloseDuringGreetingAsync(closingProxy) : Task.CompletedTask;
        var proxyPort = scenario switch
        {
            "unreachable" => (ushort)((IPEndPoint)unavailable.LocalEndPoint!).Port,
            "closed" => (ushort)((IPEndPoint)closingProxy.LocalEndPoint!).Port,
            _ => proxy.Port,
        };

        var configuration = ProxyConfiguration.Default with
        {
            Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = proxyPort },
            HandshakeTimeoutMilliseconds = scenario == "timeout" ? 300 : 5000,
            Credential = scenario == "authentication" ? new CredentialReference { Username = "test-user" } : null,
        };
        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(nat, statistics, () => configuration,
            () => scenario == "authentication" ? new Socks5Credential("test-user", "wrong-test-password") : null);
        listener.Start(0);
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = (ushort)((IPEndPoint)client.LocalEndPoint!).Port;
        nat.Record(port, new NatEntry(IPAddress.Loopback, IPAddress.Loopback, originPort,
            (uint)Environment.ProcessId, @"C:\Tests\client.exe", "Test client", null, DateTimeOffset.UtcNow)
        {
            Action = RouteAction.ProxyOnly,
            RuleKey = "*.example.com",
        });
        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.Port));

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!statistics.RecentActivity(10).Any(record => record.State == ConnectionState.Failed))
        {
            await Task.Delay(20, deadline.Token);
        }

        var failure = Assert.Single(statistics.RecentActivity(10), record => record.State == ConnectionState.Failed);
        Assert.Equal(RouteAction.ProxyOnly, failure.Route);
        if (scenario != "closed")
        {
            Assert.Equal(scenario switch
            {
                "timeout" => ConnectionErrorCategory.TimedOut,
                "authentication" => ConnectionErrorCategory.AuthenticationFailed,
                "rejected" => ConnectionErrorCategory.RejectedByProxy,
                _ => ConnectionErrorCategory.UpstreamUnreachable,
            }, failure.Error);
        }
        Assert.False(origin.Poll(0, SelectMode.SelectRead), "A direct connection reached the origin listener");
        Assert.Equal(0UL, statistics.BytesSent);
        await closeTask.WaitAsync(deadline.Token);
    }

    private static async Task CloseDuringGreetingAsync(Socket listener)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var client = await listener.AcceptAsync(deadline.Token);
        await client.ReceiveAsync(new byte[32], SocketFlags.None, deadline.Token);
        // Dispose closes an actual established proxy connection during its handshake.
    }
}
