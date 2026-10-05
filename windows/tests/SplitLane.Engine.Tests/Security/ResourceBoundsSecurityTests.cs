using System.Net;
using System.Net.Sockets;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Relay;
using SplitLane.Engine.Runtime;
using SplitLane.Platform;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-017: the engine's work queues, caches, timeouts, relays and port pools are bounded, and the
/// bounds fail closed.
/// </summary>
[Trait("Category", "Security")]
public sealed class ResourceBoundsSecurityTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(5);

    // ---- Handshake timeout ------------------------------------------------------------------------

    [Fact]
    public void A_handshake_timeout_beyond_the_limit_is_refused_when_saved()
    {
        var configuration = RuntimeConfiguration.Empty with
        {
            Proxy = ProxyConfiguration.Default with { HandshakeTimeoutMilliseconds = int.MaxValue },
        };

        Assert.Throws<ConfigurationValidationException>(() => ConfigurationValidator.Validate(configuration));
    }

    [Fact]
    public void A_handshake_timeout_beyond_the_limit_is_clamped_when_loaded_rather_than_refused()
    {
        var configuration = RuntimeConfiguration.Empty with
        {
            Proxy = ProxyConfiguration.Default with { HandshakeTimeoutMilliseconds = int.MaxValue },
        };

        var loaded = ConfigurationValidator.Sanitize(configuration);

        Assert.Equal(ConfigurationValidator.MaxHandshakeTimeoutMilliseconds, loaded.Proxy.HandshakeTimeoutMilliseconds);
    }

    // ---- Image catalog ----------------------------------------------------------------------------

    [Fact]
    public async Task A_full_catalog_evicts_its_oldest_records_not_all_of_them()
    {
        await using var catalog = new ImageCatalog((_, _) => null, _ => new FileStamp(1, 1, 1, 1), workers: 1, maxEntries: 16);

        ImageRecord? newest = null;
        for (var i = 0; i < 40; i++)
        {
            newest = catalog.Refresh($@"C:\Apps\app{i}.exe");
        }

        Assert.True(catalog.Count <= 16);
        Assert.Same(newest, catalog.Refresh(@"C:\Apps\app39.exe"));
    }

    [Fact]
    public async Task A_full_verification_queue_leaves_requests_retryable_instead_of_growing()
    {
        using var hold = new ManualResetEventSlim(false);
        await using var catalog = new ImageCatalog(
            (_, _) =>
            {
                hold.Wait(Wait);
                return null;
            },
            _ => new FileStamp(1, 1, 1, 1),
            workers: 1,
            maxEntries: 8192);

        var records = Enumerable.Range(0, ImageCatalog.QueueCapacity + 64)
            .Select(i => catalog.Refresh($@"C:\Apps\claim{i}.exe"))
            .ToList();

        foreach (var record in records)
        {
            catalog.RequestVerification(record, EvidenceNeeds.Signature);
        }

        // The last ones did not fit; they are not stuck as "queued" and will queue on their next request.
        Assert.True(records[^1].Request(EvidenceNeeds.Signature));
        hold.Set();
    }

    // ---- TCP relay --------------------------------------------------------------------------------

    [Fact]
    public async Task A_reset_on_one_side_ends_the_relay_and_the_other_side_hears_of_it()
    {
        var (application, applicationPeer) = await PairAsync();
        var (upstream, upstreamPeer) = await PairAsync();

        using (application)
        using (applicationPeer)
        using (upstream)
        {
            var relay = TcpRelay.RunAsync(application, upstream, ReadOnlyMemory<byte>.Empty, CancellationToken.None);

            // The proxy side resets.
            upstreamPeer.LingerState = new LingerOption(true, 0);
            upstreamPeer.Close();

            await relay.WaitAsync(Wait);

            // The application side learns the relay is gone instead of waiting forever.
            var buffer = new byte[1];
            var ended = await Task.Run(() =>
            {
                try
                {
                    return applicationPeer.Receive(buffer) == 0;
                }
                catch (SocketException)
                {
                    return true;
                }
            }).WaitAsync(Wait);

            Assert.True(ended);
        }
    }

    // ---- UDP lanes --------------------------------------------------------------------------------

    [Fact]
    public void A_released_lane_port_stays_bound_so_nobody_else_can_take_it()
    {
        using var pool = new UdpLanePool(size: 2);
        var acquired = pool.TryAcquire()!.Value;

        pool.Release(acquired.Port);

        Assert.Throws<SocketException>(() => new UdpClient(new IPEndPoint(IPAddress.Loopback, acquired.Port)).Dispose());
        Assert.Equal(acquired.Port, pool.TryAcquire()!.Value.Port);
    }

    // ---- Redirect listener ------------------------------------------------------------------------

    [Fact]
    public async Task Connections_beyond_the_relay_limit_are_refused()
    {
        await using var listener = new RedirectListener(
            new NatTable(), new EngineStatistics(), () => ProxyConfiguration.Default, () => null)
        {
            MaxConcurrentConnections = 0,
        };
        listener.Start(0);

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.Port));

        var buffer = new byte[1];
        var read = await client.ReceiveAsync(buffer, SocketFlags.None).WaitAsync(Wait);

        Assert.Equal(0, read);
        Assert.Equal(0, listener.ActiveConnections);
    }

    private static async Task<(Socket Near, Socket Far)> PairAsync()
    {
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(1);

        var far = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        var accepting = listener.AcceptAsync();
        await far.ConnectAsync(listener.LocalEndPoint!);
        var near = await accepting;
        return (near, far);
    }
}
