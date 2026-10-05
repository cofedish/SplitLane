using System.Net;
using System.Net.Sockets;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;
using SplitLane.Engine.Relay;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-008: the UDP relay accepts datagrams only from the peer it expects - the association socket
/// only from the relay the proxy named, a lane only from the application it stands in for - and a lane
/// socket never relays what was queued in it before it was handed out.
/// </summary>
[Trait("Category", "Security")]
public sealed class UdpRelayPeerSecurityTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(3);

    [Fact]
    public async Task A_datagram_from_the_relay_is_accepted()
    {
        await using var server = new FakeAssociateServer();
        var received = new TaskCompletionSource<RelayedDatagram>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var association = await Open(server, d => received.TrySetResult(d));

        await server.Relay.SendAsync(Reply([9, 9, 9]), association.LocalEndPoint);

        var datagram = await received.Task.WaitAsync(Wait);
        Assert.Equal([9, 9, 9], datagram.Payload);
    }

    [Theory]
    [InlineData("127.0.0.2")] // another address
    [InlineData("127.0.0.1")] // the relay's address, another port
    public async Task A_datagram_from_anyone_but_the_relay_is_refused(string from)
    {
        await using var server = new FakeAssociateServer();
        var received = new TaskCompletionSource<RelayedDatagram>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var association = await Open(server, d => received.TrySetResult(d));

        using var forger = new UdpClient(new IPEndPoint(IPAddress.Parse(from), 0));
        await forger.SendAsync(Reply([6, 6, 6]), association.LocalEndPoint);

        // And a genuine one afterwards, so "nothing arrived" cannot be mistaken for a dead association.
        await server.Relay.SendAsync(Reply([1]), association.LocalEndPoint);

        var first = await received.Task.WaitAsync(Wait);
        Assert.Equal([1], first.Payload);
    }

    [Fact]
    public async Task A_malformed_datagram_from_the_relay_is_refused()
    {
        await using var server = new FakeAssociateServer();
        var received = new TaskCompletionSource<RelayedDatagram>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var association = await Open(server, d => received.TrySetResult(d));

        await server.Relay.SendAsync(new byte[] { 0xFF, 0xFF }, association.LocalEndPoint);
        await server.Relay.SendAsync(Reply([2]), association.LocalEndPoint);

        Assert.Equal([2], (await received.Task.WaitAsync(Wait)).Payload);
    }

    [Fact]
    public async Task The_association_socket_is_not_bound_to_every_interface()
    {
        await using var server = new FakeAssociateServer();
        await using var association = await Open(server, _ => { });

        Assert.Equal(IPAddress.Loopback, association.LocalEndPoint.Address);
        Assert.Equal(server.RelayEndPoint, association.Relay);
    }

    [Theory]
    [InlineData("127.0.0.1", "198.51.100.7", false)] // loopback relay for a remote proxy
    [InlineData("169.254.10.10", "198.51.100.7", false)]
    [InlineData("255.255.255.255", "198.51.100.7", false)]
    [InlineData("224.0.0.251", "198.51.100.7", false)]
    [InlineData("fe80::1", "2001:db8::7", false)]
    [InlineData("127.0.0.1", "127.0.0.1", true)]     // a local proxy's local relay
    [InlineData("198.51.100.8", "198.51.100.7", true)] // a relay on another host of the proxy's
    public void Only_addresses_a_proxy_may_use_are_accepted_as_its_relay(string relay, string proxy, bool accepted) =>
        Assert.Equal(accepted, UdpAssociation.IsAcceptableRelay(IPAddress.Parse(relay), IPAddress.Parse(proxy)));

    [Fact]
    public async Task A_proxy_that_names_a_forbidden_relay_gets_no_association()
    {
        // The proxy is on loopback here, so name something it may never use.
        await using var server = new FakeAssociateServer(boundAddress: IPAddress.Parse("169.254.1.1"));

        await Assert.ThrowsAsync<Socks5Exception>(() => Open(server, _ => { }));
    }

    // ---- Lanes ------------------------------------------------------------------------------------

    [Theory]
    [InlineData("127.0.0.1", 50000, true)]
    [InlineData("127.0.0.1", 50001, false)]
    [InlineData("127.0.0.2", 50000, false)]
    [InlineData("192.168.0.84", 50000, false)]
    public void A_lane_accepts_only_its_application(string address, int port, bool accepted)
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var lane = new UdpLane(socket, 1, applicationPort: 50000, new IPEndPoint(IPAddress.Parse("203.0.113.1"), 443));

        Assert.Equal(accepted, lane.IsFromApplication(new IPEndPoint(IPAddress.Parse(address), port)));
    }

    [Fact]
    public async Task A_lane_socket_handed_out_holds_nothing_queued_before()
    {
        using var pool = new UdpLanePool(size: 4);
        using var stranger = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

        // Queue datagrams in every free socket of the pool.
        for (var port = pool.BasePort; port <= pool.LastPort; port++)
        {
            await stranger.SendAsync(new byte[] { 1, 2, 3 }, new IPEndPoint(IPAddress.Loopback, port));
        }

        await Task.Delay(100);

        var acquired = pool.TryAcquire();
        Assert.NotNull(acquired);
        Assert.Equal(0, acquired.Value.Socket.Available);
    }

    // ---- Helpers ----------------------------------------------------------------------------------

    private static Task<UdpAssociation> Open(FakeAssociateServer server, Action<RelayedDatagram> onDatagram) =>
        UdpAssociation.OpenAsync(
            ProxyConfiguration.Default with
            {
                Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = server.Port },
                HandshakeTimeoutMilliseconds = 3000,
            },
            null,
            onDatagram,
            CancellationToken.None);

    /// <summary>A SOCKS5 UDP reply from 203.0.113.1:443 carrying the payload.</summary>
    private static byte[] Reply(byte[] payload) =>
        Socks5Datagram.Encode(Socks5Address.FromIPv4([203, 0, 113, 1]), 443, payload);

    /// <summary>
    /// Just enough SOCKS5 to grant a UDP association: no authentication, one ASSOCIATE, a relay socket
    /// on loopback. The control connection is held open for the life of the server.
    /// </summary>
    private sealed class FakeAssociateServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly List<Socket> _held = [];
        private readonly IPAddress? _boundAddress;
        private readonly Task _accepting;

        public FakeAssociateServer(IPAddress? boundAddress = null)
        {
            _boundAddress = boundAddress;
            Relay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Start();
            Port = (ushort)((IPEndPoint)_listener.LocalEndpoint).Port;
            _accepting = Task.Run(AcceptAsync);
        }

        public ushort Port { get; }

        public UdpClient Relay { get; }

        public IPEndPoint RelayEndPoint => (IPEndPoint)Relay.Client.LocalEndPoint!;

        private async Task AcceptAsync()
        {
            try
            {
                while (true)
                {
                    var client = await _listener.AcceptSocketAsync();
                    _held.Add(client);

                    var buffer = new byte[512];
                    await ReadExactly(client, buffer, 2);                 // VER NMETHODS
                    await ReadExactly(client, buffer, buffer[1]);         // METHODS
                    await client.SendAsync(new byte[] { 5, 0 });          // no authentication
                    await ReadExactly(client, buffer, 4);                 // VER CMD RSV ATYP
                    await ReadExactly(client, buffer, buffer[3] == 4 ? 18 : 6); // ADDR PORT

                    var bound = (_boundAddress ?? IPAddress.Loopback).GetAddressBytes();
                    var reply = new List<byte> { 5, 0, 0, 1 };
                    reply.AddRange(bound);
                    reply.Add((byte)(RelayEndPoint.Port >> 8));
                    reply.Add((byte)RelayEndPoint.Port);
                    await client.SendAsync(reply.ToArray());
                }
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
            {
            }
        }

        private static async Task ReadExactly(Socket socket, byte[] buffer, int count)
        {
            var offset = 0;
            while (offset < count)
            {
                var read = await socket.ReceiveAsync(buffer.AsMemory(offset, count - offset));
                if (read == 0)
                {
                    throw new SocketException();
                }

                offset += read;
            }
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            foreach (var socket in _held)
            {
                socket.Dispose();
            }

            Relay.Dispose();
            await _accepting;
        }
    }
}
