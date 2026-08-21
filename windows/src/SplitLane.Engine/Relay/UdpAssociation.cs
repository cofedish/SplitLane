using System.Net;
using System.Net.Sockets;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Engine.Relay;

/// <summary>A datagram that came back through the proxy.</summary>
/// <param name="RemoteAddress">Who sent it, as the proxy reported.</param>
/// <param name="RemotePort">The port it came from.</param>
/// <param name="Payload">The datagram itself, with the proxy's header already removed.</param>
public readonly record struct RelayedDatagram(IPAddress RemoteAddress, ushort RemotePort, byte[] Payload);

/// <summary>
/// One application socket's UDP association with the proxy.
/// </summary>
/// <remarks>
/// <para>
/// SOCKS5 relays datagrams through an association rather than a connection: a TCP control channel is
/// opened and asked for UDP ASSOCIATE, the proxy answers with an address to send datagrams to, and
/// that address stays usable for as long as the control channel is held open. Closing the TCP
/// connection tears the association down - so it is kept, doing nothing, for the life of the
/// association. A relay that dropped it would work for a few seconds and then stop.
/// </para>
/// <para>
/// One association per application socket, not one per destination. A voice client sends to one
/// server and a game may send to several; both are the same socket to the application, and the
/// replies have to arrive back on it.
/// </para>
/// </remarks>
public sealed class UdpAssociation : IAsyncDisposable
{
    private readonly Socks5Tunnel _control;
    private readonly UdpClient _socket;
    private readonly IPEndPoint _relay;
    private readonly CancellationTokenSource _stopping = new();
    private readonly Task _receiveLoop;

    private UdpAssociation(
        Socks5Tunnel control,
        UdpClient socket,
        IPEndPoint relay,
        Action<RelayedDatagram> onDatagram)
    {
        _control = control;
        _socket = socket;
        _relay = relay;
        _receiveLoop = Task.Run(() => ReceiveLoopAsync(onDatagram, _stopping.Token));
    }

    /// <summary>When a datagram last passed in either direction, for idle eviction.</summary>
    public DateTimeOffset LastUsed { get; private set; } = DateTimeOffset.UtcNow;

    /// <summary>Opens an association with the proxy.</summary>
    /// <param name="proxy">Where the proxy is.</param>
    /// <param name="credential">Its credentials, when it wants them.</param>
    /// <param name="onDatagram">Called for every datagram that comes back.</param>
    /// <param name="cancellationToken">Bounds the handshake.</param>
    public static async Task<UdpAssociation> OpenAsync(
        ProxyConfiguration proxy,
        Socks5Credential? credential,
        Action<RelayedDatagram> onDatagram,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentNullException.ThrowIfNull(onDatagram);

        // Zeros for the address datagrams will come from. RFC 1928 allows it, and it is the honest
        // answer: the local port is not chosen until the socket below is bound, and a proxy that
        // pinned the association to an address would reject every datagram after a rebind anyway.
        var control = await Socks5Client.ConnectAsync(
            proxy,
            Socks5Address.FromIPv4([0, 0, 0, 0]),
            0,
            credential,
            cancellationToken,
            Socks5Command.UdpAssociate).ConfigureAwait(false);

        try
        {
            var relay = ResolveRelay(control, proxy);
            var socket = new UdpClient(new IPEndPoint(IPAddress.Any, 0));

            return new UdpAssociation(control, socket, relay, onDatagram);
        }
        catch
        {
            control.Dispose();
            throw;
        }
    }

    /// <summary>Sends one datagram to a destination through the proxy.</summary>
    public async Task SendAsync(IPAddress destination, ushort port, ReadOnlyMemory<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(destination);

        var address = destination.AddressFamily == AddressFamily.InterNetworkV6
            ? Socks5Address.FromIPv6(destination.GetAddressBytes())
            : Socks5Address.FromIPv4(destination.GetAddressBytes());

        var datagram = Socks5Datagram.Encode(address, port, payload.Span);

        LastUsed = DateTimeOffset.UtcNow;
        await _socket.SendAsync(datagram, datagram.Length, _relay).ConfigureAwait(false);
    }

    /// <summary>
    /// Where the proxy said to send datagrams.
    /// </summary>
    /// <remarks>
    /// A proxy commonly answers with <c>0.0.0.0</c>, meaning "the address you already reached me on".
    /// Taking that literally sends every datagram to a wildcard address and nothing works, so the
    /// proxy's own address stands in - which is what the reply means, and what every client does.
    /// </remarks>
    private static IPEndPoint ResolveRelay(Socks5Tunnel control, ProxyConfiguration proxy)
    {
        var port = control.Info.BoundPort;

        if (port == 0)
        {
            throw new Socks5Exception(
                Socks5ErrorCode.MalformedResponse,
                "the proxy granted a UDP association without a port to send datagrams to");
        }

        // Whatever the proxy named, if it named anything usable.
        var bound = control.Info.BoundAddress;

        if (bound.Type is Socks5AddressType.IPv4 or Socks5AddressType.IPv6)
        {
            var address = new IPAddress(bound.Octets);

            if (!address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))
            {
                return new IPEndPoint(address, port);
            }
        }

        // Most proxies answer 0.0.0.0, meaning "the address you already reached me on". Taking that
        // literally sends every datagram to a wildcard and nothing works, so the address the control
        // channel is connected to stands in - which is what the reply means.
        var remote = (control.Socket.RemoteEndPoint as IPEndPoint)?.Address
                     ?? IPAddress.Parse(proxy.Endpoint.Host);

        return new IPEndPoint(remote, port);
    }

    private async Task ReceiveLoopAsync(Action<RelayedDatagram> onDatagram, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult received;

            try
            {
                received = await _socket.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                // A datagram whose destination refused it produces this on Windows. It concerns one
                // datagram, not the association, so the loop keeps going.
                continue;
            }

            if (!Socks5Datagram.TryDecode(received.Buffer, out var source, out var port, out var offset))
            {
                continue;
            }

            LastUsed = DateTimeOffset.UtcNow;

            onDatagram(new RelayedDatagram(
                new IPAddress(source),
                port,
                received.Buffer[offset..]));
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        _socket.Dispose();

        try
        {
            await _receiveLoop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _control.Dispose();
        _stopping.Dispose();
    }
}
