using System.Net;
using System.Net.Sockets;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy;

namespace SplitLane.Engine.Relay;

/// <summary>
/// Opens TCP to the proxy, resolving its name as a separate, reported step.
/// </summary>
/// <remarks>
/// <c>Socket.ConnectAsync(host, port)</c> does both at once, and a failure or a timeout then cannot
/// say whether the proxy's name did not resolve or its address did not answer. Split, the stage
/// callback tells the caller which one it is waiting on.
/// </remarks>
internal static class UpstreamSocket
{
    /// <summary>Resolves the endpoint if it is a name, then connects to the first address that accepts.</summary>
    /// <exception cref="SocketException">Resolution or connection failed.</exception>
    public static async Task<Socket> ConnectAsync(
        ProxyEndpoint endpoint,
        Action<UpstreamStage> stage,
        CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        if (IPAddress.TryParse(endpoint.Host.Trim('[', ']'), out var literal))
        {
            addresses = [literal];
        }
        else
        {
            stage(UpstreamStage.Resolve);
            addresses = await Dns.GetHostAddressesAsync(endpoint.Host, cancellationToken).ConfigureAwait(false);
            if (addresses.Length == 0)
            {
                throw new SocketException((int)SocketError.HostNotFound);
            }
        }

        stage(UpstreamStage.TcpConnect);

        // Dual-mode, so one socket reaches whichever family the name resolved to.
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp)
        {
            // Nagle would hold the request back waiting for more, adding a round trip's worth of
            // latency to every relayed connection.
            NoDelay = true,
        };

        try
        {
            await socket.ConnectAsync(addresses, endpoint.Port, cancellationToken).ConfigureAwait(false);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
