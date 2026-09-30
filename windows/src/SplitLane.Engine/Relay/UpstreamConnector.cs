using System.Diagnostics;
using System.Net.Sockets;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy;
using SplitLane.Core.Proxy.Http;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Engine.Relay;

/// <summary>
/// Opens a tunnel through the configured upstream, whichever protocol it speaks.
/// </summary>
/// <remarks>
/// The one place the proxy's type is looked at for a TCP connection. Everything above it - the
/// redirect listener, the proxy test - gets an <see cref="UpstreamTunnel"/> or an
/// <see cref="UpstreamProxyException"/>, and never has to know which protocol produced it.
/// </remarks>
public sealed class UpstreamConnector
{
    private readonly HttpAuthenticationMemory _authentication = new();

    /// <summary>
    /// The name to ask the proxy for: the hostname the application resolved, when there is one and
    /// the configuration prefers it, otherwise the address it connected to.
    /// </summary>
    /// <remarks>
    /// A name that cannot be written into an HTTP request line - it came out of a DNS answer, and a
    /// DNS label can hold anything - is replaced by the address rather than refused.
    /// </remarks>
    public static string TargetHost(ProxyConfiguration proxy, string? hostname, string address)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        if (!proxy.PreferHostnames || string.IsNullOrEmpty(hostname))
        {
            return address;
        }

        return proxy.Type == ProxyProtocolType.Http && !HttpConnectRequest.IsValidHost(hostname)
            ? address
            : hostname;
    }

    /// <summary>Opens a tunnel to <paramref name="host"/>:<paramref name="port"/>.</summary>
    /// <exception cref="UpstreamProxyException">Every failure, for either protocol.</exception>
    public async Task<UpstreamTunnel> ConnectAsync(
        ProxyConfiguration proxy,
        string host,
        ushort port,
        Socks5Credential? credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentException.ThrowIfNullOrEmpty(host);

        if (proxy.Type == ProxyProtocolType.Http)
        {
            if (!HttpConnectRequest.IsValidHost(host))
            {
                throw new UpstreamProxyException(
                    ConnectionErrorCategory.InternalError,
                    UpstreamStage.Connect,
                    "The destination cannot be named in a CONNECT request")
                {
                    Protocol = ProxyProtocolType.Http,
                    Endpoint = proxy.Endpoint.DisplayString,
                };
            }

            return await HttpConnectClient
                .ConnectAsync(proxy, host, port, credential, _authentication, cancellationToken)
                .ConfigureAwait(false);
        }

        var stopwatch = Stopwatch.StartNew();
        Socks5Address? destination = null;

        try
        {
            destination = Socks5Address.Destination(host, null);

            var tunnel = await Socks5Client
                .ConnectAsync(proxy, destination.Value, port, credential, cancellationToken)
                .ConfigureAwait(false);

            // Ownership of the socket moves to the new record; the SOCKS5 one is not disposed.
            return new UpstreamTunnel(tunnel.Socket, tunnel.Info.LeftoverBytes, tunnel.ElapsedMilliseconds);
        }
        catch (Socks5Exception ex)
        {
            throw new UpstreamProxyException(ex.ToCategory(), ex.Stage ?? UpstreamStage.Connect, ex.Message, ex)
            {
                Protocol = ProxyProtocolType.Socks5,
                Endpoint = proxy.Endpoint.DisplayString,
                Destination = destination is { } named ? $"{named}:{port}" : $"{host}:{port}",
                ElapsedMilliseconds = stopwatch.Elapsed.TotalMilliseconds,
                OsError = (ex.InnerException as SocketException)?.SocketErrorCode.ToString(),
            };
        }
    }
}
