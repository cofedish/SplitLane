using System.Diagnostics;
using System.Net.Sockets;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Engine.Relay;

/// <summary>An open tunnel to the upstream, plus whatever arrived glued to the handshake.</summary>
/// <param name="Socket">The connected socket, owned by the caller from here on.</param>
/// <param name="Info">Handshake result.</param>
/// <param name="ElapsedMilliseconds">Connect plus handshake, for the proxy test and for logs.</param>
public sealed record Socks5Tunnel(Socket Socket, Socks5ConnectionInfo Info, double ElapsedMilliseconds) : IDisposable
{
    /// <summary>Closes the tunnel.</summary>
    public void Dispose() => Socket.Dispose();
}

/// <summary>
/// Drives the pure handshake state machine over a real socket.
/// </summary>
/// <remarks>
/// All the protocol lives in <see cref="Socks5Negotiator"/>; this type only supplies I/O and a
/// deadline. Keeping the split means every protocol edge case is covered by a unit test that never
/// opens a socket, and the only thing left to get wrong here is timing and cleanup.
/// </remarks>
public static class Socks5Client
{
    /// <summary>Bytes read per receive during the handshake. A SOCKS5 reply is never larger.</summary>
    private const int HandshakeBufferSize = 512;

    /// <summary>
    /// Connects to the upstream and asks it to open a tunnel to the destination.
    /// </summary>
    /// <remarks>
    /// The timeout covers connect <b>and</b> handshake together, because from the application's point
    /// of view they are one wait. A proxy that accepts TCP promptly and then never answers the
    /// greeting is exactly as broken as one that never accepts, and both must fail in bounded time
    /// rather than leaving the application's connection hanging.
    /// </remarks>
    public static async Task<Socks5Tunnel> ConnectAsync(
        ProxyConfiguration proxy,
        Socks5Address destination,
        ushort destinationPort,
        Socks5Credential? credential,
        CancellationToken cancellationToken,
        Socks5Command command = Socks5Command.Connect)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        var stopwatch = Stopwatch.StartNew();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(proxy.HandshakeTimeoutMilliseconds);

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);

        try
        {
            // Nagle would coalesce the greeting with nothing and add a round trip's worth of latency
            // to every single relayed connection.
            socket.NoDelay = true;

            await socket.ConnectAsync(proxy.Endpoint.Host, proxy.Endpoint.Port, timeout.Token)
                .ConfigureAwait(false);

            var negotiator = new Socks5Negotiator(destination, destinationPort, credential, command);
            var step = negotiator.Start();
            var buffer = new byte[HandshakeBufferSize];

            while (true)
            {
                switch (step.Kind)
                {
                    case Socks5StepKind.Send:
                        await SendAllAsync(socket, step.Bytes!, timeout.Token).ConfigureAwait(false);
                        step = new Socks5Step(Socks5StepKind.NeedMoreBytes);
                        break;

                    case Socks5StepKind.NeedMoreBytes:
                        var read = await socket.ReceiveAsync(buffer, SocketFlags.None, timeout.Token)
                            .ConfigureAwait(false);

                        if (read == 0)
                        {
                            // The upstream hung up mid-handshake. Reported as a transport failure
                            // rather than a protocol error: the common cause is a proxy that is
                            // starting, stopping, or refusing this client outright.
                            throw Socks5Exception.Transport("proxy closed the connection during the handshake");
                        }

                        step = negotiator.Receive(buffer.AsSpan(0, read));
                        break;

                    case Socks5StepKind.Established:
                        stopwatch.Stop();
                        var tunnel = new Socks5Tunnel(socket, step.Connection!, stopwatch.Elapsed.TotalMilliseconds);
                        socket = null!;
                        return tunnel;

                    default:
                        throw Socks5Exception.ProtocolViolation($"unexpected step {step.Kind}");
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            socket?.Dispose();
            throw Socks5Exception.TimedOut();
        }
        catch (OperationCanceledException)
        {
            socket?.Dispose();
            throw Socks5Exception.Cancelled();
        }
        catch (SocketException ex)
        {
            socket?.Dispose();
            throw Socks5Exception.Transport(ex.SocketErrorCode.ToString(), ex);
        }
        catch
        {
            socket?.Dispose();
            throw;
        }
    }

    /// <summary>Writes a buffer completely, because a partial send during a handshake desynchronises it.</summary>
    private static async Task SendAllAsync(Socket socket, byte[] bytes, CancellationToken cancellationToken)
    {
        var sent = 0;
        while (sent < bytes.Length)
        {
            var written = await socket
                .SendAsync(bytes.AsMemory(sent), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);

            if (written == 0)
            {
                throw Socks5Exception.Transport("proxy stopped accepting the handshake");
            }

            sent += written;
        }
    }
}
