using System.Net.Sockets;

namespace SplitLane.Engine.Relay;

/// <summary>How much moved, and which way.</summary>
/// <param name="BytesSent">Application to upstream.</param>
/// <param name="BytesReceived">Upstream to application.</param>
public readonly record struct RelayResult(ulong BytesSent, ulong BytesReceived);

/// <summary>
/// Pumps bytes between the application's socket and the upstream tunnel until either end closes.
/// </summary>
/// <remarks>
/// <para>
/// The two directions are independent tasks, and a half-close is propagated rather than treated as a
/// teardown. That matters for real protocols: an HTTP client that finishes its request and shuts
/// down its send side is still waiting for the response, and a relay that tore the whole connection
/// down on the first zero-length read would truncate it.
/// </para>
/// <para>
/// No payload is inspected, buffered beyond one read, or logged. The only thing this type learns
/// about the traffic is how many bytes there were.
/// </para>
/// </remarks>
public static class TcpRelay
{
    /// <summary>Per-direction buffer size.</summary>
    /// <remarks>
    /// Large enough that a bulk transfer is not syscall-bound, small enough that a few hundred idle
    /// connections do not pin megabytes. Buffers are rented from the shared pool rather than
    /// allocated, because this is the one hot path in the engine that runs per connection.
    /// </remarks>
    private const int BufferSize = 32 * 1024;

    /// <summary>Relays until both directions finish.</summary>
    public static async Task<RelayResult> RunAsync(
        Socket application,
        Socket upstream,
        ReadOnlyMemory<byte> upstreamPreamble,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(upstream);

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Bytes the proxy glued to its CONNECT reply belong to the application, and are delivered
        // before anything else is read.
        ulong received = 0;
        if (!upstreamPreamble.IsEmpty)
        {
            await SendAllAsync(application, upstreamPreamble, linked.Token).ConfigureAwait(false);
            received = (ulong)upstreamPreamble.Length;
        }

        // A reset or failure in either direction ends both (SL-SEC-017). An orderly half-close does not:
        // the other direction keeps running until it, too, is done.
        var toUpstream = PumpAsync(application, upstream, linked);
        var toApplication = PumpAsync(upstream, application, linked);

        var results = await Task.WhenAll(toUpstream, toApplication).ConfigureAwait(false);

        return new RelayResult(results[0], results[1] + received);
    }

    private static async Task<ulong> PumpAsync(Socket from, Socket to, CancellationTokenSource both)
    {
        var cancellationToken = both.Token;
        var buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(BufferSize);
        ulong total = 0;
        var aborted = false;

        try
        {
            while (true)
            {
                int read;
                try
                {
                    read = await from.ReceiveAsync(buffer, SocketFlags.None, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (SocketException)
                {
                    // A reset is a normal way for a connection to end, and it ends the other direction
                    // too: left running, it would hold both sockets until the far side gave up.
                    aborted = true;
                    break;
                }
                catch (ObjectDisposedException)
                {
                    aborted = true;
                    break;
                }

                if (read == 0)
                {
                    // Orderly half-close: tell the other end no more data is coming, and let the
                    // opposite direction keep running.
                    TryShutdownSend(to);
                    break;
                }

                if (!await SendAllAsync(to, buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false))
                {
                    aborted = true;
                    break;
                }

                total += (ulong)read;
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
            aborted = true;
        }
        catch (ObjectDisposedException)
        {
            aborted = true;
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
        }

        if (aborted)
        {
            await both.CancelAsync().ConfigureAwait(false);
            Abort(to);
        }

        return total;
    }

    /// <summary>Resets a socket, so the far end learns at once that the relay is gone.</summary>
    private static void Abort(Socket socket)
    {
        try
        {
            socket.LingerState = new LingerOption(true, 0);
            socket.Close();
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
        }
    }

    /// <summary>Sends everything, or reports that it could not.</summary>
    private static async Task<bool> SendAllAsync(Socket socket, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        var sent = 0;
        while (sent < data.Length)
        {
            var written = await socket.SendAsync(data[sent..], SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);

            if (written == 0)
            {
                // Nothing taken is a connection that can carry nothing more; silently returning used
                // to drop the rest of the data and carry on as though it had been delivered.
                return false;
            }

            sent += written;
        }

        return true;
    }

    private static void TryShutdownSend(Socket socket)
    {
        try
        {
            socket.Shutdown(SocketShutdown.Send);
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }
}
