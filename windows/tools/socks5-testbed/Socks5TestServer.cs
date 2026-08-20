using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SplitLane.Testbed.Socks5;

/// <summary>How the test server should behave, so failure paths can be exercised.</summary>
public sealed record Socks5TestServerOptions
{
    /// <summary>Require username/password authentication.</summary>
    public bool RequireAuthentication { get; init; }

    /// <summary>The username the server accepts.</summary>
    public string? Username { get; init; }

    /// <summary>The password the server accepts.</summary>
    public string? Password { get; init; }

    /// <summary>Refuse every CONNECT with this reply code, instead of dialling.</summary>
    public byte? RejectWith { get; init; }

    /// <summary>Accept the greeting and then send nothing, to exercise the handshake timeout.</summary>
    public bool StallAfterGreeting { get; init; }

    /// <summary>
    /// Answer requests from the server itself instead of dialling the destination.
    /// </summary>
    /// <remarks>
    /// Set to a payload size in bytes to make the server behave as the origin as well as the proxy.
    ///
    /// <para>
    /// This is what makes a load test provable. The destination can then be an address that does not
    /// exist - TEST-NET, say - which is reachable only by going through the proxy. An application
    /// that succeeds must have been proxied, and one that fails must have gone DIRECT, so the
    /// control case needs no interpretation.
    /// </para>
    /// </remarks>
    public int? ServePayloadBytes { get; init; }

    /// <summary>
    /// Append these bytes to the CONNECT reply, in the same segment.
    /// </summary>
    /// <remarks>
    /// Reproduces the real-server behaviour of coalescing the reply with the first bytes of the
    /// relayed stream, which is the case a naive client silently truncates.
    /// </remarks>
    public byte[]? CoalesceWithReply { get; init; }
}

/// <summary>
/// A minimal but genuine SOCKS5 server for integration tests.
/// </summary>
/// <remarks>
/// Implements RFC 1928 CONNECT and RFC 1929 authentication, and actually dials the destination, so a
/// test that relays through it is exercising the whole path rather than a mock.
/// </remarks>
public sealed class Socks5TestServer : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _stopping = new();
    private readonly Socks5TestServerOptions _options;
    private readonly Task _acceptLoop;

    /// <summary>Starts a server on an ephemeral loopback port.</summary>
    public Socks5TestServer(Socks5TestServerOptions? options = null)
    {
        _options = options ?? new Socks5TestServerOptions();

        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(64);

        Port = (ushort)((IPEndPoint)_listener.LocalEndPoint!).Port;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_stopping.Token));
    }

    /// <summary>The port the server bound.</summary>
    public ushort Port { get; }

    /// <summary>How many connections have been accepted.</summary>
    public int AcceptedConnections { get; private set; }

    /// <summary>The destination named by the most recent CONNECT, as it arrived on the wire.</summary>
    public string? LastRequestedHost { get; private set; }

    /// <summary>The port named by the most recent CONNECT.</summary>
    public ushort LastRequestedPort { get; private set; }

    /// <summary>The address type tag of the most recent CONNECT.</summary>
    public byte LastRequestedAddressType { get; private set; }

    /// <summary>
    /// Raised for every CONNECT the server accepts, with the destination as it arrived on the wire.
    /// </summary>
    /// <remarks>
    /// This is how a divert-layer run is proved rather than assumed: if a selected application's
    /// connection really was intercepted and relayed, it shows up here, named, on the upstream side.
    /// </remarks>
    public event Action<string, ushort>? ConnectRequested;

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            AcceptedConnections++;
            _ = Task.Run(() => ServeAsync(client, cancellationToken), CancellationToken.None);
        }
    }

    private async Task ServeAsync(Socket client, CancellationToken cancellationToken)
    {
        Socket? upstream = null;

        try
        {
            var buffer = new byte[512];

            // Greeting.
            var read = await client.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read < 3 || buffer[0] != 0x05)
            {
                return;
            }

            var methodCount = buffer[1];
            var offered = buffer.AsSpan(2, Math.Min(methodCount, read - 2)).ToArray();

            if (_options.RequireAuthentication)
            {
                if (!offered.Contains<byte>(0x02))
                {
                    await client.SendAsync(new byte[] { 0x05, 0xFF }, cancellationToken).ConfigureAwait(false);
                    return;
                }

                await client.SendAsync(new byte[] { 0x05, 0x02 }, cancellationToken).ConfigureAwait(false);

                read = await client.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read < 2 || !CredentialsMatch(buffer.AsSpan(0, read)))
                {
                    await client.SendAsync(new byte[] { 0x01, 0x01 }, cancellationToken).ConfigureAwait(false);
                    return;
                }

                await client.SendAsync(new byte[] { 0x01, 0x00 }, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await client.SendAsync(new byte[] { 0x05, 0x00 }, cancellationToken).ConfigureAwait(false);
            }

            if (_options.StallAfterGreeting)
            {
                await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                return;
            }

            // CONNECT request.
            read = await client.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read < 7 || buffer[0] != 0x05 || buffer[1] != 0x01)
            {
                return;
            }

            var addressType = buffer[3];
            LastRequestedAddressType = addressType;

            string host;
            int cursor;

            switch (addressType)
            {
                case 0x01:
                    host = new IPAddress(buffer.AsSpan(4, 4)).ToString();
                    cursor = 8;
                    break;

                case 0x03:
                    var length = buffer[4];
                    host = Encoding.UTF8.GetString(buffer, 5, length);
                    cursor = 5 + length;
                    break;

                case 0x04:
                    host = new IPAddress(buffer.AsSpan(4, 16)).ToString();
                    cursor = 20;
                    break;

                default:
                    await client.SendAsync(Reply(0x08), cancellationToken).ConfigureAwait(false);
                    return;
            }

            var port = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(cursor, 2));
            LastRequestedHost = host;
            LastRequestedPort = port;
            ConnectRequested?.Invoke(host, port);

            if (_options.RejectWith is { } rejection)
            {
                await client.SendAsync(Reply(rejection), cancellationToken).ConfigureAwait(false);
                return;
            }

            if (_options.ServePayloadBytes is { } payloadSize)
            {
                // Accept the tunnel, then answer as the origin would. The destination is never
                // dialled, so it does not have to exist.
                await client.SendAsync(Reply(0x00), cancellationToken).ConfigureAwait(false);
                await ServePayloadAsync(client, payloadSize, cancellationToken).ConfigureAwait(false);
                return;
            }

            upstream = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

            try
            {
                await upstream.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException)
            {
                await client.SendAsync(Reply(0x05), cancellationToken).ConfigureAwait(false);
                return;
            }

            var reply = Reply(0x00);
            if (_options.CoalesceWithReply is { Length: > 0 } extra)
            {
                reply = [.. reply, .. extra];
            }

            await client.SendAsync(reply, cancellationToken).ConfigureAwait(false);

            await Task.WhenAll(
                PumpAsync(client, upstream, cancellationToken),
                PumpAsync(upstream, client, cancellationToken)).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        finally
        {
            upstream?.Dispose();
            client.Dispose();
        }
    }

    /// <summary>Reads an HTTP request and answers it with a payload of the requested size.</summary>
    private static async Task ServePayloadAsync(Socket client, int payloadSize, CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        var request = new StringBuilder();

        // Read to the end of the headers. One receive is not enough: under load a request arrives
        // split across segments, and stopping early would answer a request nobody finished sending.
        while (!request.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
        {
            var read = await client.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return;
            }

            request.Append(Encoding.ASCII.GetString(buffer, 0, read));

            if (request.Length > 16384)
            {
                return;
            }
        }

        var payload = new byte[payloadSize];
        Random.Shared.NextBytes(payload);

        var header = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/octet-stream\r\n" +
            $"Content-Length: {payloadSize}\r\n" +
            "Connection: close\r\n" +
            "\r\n");

        await SendAllAsync(client, header, cancellationToken).ConfigureAwait(false);
        await SendAllAsync(client, payload, cancellationToken).ConfigureAwait(false);

        try
        {
            client.Shutdown(SocketShutdown.Send);
        }
        catch (SocketException)
        {
        }
    }

    private static async Task SendAllAsync(Socket socket, byte[] data, CancellationToken cancellationToken)
    {
        var sent = 0;
        while (sent < data.Length)
        {
            var written = await socket.SendAsync(data.AsMemory(sent), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);

            if (written == 0)
            {
                return;
            }

            sent += written;
        }
    }

    private bool CredentialsMatch(ReadOnlySpan<byte> message)
    {
        if (message.Length < 2 || message[0] != 0x01)
        {
            return false;
        }

        var usernameLength = message[1];
        if (message.Length < 2 + usernameLength + 1)
        {
            return false;
        }

        var username = Encoding.UTF8.GetString(message.Slice(2, usernameLength));
        var passwordLength = message[2 + usernameLength];

        if (message.Length < 3 + usernameLength + passwordLength)
        {
            return false;
        }

        var password = Encoding.UTF8.GetString(message.Slice(3 + usernameLength, passwordLength));

        return username == _options.Username && password == _options.Password;
    }

    private static byte[] Reply(byte code) => [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

    private static async Task PumpAsync(Socket from, Socket to, CancellationToken cancellationToken)
    {
        var buffer = new byte[16 * 1024];

        try
        {
            while (true)
            {
                var read = await from.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    try
                    {
                        to.Shutdown(SocketShutdown.Send);
                    }
                    catch (SocketException)
                    {
                    }

                    return;
                }

                await to.SendAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        _listener.Dispose();

        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _stopping.Dispose();
    }
}
