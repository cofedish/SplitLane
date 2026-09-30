using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace SplitLane.Testbed.Socks5;

/// <summary>How the HTTP test proxy should behave, so each failure path can be exercised.</summary>
public sealed record HttpProxyTestServerOptions
{
    /// <summary>Require <c>Basic</c> with these credentials.</summary>
    public (string Username, string Password)? Basic { get; init; }

    /// <summary>
    /// Require NTLM. The challenge is a real one, made by SSPI; the answer is checked for shape and
    /// for the username it carries, because verifying it would need a real account's password.
    /// </summary>
    public string? NtlmUsername { get; init; }

    /// <summary>
    /// With <see cref="NtlmUsername"/>, offer Negotiate as well as NTLM and refuse it, as a proxy with a
    /// Kerberos-only Negotiate helper does to a client that has no ticket for it.
    /// </summary>
    public bool OfferNegotiate { get; init; }

    /// <summary>Offer these challenges instead, and accept nothing: to test schemes SplitLane does not speak.</summary>
    public IReadOnlyList<string>? OfferOnly { get; init; }

    /// <summary>Close the connection after every 407, as some proxies do.</summary>
    public bool CloseAfter407 { get; init; }

    /// <summary>Send the 407 body chunked rather than with a Content-Length.</summary>
    public bool Chunked407 { get; init; }

    /// <summary>Answer every authorised CONNECT with this status instead of dialling.</summary>
    public int? RespondWith { get; init; }

    /// <summary>Read the request and never answer it, to exercise the stage timeouts.</summary>
    public bool StallOnConnect { get; init; }

    /// <summary>Read the authenticated request and never answer it.</summary>
    public bool StallOnAuthenticated { get; init; }

    /// <summary>Close the connection instead of answering the NTLM negotiate message.</summary>
    public bool CloseOnNtlmNegotiate { get; init; }

    /// <summary>Put these bytes in the same segment as the 200, the way a server that speaks first does.</summary>
    public byte[]? CoalesceWith200 { get; init; }

    /// <summary>Add a Content-Length to the 200, which a client must ignore rather than wait on.</summary>
    public bool ContentLengthOn200 { get; init; }
}

/// <summary>
/// A small but genuine HTTP proxy for integration tests: <c>CONNECT</c>, <c>407</c> and a tunnel.
/// </summary>
/// <remarks>
/// It reads a request to its blank line before it answers anything, as real proxies do. That is the
/// behaviour that turned a SOCKS5 greeting into a silent wait, and a test that proves SplitLane now
/// speaks HTTP has to be run against something that behaves like that. Authorised CONNECTs dial the
/// destination for real.
/// </remarks>
public sealed class HttpProxyTestServer : IAsyncDisposable
{
    private readonly Socket _listener;
    private readonly CancellationTokenSource _stopping = new();
    private readonly HttpProxyTestServerOptions _options;
    private readonly Task _acceptLoop;
    private readonly List<string> _requests = [];
    private readonly Lock _gate = new();
    private int _accepted;

    /// <summary>Starts a server on an ephemeral loopback port.</summary>
    public HttpProxyTestServer(HttpProxyTestServerOptions? options = null)
    {
        _options = options ?? new HttpProxyTestServerOptions();

        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(64);

        Port = (ushort)((IPEndPoint)_listener.LocalEndPoint!).Port;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_stopping.Token));
    }

    /// <summary>The port the server bound.</summary>
    public ushort Port { get; }

    /// <summary>TCP connections accepted.</summary>
    public int AcceptedConnections => Volatile.Read(ref _accepted);

    /// <summary>
    /// Every request, as <c>CONNECT target | Host | scheme-or-none</c>. The authorization value itself
    /// is never recorded - a test that needs to know it was right asserts on the outcome.
    /// </summary>
    public IReadOnlyList<string> Requests
    {
        get
        {
            lock (_gate)
            {
                return [.. _requests];
            }
        }
    }

    /// <summary>The username the last NTLM authenticate message carried, when there was one.</summary>
    public string? LastNtlmUser { get; private set; }

    /// <summary>The domain the last NTLM authenticate message carried.</summary>
    public string? LastNtlmDomain { get; private set; }

    /// <summary>Raised for every CONNECT, with the target as it arrived.</summary>
    public event Action<string>? ConnectRequested;

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await _listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            Interlocked.Increment(ref _accepted);
            _ = Task.Run(() => HandleAsync(client, cancellationToken), CancellationToken.None);
        }
    }

    private async Task HandleAsync(Socket client, CancellationToken cancellationToken)
    {
        NegotiateAuthentication? ntlm = null;
        var buffer = new List<byte>();

        try
        {
            while (true)
            {
                var head = await ReadHeadAsync(client, buffer, cancellationToken).ConfigureAwait(false);
                if (head is null)
                {
                    return;
                }

                var lines = head.Split("\r\n");
                var parts = lines[0].Split(' ');
                var headers = lines.Skip(1)
                    .Select(line => line.Split(':', 2))
                    .Where(pair => pair.Length == 2)
                    .ToLookup(pair => pair[0].Trim(), pair => pair[1].Trim(), StringComparer.OrdinalIgnoreCase);

                var authorization = headers["Proxy-Authorization"].FirstOrDefault();
                var scheme = authorization?.Split(' ', 2)[0];
                var target = parts.Length > 1 ? parts[1] : string.Empty;

                lock (_gate)
                {
                    _requests.Add($"{parts[0]} {target} | {headers["Host"].FirstOrDefault()} | {scheme ?? "none"}");
                }

                if (parts[0] != "CONNECT")
                {
                    await SendAsync(client, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n", cancellationToken).ConfigureAwait(false);
                    return;
                }

                ConnectRequested?.Invoke(target);

                if (_options.StallOnConnect || (_options.StallOnAuthenticated && authorization is not null))
                {
                    await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
                }

                // ---- Authentication ------------------------------------------------------------

                if (_options.OfferOnly is { } offers)
                {
                    await Send407Async(client, offers, cancellationToken).ConfigureAwait(false);
                    if (_options.CloseAfter407)
                    {
                        return;
                    }

                    continue;
                }

                if (_options.Basic is { } basic)
                {
                    var expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{basic.Username}:{basic.Password}"));
                    if (authorization != expected)
                    {
                        await Send407Async(client, ["Basic realm=\"splitlane-testbed\""], cancellationToken).ConfigureAwait(false);
                        if (_options.CloseAfter407)
                        {
                            return;
                        }

                        continue;
                    }
                }

                if (_options.NtlmUsername is not null)
                {
                    var token = authorization is not null && scheme!.Equals("NTLM", StringComparison.OrdinalIgnoreCase)
                        ? authorization.Split(' ', 2)[1]
                        : null;

                    var message = token is null ? null : Convert.FromBase64String(token);
                    var type = message is { Length: >= 12 } && Encoding.ASCII.GetString(message, 0, 8) == "NTLMSSP\0"
                        ? BitConverter.ToInt32(message, 8)
                        : 0;

                    if (type == 1)
                    {
                        if (_options.CloseOnNtlmNegotiate)
                        {
                            return;
                        }

                        ntlm?.Dispose();
                        ntlm = new NegotiateAuthentication(new NegotiateAuthenticationServerOptions { Package = "NTLM" });
                        var challenge = ntlm.GetOutgoingBlob(token, out _);
                        await Send407Async(client, [$"NTLM {challenge}"], cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    if (type != 3 || !ReadNtlmIdentity(message!, out var user, out var domain) ||
                        !string.Equals(user, _options.NtlmUsername, StringComparison.OrdinalIgnoreCase))
                    {
                        await Send407Async(client, _options.OfferNegotiate ? ["Negotiate", "NTLM"] : ["NTLM"], cancellationToken).ConfigureAwait(false);
                        if (_options.CloseAfter407)
                        {
                            return;
                        }

                        continue;
                    }

                    LastNtlmUser = user;
                    LastNtlmDomain = domain;
                }

                // ---- Tunnel --------------------------------------------------------------------

                if (_options.RespondWith is { } status)
                {
                    await SendAsync(client, $"HTTP/1.1 {status} Refused By Testbed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", cancellationToken).ConfigureAwait(false);
                    return;
                }

                var separator = target.LastIndexOf(':');
                var host = target[..separator].Trim('[', ']');
                var port = int.Parse(target[(separator + 1)..], System.Globalization.CultureInfo.InvariantCulture);

                Socket upstream;
                try
                {
                    upstream = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    await upstream.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
                }
                catch (SocketException)
                {
                    await SendAsync(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", cancellationToken).ConfigureAwait(false);
                    return;
                }

                using (upstream)
                {
                    var established = "HTTP/1.1 200 Connection established\r\n" +
                        (_options.ContentLengthOn200 ? "Content-Length: 100\r\n" : string.Empty) + "\r\n";
                    var reply = Encoding.ASCII.GetBytes(established).Concat(_options.CoalesceWith200 ?? []).ToArray();
                    await client.SendAsync(reply, cancellationToken).ConfigureAwait(false);

                    if (buffer.Count > 0)
                    {
                        await upstream.SendAsync(buffer.ToArray(), cancellationToken).ConfigureAwait(false);
                    }

                    await Task.WhenAll(PumpAsync(client, upstream, cancellationToken), PumpAsync(upstream, client, cancellationToken))
                        .ConfigureAwait(false);
                }

                return;
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
        {
        }
        finally
        {
            ntlm?.Dispose();
            client.Dispose();
        }
    }

    private async Task Send407Async(Socket client, IReadOnlyList<string> challenges, CancellationToken cancellationToken)
    {
        const string body = "<html><body>Proxy authentication required</body></html>";
        var reply = new StringBuilder("HTTP/1.1 407 Proxy Authentication Required\r\n");
        foreach (var challenge in challenges)
        {
            reply.Append("Proxy-Authenticate: ").Append(challenge).Append("\r\n");
        }

        reply.Append(_options.CloseAfter407 ? "Connection: close\r\n" : "Proxy-Connection: keep-alive\r\n");

        if (_options.Chunked407)
        {
            reply.Append("Transfer-Encoding: chunked\r\n\r\n");
            reply.Append($"{10:x}; ext=1\r\n").Append(body[..10]).Append("\r\n");
            reply.Append($"{body.Length - 10:x}\r\n").Append(body[10..]).Append("\r\n");
            reply.Append("0\r\nX-Trailer: done\r\n\r\n");
        }
        else
        {
            reply.Append("Content-Length: ").Append(body.Length).Append("\r\n\r\n").Append(body);
        }

        await SendAsync(client, reply.ToString(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads to the blank line. Bytes after it stay in the buffer.</summary>
    private static async Task<string?> ReadHeadAsync(Socket client, List<byte> buffer, CancellationToken cancellationToken)
    {
        var chunk = new byte[4096];
        while (true)
        {
            for (var i = 3; i < buffer.Count; i++)
            {
                if (buffer[i - 3] == '\r' && buffer[i - 2] == '\n' && buffer[i - 1] == '\r' && buffer[i] == '\n')
                {
                    var head = Encoding.Latin1.GetString(buffer.GetRange(0, i - 3).ToArray());
                    buffer.RemoveRange(0, i + 1);
                    return head;
                }
            }

            var read = await client.ReceiveAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            buffer.AddRange(chunk.AsSpan(0, read));
        }
    }

    /// <summary>User and domain from an NTLM AUTHENTICATE message, MS-NLMP §2.2.1.3.</summary>
    private static bool ReadNtlmIdentity(byte[] message, out string user, out string domain)
    {
        user = string.Empty;
        domain = string.Empty;

        if (message.Length < 44)
        {
            return false;
        }

        string? Field(int at)
        {
            var length = BitConverter.ToUInt16(message, at);
            var offset = BitConverter.ToInt32(message, at + 4);
            return offset + length <= message.Length ? Encoding.Unicode.GetString(message, offset, length) : null;
        }

        var d = Field(28);
        var u = Field(36);
        if (d is null || u is null)
        {
            return false;
        }

        user = u;
        domain = d;
        return true;
    }

    private static Task SendAsync(Socket client, string text, CancellationToken cancellationToken)
        => client.SendAsync(Encoding.ASCII.GetBytes(text), cancellationToken).AsTask();

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
                    to.Shutdown(SocketShutdown.Send);
                    return;
                }

                await to.SendAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
        {
        }
    }

    /// <summary>Stops accepting.</summary>
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
