using System.Diagnostics;
using System.Net.Sockets;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy;
using SplitLane.Core.Proxy.Http;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Engine.Relay;

/// <summary>An open tunnel to the destination, through either protocol.</summary>
/// <param name="Socket">The connected socket, owned by the caller from here on.</param>
/// <param name="LeftoverBytes">
/// Bytes that arrived after the proxy's answer. They are the destination's - a server that speaks
/// first can land in the same segment as "200 Connection established" - and go to the application
/// before anything else.
/// </param>
/// <param name="ElapsedMilliseconds">Resolve, connect and handshake, for the proxy test and for logs.</param>
/// <param name="AuthenticationScheme">The HTTP scheme that authenticated, or null.</param>
public sealed record UpstreamTunnel(
    Socket Socket,
    byte[] LeftoverBytes,
    double ElapsedMilliseconds,
    string? AuthenticationScheme = null) : IDisposable
{
    /// <summary>Closes the tunnel.</summary>
    public void Dispose() => Socket.Dispose();
}

/// <summary>
/// Opens a tunnel through an HTTP proxy with <c>CONNECT</c>, authenticating when it answers 407.
/// </summary>
/// <remarks>
/// <para>
/// The protocol - request, response head, challenges, body framing - is in
/// <c>SplitLane.Core.Proxy.Http</c> and tested without sockets. This type is the I/O around it and
/// the order of the exchange:
/// </para>
/// <list type="number">
/// <item>CONNECT, with credentials only if this proxy took a scheme before.</item>
/// <item>2xx: the tunnel is open from the byte after the blank line. Nothing more is read.</item>
/// <item>407: pick the best scheme on offer, read past the 407's body so the connection can be used
/// again - or open a new one when the proxy closes it - and send the next message. NTLM and
/// Negotiate take two rounds on one connection.</item>
/// <item>A 407 after the final message is a refusal of the credentials. It ends the attempt:
/// retrying the same credentials cannot succeed and would only lock the account sooner.</item>
/// </list>
/// <para>
/// Every failure is an <see cref="UpstreamProxyException"/> naming its stage. A 504 is the proxy's
/// own attempt to reach the destination timing out and is reported as that, not as the proxy being
/// unreachable.
/// </para>
/// </remarks>
public static class HttpConnectClient
{
    private const string LogCategory = "upstream";

    /// <summary>Requests on one attempt, before it is abandoned. NTLM needs three at most.</summary>
    internal const int MaxRequests = 5;

    /// <summary>
    /// Longest 407 body read past to keep a connection. Longer, and a new connection is cheaper -
    /// unless the scheme needs this one, which is then a failure.
    /// </summary>
    internal const long MaxDrainBytes = 256 * 1024;

    /// <summary>Opens a tunnel to <paramref name="host"/>:<paramref name="port"/>.</summary>
    /// <param name="proxy">The proxy, and the time budget for the whole attempt.</param>
    /// <param name="host">A hostname or address literal accepted by <see cref="HttpConnectRequest.IsValidHost"/>.</param>
    /// <param name="port">Destination port.</param>
    /// <param name="credential">Username and password, when configured.</param>
    /// <param name="memory">Which scheme worked before, or null to always start by asking.</param>
    /// <param name="cancellationToken">Engine stopping, or the flow closed.</param>
    /// <exception cref="UpstreamProxyException">Every failure.</exception>
    internal static async Task<UpstreamTunnel> ConnectAsync(
        ProxyConfiguration proxy,
        string host,
        ushort port,
        Socks5Credential? credential,
        HttpAuthenticationMemory? memory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        var stopwatch = Stopwatch.StartNew();
        var authority = HttpConnectRequest.Authority(host, port);
        var endpoint = proxy.Endpoint.DisplayString;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(proxy.HandshakeTimeoutMilliseconds);

        var stage = UpstreamStage.Resolve;
        var received = new ReceiveBuffer();
        Socket? socket = null;
        IHttpProxyAuthenticator? authenticator = null;
        string? challengeToken = null;
        IReadOnlyList<ProxyAuthenticationChallenge> challenges = [];

        // Negotiate refused while the proxy also offers NTLM: start again with NTLM, as browsers do.
        // Kerberos needs a service name for the proxy, and a proxy entered by address, or a machine
        // outside the domain, has none; SPNEGO then carries NTLM, which a Kerberos-only proxy refuses
        // even though it would take NTLM offered on its own. Once only, and never down to Basic.
        bool TryFallBackToNtlm()
        {
            if (credential is null || authenticator is null ||
                !authenticator.Scheme.Equals("Negotiate", StringComparison.OrdinalIgnoreCase) ||
                !challenges.Any(challenge => challenge.Is("NTLM")))
            {
                return false;
            }

            Trace(UpstreamStage.Authentication, "Negotiate refused, falling back to NTLM", stopwatch);
            authenticator.Dispose();
            authenticator = HttpProxyAuthentication.Create("NTLM", credential, proxy.Endpoint.Host);
            challengeToken = null;
            return true;
        }

        UpstreamProxyException Fail(
            ConnectionErrorCategory category,
            string message,
            int? status = null,
            string? scheme = null,
            Exception? inner = null)
            => new(category, stage, message, inner)
            {
                Protocol = ProxyProtocolType.Http,
                Endpoint = endpoint,
                Destination = authority,
                ElapsedMilliseconds = stopwatch.Elapsed.TotalMilliseconds,
                StatusCode = status,
                AuthenticationScheme = scheme ?? authenticator?.Scheme,
                OsError = (inner as SocketException)?.SocketErrorCode.ToString(),
            };

        try
        {
            if (credential is not null && memory?.Lookup(proxy, credential) is { } remembered &&
                HttpProxyAuthentication.BasicRefusal(remembered, proxy, credential, memory.StrongestAccepted(proxy, credential)) is null)
            {
                authenticator = HttpProxyAuthentication.Create(remembered, credential, proxy.Endpoint.Host);
            }

            for (var request = 1; ; request++)
            {
                if (request > MaxRequests)
                {
                    throw Fail(
                        ConnectionErrorCategory.AuthenticationFailed,
                        $"Authentication did not finish within {MaxRequests} requests");
                }

                if (socket is null)
                {
                    socket = await UpstreamSocket.ConnectAsync(proxy.Endpoint, s => stage = s, timeout.Token)
                        .ConfigureAwait(false);
                    received.Clear();
                    Trace(stage, $"ok {endpoint}", stopwatch);
                }

                string? authorization = null;
                if (authenticator is not null)
                {
                    stage = UpstreamStage.Authentication;
                    try
                    {
                        authorization = authenticator.NextAuthorization(challengeToken);
                    }
                    catch (UpstreamProxyException) when (TryFallBackToNtlm())
                    {
                        authorization = NextOrFail(authenticator!, Fail);
                    }
                    catch (UpstreamProxyException ex)
                    {
                        throw Fail(ex.Category, ex.Message);
                    }
                }
                else
                {
                    stage = UpstreamStage.Connect;
                }

                await SendAllAsync(socket, HttpConnectRequest.Build(authority, authorization), timeout.Token)
                    .ConfigureAwait(false);
                Trace(stage, $"sent CONNECT {authority}{(authenticator is null ? string.Empty : " with " + authenticator.Scheme)}", stopwatch);

                var (head, headLength) = await ReadHeadAsync(socket, received, Fail, timeout.Token)
                    .ConfigureAwait(false);
                Trace(stage, $"status={head.StatusCode}", stopwatch);

                if (head.IsSuccess)
                {
                    // The tunnel starts at the byte after the blank line. Content-Length and
                    // Transfer-Encoding on a 2xx to CONNECT mean nothing (RFC 9110 §9.3.6), so there is
                    // no body to wait for and no EOF to wait for.
                    memory?.Remember(proxy, credential, authenticator?.Scheme);
                    var tunnel = new UpstreamTunnel(
                        socket,
                        received.Span[headLength..].ToArray(),
                        stopwatch.Elapsed.TotalMilliseconds,
                        authenticator?.Scheme);
                    socket = null;
                    Trace(UpstreamStage.Connect, "tunnel established", stopwatch);
                    return tunnel;
                }

                if (head.StatusCode != 407)
                {
                    if (authenticator is not null && !authenticator.IsComplete)
                    {
                        // Refused in the middle of a handshake with something other than a challenge.
                        memory?.Forget(proxy, credential);
                    }

                    stage = UpstreamStage.Connect;
                    throw RefusalFor(head, port, Fail);
                }

                challenges = ProxyAuthenticationChallenge.Parse(head.Values("Proxy-Authenticate"));
                var offered = HttpProxyAuthentication.Offered(challenges);
                Trace(UpstreamStage.Authentication, $"challenge: {offered}", stopwatch);

                if (authenticator is null)
                {
                    stage = UpstreamStage.Authentication;

                    if (credential is null)
                    {
                        throw Fail(
                            ConnectionErrorCategory.AuthenticationRequired,
                            $"The proxy requires authentication ({offered}) and no username and password are configured",
                            407,
                            offered);
                    }

                    if (HttpProxyAuthentication.Choose(challenges) is not { } scheme)
                    {
                        throw Fail(
                            ConnectionErrorCategory.AuthenticationUnsupported,
                            $"Unsupported proxy authentication scheme: {offered}. SplitLane speaks " +
                            string.Join(", ", HttpProxyAuthentication.SupportedSchemes),
                            407,
                            offered);
                    }

                    // Never a silent downgrade to the one scheme that sends the password (SL-SEC-011).
                    if (HttpProxyAuthentication.BasicRefusal(
                            scheme, proxy, credential, memory?.StrongestAccepted(proxy, credential)) is { } refusal)
                    {
                        throw Fail(ConnectionErrorCategory.AuthenticationUnsupported, refusal, 407, offered);
                    }

                    authenticator = HttpProxyAuthentication.Create(scheme, credential, proxy.Endpoint.Host);
                    challengeToken = null;
                }
                else if (authenticator.IsConnectionOriented && !authenticator.IsComplete)
                {
                    challengeToken = challenges
                        .FirstOrDefault(challenge => challenge.Is(authenticator.Scheme) && challenge.Token is not null)
                        ?.Token;

                    if (challengeToken is null && !TryFallBackToNtlm())
                    {
                        memory?.Forget(proxy, credential);
                        throw Fail(
                            ConnectionErrorCategory.AuthenticationFailed,
                            $"The proxy rejected the {authenticator.Scheme} credentials",
                            407);
                    }
                }
                else if (!TryFallBackToNtlm())
                {
                    memory?.Forget(proxy, credential);
                    throw Fail(
                        ConnectionErrorCategory.AuthenticationFailed,
                        $"The proxy rejected the {authenticator.Scheme} credentials",
                        407);
                }

                // The next request goes on this connection if the proxy keeps it and its 407 can be
                // read to the end, and on a new one otherwise - which a connection-oriented scheme
                // halfway through cannot survive.
                var reusable = !head.ClosesConnection &&
                    await TryReadPastBodyAsync(socket, received, head, headLength, Fail, timeout.Token).ConfigureAwait(false);

                if (!reusable)
                {
                    if (challengeToken is not null)
                    {
                        throw Fail(
                            ConnectionErrorCategory.AuthenticationFailed,
                            $"The proxy closed the connection in the middle of the {authenticator.Scheme} handshake, " +
                            "which can only complete on one connection",
                            407);
                    }

                    socket.Dispose();
                    socket = null;
                    stage = UpstreamStage.Resolve;
                }
            }
        }
        catch (UpstreamProxyException)
        {
            throw;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw Fail(ConnectionErrorCategory.TimedOut, TimeoutMessage(stage, proxy.HandshakeTimeoutMilliseconds, authority));
        }
        catch (OperationCanceledException)
        {
            throw Fail(ConnectionErrorCategory.Cancelled, "Proxy connection cancelled");
        }
        catch (SocketException ex)
        {
            var message = stage switch
            {
                UpstreamStage.Resolve => $"The proxy's name {proxy.Endpoint.Host} did not resolve",
                UpstreamStage.TcpConnect => "Could not connect to the proxy",
                _ => "The connection to the proxy failed",
            };

            throw Fail(ConnectionErrorCategory.UpstreamUnreachable, $"{message} ({ex.SocketErrorCode})", inner: ex);
        }
        finally
        {
            socket?.Dispose();
            authenticator?.Dispose();
        }
    }

    /// <summary>The first message of a fallback scheme, with the stage and proxy added to a failure.</summary>
    private static string NextOrFail(
        IHttpProxyAuthenticator authenticator,
        Func<ConnectionErrorCategory, string, int?, string?, Exception?, UpstreamProxyException> fail)
    {
        try
        {
            return authenticator.NextAuthorization(null);
        }
        catch (UpstreamProxyException ex)
        {
            throw fail(ex.Category, ex.Message, null, authenticator.Scheme, null);
        }
    }

    /// <summary>What a status other than 2xx and 407 means, and whose problem it is.</summary>
    private static UpstreamProxyException RefusalFor(
        HttpResponseHead head,
        ushort port,
        Func<ConnectionErrorCategory, string, int?, string?, Exception?, UpstreamProxyException> fail)
    {
        var status = head.StatusCode;
        var said = $"{status} {head.ReasonPhrase}".TrimEnd();

        return status switch
        {
            // The proxy was reached, accepted the request, and its own attempt to reach the
            // destination failed. The proxy is fine.
            502 or 503 => fail(ConnectionErrorCategory.DestinationUnreachable, $"The proxy could not reach the destination ({said})", status, null, null),
            504 => fail(ConnectionErrorCategory.DestinationUnreachable, $"The proxy timed out reaching the destination ({said})", status, null, null),
            403 when port != 443 => fail(
                ConnectionErrorCategory.RejectedByProxy,
                $"The proxy's policy refused the tunnel ({said}); many proxies allow CONNECT only to port 443",
                status, null, null),
            403 => fail(ConnectionErrorCategory.RejectedByProxy, $"The proxy's policy refused the tunnel ({said})", status, null, null),
            405 or 501 => fail(ConnectionErrorCategory.RejectedByProxy, $"The proxy does not support CONNECT ({said})", status, null, null),
            _ => fail(ConnectionErrorCategory.RejectedByProxy, $"The proxy refused the tunnel ({said})", status, null, null),
        };
    }

    private static async Task<(HttpResponseHead Head, int Length)> ReadHeadAsync(
        Socket socket,
        ReceiveBuffer received,
        Func<ConnectionErrorCategory, string, int?, string?, Exception?, UpstreamProxyException> fail,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            switch (HttpResponseHead.TryParse(received.Span, out var head, out var length))
            {
                case HttpHeadParseStatus.Complete:
                    return (head!, length);

                case HttpHeadParseStatus.NotHttp:
                    throw received.Span[0] == 0x05
                        ? fail(ConnectionErrorCategory.ProtocolMismatch, "The proxy answered in SOCKS5, not HTTP - set the proxy type to SOCKS5", null, null, null)
                        : fail(ConnectionErrorCategory.ProtocolMismatch, $"The proxy's answer is not HTTP (first byte 0x{received.Span[0]:x2})", null, null, null);

                case HttpHeadParseStatus.Malformed:
                    throw fail(ConnectionErrorCategory.InternalError, "The proxy's answer is malformed HTTP", null, null, null);

                case HttpHeadParseStatus.TooLarge:
                    throw fail(ConnectionErrorCategory.InternalError, "The proxy's answer has no end to its headers", null, null, null);
            }

            if (await received.ReceiveAsync(socket, cancellationToken).ConfigureAwait(false) == 0)
            {
                throw fail(
                    ConnectionErrorCategory.UpstreamUnreachable,
                    received.Length == 0
                        ? "The proxy closed the connection without answering"
                        : "The proxy closed the connection in the middle of its answer",
                    null, null, null);
            }
        }
    }

    /// <summary>
    /// Reads past a 407's body. Leaves the buffer holding whatever followed it, and returns whether
    /// the connection is at a message boundary and can carry the next request.
    /// </summary>
    private static async Task<bool> TryReadPastBodyAsync(
        Socket socket,
        ReceiveBuffer received,
        HttpResponseHead head,
        int headLength,
        Func<ConnectionErrorCategory, string, int?, string?, Exception?, UpstreamProxyException> fail,
        CancellationToken cancellationToken)
    {
        HttpBodyReader? reader;
        try
        {
            reader = head.BodyReader();
        }
        catch (FormatException ex)
        {
            throw fail(ConnectionErrorCategory.InternalError, $"The proxy's 407 is malformed: {ex.Message}", 407, null, ex);
        }

        received.Consume(headLength);

        if (reader is null)
        {
            // Delimited by the proxy closing the connection.
            return false;
        }

        while (true)
        {
            try
            {
                received.Consume(reader.Consume(received.Span));
            }
            catch (FormatException ex)
            {
                throw fail(ConnectionErrorCategory.InternalError, $"The proxy's 407 is malformed: {ex.Message}", 407, null, ex);
            }

            if (reader.IsComplete)
            {
                return true;
            }

            if (reader.BodyBytes > MaxDrainBytes ||
                await received.ReceiveAsync(socket, cancellationToken).ConfigureAwait(false) == 0)
            {
                return false;
            }
        }
    }

    private static string TimeoutMessage(UpstreamStage stage, int budgetMilliseconds, string authority) => stage switch
    {
        UpstreamStage.Resolve => $"Resolving the proxy's name did not finish within {budgetMilliseconds} ms",
        UpstreamStage.TcpConnect => $"The proxy did not accept a TCP connection within {budgetMilliseconds} ms",
        UpstreamStage.Authentication => $"The proxy did not answer the authenticated CONNECT within {budgetMilliseconds} ms",
        _ => $"The proxy accepted the connection and did not answer CONNECT {authority} within {budgetMilliseconds} ms. " +
             "It may still be trying to reach the destination; a SOCKS5 proxy also stays silent like this",
    };

    private static async Task SendAllAsync(Socket socket, byte[] bytes, CancellationToken cancellationToken)
    {
        var sent = 0;
        while (sent < bytes.Length)
        {
            var written = await socket.SendAsync(bytes.AsMemory(sent), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);

            if (written == 0)
            {
                throw new SocketException((int)SocketError.ConnectionReset);
            }

            sent += written;
        }
    }

    /// <summary>One debug line per step, named by stage. Never a header value.</summary>
    private static void Trace(UpstreamStage stage, string what, Stopwatch stopwatch)
        => SplitLaneLog.Debug(LogCategory, $"{stage.LogName()} {what} (+{stopwatch.Elapsed.TotalMilliseconds:F0}ms)");

    /// <summary>Bytes received and not yet consumed.</summary>
    private sealed class ReceiveBuffer
    {
        private byte[] _data = new byte[4096];

        public int Length { get; private set; }

        public ReadOnlySpan<byte> Span => _data.AsSpan(0, Length);

        public void Clear() => Length = 0;

        public void Consume(int count)
        {
            Buffer.BlockCopy(_data, count, _data, 0, Length - count);
            Length -= count;
        }

        /// <summary>Receives once, growing the buffer when it is full. Returns 0 at end of stream.</summary>
        public async Task<int> ReceiveAsync(Socket socket, CancellationToken cancellationToken)
        {
            if (Length == _data.Length)
            {
                Array.Resize(ref _data, _data.Length * 2);
            }

            var read = await socket.ReceiveAsync(_data.AsMemory(Length), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);
            Length += read;
            return read;
        }
    }
}
