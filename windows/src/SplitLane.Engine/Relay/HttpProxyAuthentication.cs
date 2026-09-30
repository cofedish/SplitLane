using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy;
using SplitLane.Core.Proxy.Http;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Engine.Relay;

/// <summary>
/// One authentication exchange with an HTTP proxy, producing <c>Proxy-Authorization</c> values.
/// </summary>
/// <remarks>
/// A value produced here is a credential or derived from one. It goes into the request and nowhere
/// else: not into a log, an exception message, or a <see cref="ConnectionEvent"/>.
/// </remarks>
internal interface IHttpProxyAuthenticator : IDisposable
{
    /// <summary>The scheme, spelled as it is sent.</summary>
    string Scheme { get; }

    /// <summary>
    /// Whether the proxy ties the exchange to one connection. True for NTLM and Negotiate, whose
    /// second message answers a challenge that only the connection that asked for it can use.
    /// </summary>
    bool IsConnectionOriented { get; }

    /// <summary>Whether the last value produced was the final one, so a further 407 is a refusal.</summary>
    bool IsComplete { get; }

    /// <summary>The next <c>Proxy-Authorization</c> value.</summary>
    /// <param name="challengeToken">The proxy's token from its 407, or null for the first message.</param>
    /// <exception cref="UpstreamProxyException">The exchange cannot continue.</exception>
    string NextAuthorization(string? challengeToken);
}

/// <summary>Which schemes SplitLane speaks, and how to start each.</summary>
/// <remarks>
/// <para>
/// Basic, NTLM and Negotiate, which between them cover the proxies organisations run. Digest is not
/// implemented: it is rare in front of corporate networks, and a proxy that offers only Digest gets
/// a failure that names it rather than a timeout.
/// </para>
/// <para>
/// NTLM and Negotiate go through SSPI (<see cref="NegotiateAuthentication"/>), with the username and
/// password configured for the proxy - never with the engine's own identity. The engine is
/// LocalSystem, whose network identity is the computer account, and a proxy that accepted it would be
/// letting the machine, not the user, through.
/// </para>
/// </remarks>
internal static class HttpProxyAuthentication
{
    /// <summary>Supported schemes, most preferred first. Basic, the only one that sends the password, is last.</summary>
    public static IReadOnlyList<string> SupportedSchemes { get; } = ["Negotiate", "NTLM", "Basic"];

    /// <summary>The best supported scheme the proxy offers, or null when there is none in common.</summary>
    public static string? Choose(IReadOnlyList<ProxyAuthenticationChallenge> challenges)
        => SupportedSchemes.FirstOrDefault(scheme => challenges.Any(challenge => challenge.Is(scheme)));

    /// <summary>The schemes on offer, for a message: <c>Digest, Bearer</c>.</summary>
    public static string Offered(IReadOnlyList<ProxyAuthenticationChallenge> challenges)
        => challenges.Count == 0
            ? "no scheme named"
            : string.Join(", ", challenges.Select(challenge => challenge.Scheme).Distinct(StringComparer.OrdinalIgnoreCase));

    /// <summary>Starts an exchange.</summary>
    public static IHttpProxyAuthenticator Create(string scheme, Socks5Credential credential, string proxyHost)
    {
        ArgumentNullException.ThrowIfNull(credential);

        return scheme.ToUpperInvariant() switch
        {
            "BASIC" => new BasicAuthenticator(credential),
            "NTLM" => new SspiAuthenticator("NTLM", credential, proxyHost),
            "NEGOTIATE" => new SspiAuthenticator("Negotiate", credential, proxyHost),
            _ => throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "Unsupported scheme"),
        };
    }

    private sealed class BasicAuthenticator(Socks5Credential credential) : IHttpProxyAuthenticator
    {
        public string Scheme => "Basic";

        public bool IsConnectionOriented => false;

        public bool IsComplete { get; private set; }

        public string NextAuthorization(string? challengeToken)
        {
            if (credential.Username.Contains(':'))
            {
                throw new UpstreamProxyException(
                    ConnectionErrorCategory.AuthenticationFailed,
                    UpstreamStage.Authentication,
                    "A username with a colon cannot be sent with Basic authentication")
                {
                    Protocol = ProxyProtocolType.Http,
                    AuthenticationScheme = Scheme,
                };
            }

            IsComplete = true;
            return HttpConnectRequest.BasicAuthorization(credential.Username, credential.Password);
        }

        public void Dispose()
        {
        }
    }

    private sealed class SspiAuthenticator : IHttpProxyAuthenticator
    {
        private readonly NegotiateAuthentication _context;

        public SspiAuthenticator(string package, Socks5Credential credential, string proxyHost)
        {
            Scheme = package;

            var (user, domain) = SplitDomain(credential.Username);

            _context = new NegotiateAuthentication(new NegotiateAuthenticationClientOptions
            {
                Package = package,
                Credential = new NetworkCredential(user, credential.Password, domain),

                // Kerberos finds the proxy's service ticket by this name. NTLM ignores it.
                TargetName = "HTTP/" + proxyHost,

                // The tunnel carries the application's own TLS; nothing here signs or seals it.
                RequiredProtectionLevel = ProtectionLevel.None,
            });
        }

        public string Scheme { get; }

        public bool IsConnectionOriented => true;

        public bool IsComplete { get; private set; }

        public string NextAuthorization(string? challengeToken)
        {
            string? blob;
            NegotiateAuthenticationStatusCode status;
            try
            {
                blob = _context.GetOutgoingBlob(challengeToken, out status);
            }
            catch (FormatException)
            {
                // token68 allows characters base64 does not; a challenge made of them is the proxy's
                // fault and an authentication failure, not an internal error.
                throw new UpstreamProxyException(
                    ConnectionErrorCategory.AuthenticationFailed,
                    UpstreamStage.Authentication,
                    $"The proxy's {Scheme} challenge is not valid base64")
                {
                    Protocol = ProxyProtocolType.Http,
                    AuthenticationScheme = Scheme,
                };
            }

            switch (status)
            {
                case NegotiateAuthenticationStatusCode.Completed:
                    IsComplete = true;
                    break;

                case NegotiateAuthenticationStatusCode.ContinueNeeded:
                    break;

                default:
                    // The status names the reason - UnknownCredentials, InvalidToken, ... - and
                    // carries nothing secret.
                    throw new UpstreamProxyException(
                        ConnectionErrorCategory.AuthenticationFailed,
                        UpstreamStage.Authentication,
                        $"{Scheme} could not continue: {status}")
                    {
                        Protocol = ProxyProtocolType.Http,
                        AuthenticationScheme = Scheme,
                    };
            }

            if (string.IsNullOrEmpty(blob))
            {
                throw new UpstreamProxyException(
                    ConnectionErrorCategory.AuthenticationFailed,
                    UpstreamStage.Authentication,
                    $"{Scheme} produced no token to send")
                {
                    Protocol = ProxyProtocolType.Http,
                    AuthenticationScheme = Scheme,
                };
            }

            return Scheme + " " + blob;
        }

        public void Dispose() => _context.Dispose();

        /// <summary><c>DOMAIN\user</c> to its parts; a UPN, <c>user@domain</c>, goes to SSPI whole.</summary>
        internal static (string User, string Domain) SplitDomain(string username)
        {
            var slash = username.IndexOf('\\');
            return slash > 0 ? (username[(slash + 1)..], username[..slash]) : (username, string.Empty);
        }
    }
}

/// <summary>
/// Which scheme worked last time, per proxy and user, so later connections start with it.
/// </summary>
/// <remarks>
/// Every relayed connection is its own CONNECT. Without this each one would first be refused with a
/// 407 - and, when that 407 closes the connection, connect twice. Remembering the scheme lets Basic be
/// sent with the first request and NTLM or Negotiate start its first message at once. It holds a
/// scheme name, never a credential, and forgets it the moment the proxy refuses.
/// </remarks>
internal sealed class HttpAuthenticationMemory
{
    private readonly ConcurrentDictionary<string, string> _schemes = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The scheme that last worked, or null to start by asking.</summary>
    public string? Lookup(ProxyConfiguration proxy, Socks5Credential? credential)
        => credential is not null && _schemes.TryGetValue(Key(proxy, credential), out var scheme) ? scheme : null;

    /// <summary>Records the outcome of a successful CONNECT.</summary>
    public void Remember(ProxyConfiguration proxy, Socks5Credential? credential, string? scheme)
    {
        if (credential is null)
        {
            return;
        }

        if (scheme is null)
        {
            _schemes.TryRemove(Key(proxy, credential), out _);
        }
        else
        {
            _schemes[Key(proxy, credential)] = scheme;
        }
    }

    /// <summary>Forgets after a refusal, so the next connection asks the proxy again.</summary>
    public void Forget(ProxyConfiguration proxy, Socks5Credential? credential)
    {
        if (credential is not null)
        {
            _schemes.TryRemove(Key(proxy, credential), out _);
        }
    }

    private static string Key(ProxyConfiguration proxy, Socks5Credential credential)
        => $"{proxy.Endpoint.DisplayString}\n{credential.Username}";
}
