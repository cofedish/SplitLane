using System.Globalization;
using System.Text;

namespace SplitLane.Core.Proxy.Http;

/// <summary>
/// The CONNECT request, RFC 9110 §9.3.6 and RFC 9112 §3.2.3.
/// </summary>
/// <remarks>
/// The destination name reaches this from the DNS observer, which reads it out of a DNS answer, and a
/// DNS label may carry any byte - including CR and LF. Written into a request line unchecked, a name
/// could end the line and add headers of its own choosing. So the authority is held to the characters
/// a hostname or an address literal can contain, and anything else is refused before it is sent.
/// </remarks>
public static class HttpConnectRequest
{
    /// <summary>
    /// Whether a host can be written into a request line as it is: a hostname of letters, digits,
    /// hyphens, underscores and dots, or an IPv4 or IPv6 literal.
    /// </summary>
    public static bool IsValidHost(string? host)
    {
        if (string.IsNullOrEmpty(host) || host.Length > 255)
        {
            return false;
        }

        if (host.Contains(':'))
        {
            // Only an IPv6 literal contains a colon; a zone index is meaningless to a proxy.
            return System.Net.IPAddress.TryParse(host, out var address)
                && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                && !host.Contains('%');
        }

        foreach (var c in host)
        {
            var allowed = c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '-' or '.' or '_';
            if (!allowed)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary><c>host:port</c>, bracketing an IPv6 literal.</summary>
    public static string Authority(string host, ushort port)
    {
        if (!IsValidHost(host))
        {
            throw new ArgumentException("Host cannot be written into an HTTP request line", nameof(host));
        }

        var port10 = port.ToString(CultureInfo.InvariantCulture);
        return host.Contains(':') ? $"[{host}]:{port10}" : $"{host}:{port10}";
    }

    /// <summary>
    /// Builds <c>CONNECT authority HTTP/1.1</c> with its headers.
    /// </summary>
    /// <param name="authority">From <see cref="Authority"/>.</param>
    /// <param name="proxyAuthorization">
    /// The whole <c>Proxy-Authorization</c> value, scheme included, or null to send none. The caller
    /// builds it from a credential; it must not be logged, and nothing here does.
    /// </param>
    public static byte[] Build(string authority, string? proxyAuthorization)
    {
        ArgumentException.ThrowIfNullOrEmpty(authority);

        if (proxyAuthorization is not null && proxyAuthorization.AsSpan().IndexOfAny('\r', '\n') >= 0)
        {
            throw new ArgumentException("Authorization value contains a line break", nameof(proxyAuthorization));
        }

        var request = new StringBuilder(256);
        request.Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n");
        request.Append("Host: ").Append(authority).Append("\r\n");

        // Asks the proxy to keep the connection open across a 407, which connection-oriented schemes
        // (NTLM, Negotiate) need: their second and third messages are only valid on the connection
        // that carried the first. "Proxy-Connection" is not standard and is what proxies look for.
        request.Append("Proxy-Connection: Keep-Alive\r\n");

        if (proxyAuthorization is not null)
        {
            request.Append("Proxy-Authorization: ").Append(proxyAuthorization).Append("\r\n");
        }

        request.Append("\r\n");

        // Latin-1 is how HTTP/1.1 treats header bytes; every character here is ASCII anyway.
        return Encoding.Latin1.GetBytes(request.ToString());
    }

    /// <summary>
    /// The <c>Proxy-Authorization</c> value for Basic, RFC 7617: UTF-8, base64 of <c>user:password</c>.
    /// </summary>
    /// <remarks>
    /// A colon in the username cannot be represented - the proxy splits at the first one - so it is
    /// refused rather than sent as a different user.
    /// </remarks>
    public static string BasicAuthorization(string username, string password)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(password);

        if (username.Contains(':'))
        {
            throw new ArgumentException("A Basic username cannot contain a colon", nameof(username));
        }

        return "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(username + ":" + password));
    }
}
