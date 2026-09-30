using System.Globalization;
using System.Text;

namespace SplitLane.Core.Proxy.Http;

/// <summary>What <see cref="HttpResponseHead.TryParse"/> made of the bytes so far.</summary>
public enum HttpHeadParseStatus
{
    /// <summary>The head is complete and parsed.</summary>
    Complete,

    /// <summary>The blank line that ends the head has not arrived yet.</summary>
    NeedMoreBytes,

    /// <summary>The bytes are not an HTTP response at all. The first byte says what they might be.</summary>
    NotHttp,

    /// <summary>The head is an HTTP response and breaks its grammar.</summary>
    Malformed,

    /// <summary>The head exceeds <see cref="HttpResponseHead.MaxHeadBytes"/> without ending.</summary>
    TooLarge,
}

/// <summary>
/// The status line and headers of a proxy's answer to CONNECT.
/// </summary>
/// <remarks>
/// <para>
/// Parsing stops at the blank line. For a 2xx answer to CONNECT that is the whole message - RFC 9110
/// §9.3.6: the connection is a tunnel from the byte after it, and any Content-Length or
/// Transfer-Encoding is to be ignored. Whatever arrived after the blank line is the destination's,
/// not the proxy's, and is handed to the relay. A client that waited for a body, or for the proxy to
/// close, after "200 Connection established" would sit there until its timeout with a working tunnel.
/// </para>
/// <para>
/// Bare LF line endings are accepted as well as CRLF (RFC 9112 §2.2).
/// </para>
/// </remarks>
public sealed class HttpResponseHead
{
    /// <summary>Longest head accepted. A proxy's 407 is a few hundred bytes; this is generous.</summary>
    public const int MaxHeadBytes = 32 * 1024;

    private readonly List<KeyValuePair<string, string>> _headers;

    private HttpResponseHead(int statusCode, string reasonPhrase, int minorVersion, List<KeyValuePair<string, string>> headers)
    {
        StatusCode = statusCode;
        ReasonPhrase = reasonPhrase;
        MinorVersion = minorVersion;
        _headers = headers;
    }

    /// <summary>The three-digit status.</summary>
    public int StatusCode { get; }

    /// <summary>The reason phrase, for messages. May be empty.</summary>
    public string ReasonPhrase { get; }

    /// <summary>0 for HTTP/1.0, 1 for HTTP/1.1.</summary>
    public int MinorVersion { get; }

    /// <summary>Every header, in order, names as sent.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers => _headers;

    /// <summary>Whether the tunnel is open.</summary>
    public bool IsSuccess => StatusCode is >= 200 and <= 299;

    /// <summary>Every value of a header, case-insensitively, in order.</summary>
    public IEnumerable<string> Values(string name)
    {
        foreach (var header in _headers)
        {
            if (header.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                yield return header.Value;
            }
        }
    }

    /// <summary>
    /// Whether the proxy will close the connection after this response, so another request needs a
    /// new one.
    /// </summary>
    public bool ClosesConnection
    {
        get
        {
            var tokens = Values("Connection").Concat(Values("Proxy-Connection"))
                .SelectMany(value => value.Split(','))
                .Select(token => token.Trim())
                .ToList();

            if (tokens.Exists(token => token.Equals("close", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            // HTTP/1.0 closes unless told otherwise.
            return MinorVersion == 0
                && !tokens.Exists(token => token.Equals("keep-alive", StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// How the body of a non-2xx answer ends, so it can be read past before the connection is used
    /// again.
    /// </summary>
    /// <returns>
    /// A reader, or null when the body is delimited by the proxy closing the connection - which
    /// means the connection cannot be used again at all.
    /// </returns>
    /// <exception cref="FormatException">The framing headers contradict each other or do not parse.</exception>
    public HttpBodyReader? BodyReader()
    {
        if (StatusCode is (>= 100 and <= 199) or 204 or 304)
        {
            return HttpBodyReader.ForLength(0);
        }

        var encodings = Values("Transfer-Encoding").ToList();
        if (encodings.Count > 0)
        {
            var last = encodings.SelectMany(value => value.Split(',')).Select(token => token.Trim()).LastOrDefault();

            // RFC 9112 §6.3: chunked last means chunked; anything else is read until close.
            return string.Equals(last, "chunked", StringComparison.OrdinalIgnoreCase)
                ? HttpBodyReader.Chunked()
                : null;
        }

        var lengths = Values("Content-Length")
            .SelectMany(value => value.Split(','))
            .Select(token => token.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (lengths.Count == 0)
        {
            return null;
        }

        if (lengths.Count > 1 ||
            !long.TryParse(lengths[0], NumberStyles.None, CultureInfo.InvariantCulture, out var length))
        {
            throw new FormatException("Content-Length is not a single non-negative number");
        }

        return HttpBodyReader.ForLength(length);
    }

    /// <summary>
    /// Parses the head from the start of <paramref name="data"/>.
    /// </summary>
    /// <param name="data">Everything received so far.</param>
    /// <param name="head">The head, when <see cref="HttpHeadParseStatus.Complete"/>.</param>
    /// <param name="headLength">How many bytes the head occupied, blank line included.</param>
    public static HttpHeadParseStatus TryParse(ReadOnlySpan<byte> data, out HttpResponseHead? head, out int headLength)
    {
        head = null;
        headLength = 0;

        // Recognised as soon as there are enough bytes to say, not only once the head is complete:
        // a SOCKS5 server sends two bytes and waits, and waiting for a blank line from it would be
        // a timeout rather than an answer.
        ReadOnlySpan<byte> prefix = "HTTP/"u8;
        var comparable = Math.Min(data.Length, prefix.Length);
        if (!data[..comparable].SequenceEqual(prefix[..comparable]))
        {
            return HttpHeadParseStatus.NotHttp;
        }

        var end = FindEndOfHead(data, out var terminatorLength);
        if (end < 0)
        {
            return data.Length > MaxHeadBytes ? HttpHeadParseStatus.TooLarge : HttpHeadParseStatus.NeedMoreBytes;
        }

        if (end + terminatorLength > MaxHeadBytes)
        {
            return HttpHeadParseStatus.TooLarge;
        }

        var text = Encoding.Latin1.GetString(data[..end]);
        var lines = text.Split('\n').Select(line => line.TrimEnd('\r')).ToList();

        if (!TryParseStatusLine(lines[0], out var minor, out var status, out var reason))
        {
            return HttpHeadParseStatus.Malformed;
        }

        var headers = new List<KeyValuePair<string, string>>();
        foreach (var line in lines.Skip(1))
        {
            if (line.Length == 0)
            {
                continue;
            }

            if (line[0] is ' ' or '\t')
            {
                // Obsolete line folding, RFC 9112 §5.2: a continuation of the previous value.
                if (headers.Count == 0)
                {
                    return HttpHeadParseStatus.Malformed;
                }

                var previous = headers[^1];
                headers[^1] = new(previous.Key, previous.Value + " " + line.Trim());
                continue;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0 || line[..colon].Any(c => c is ' ' or '\t'))
            {
                return HttpHeadParseStatus.Malformed;
            }

            headers.Add(new(line[..colon], line[(colon + 1)..].Trim(' ', '\t')));
        }

        head = new HttpResponseHead(status, reason, minor, headers);
        headLength = end + terminatorLength;
        return HttpHeadParseStatus.Complete;
    }

    private static int FindEndOfHead(ReadOnlySpan<byte> data, out int terminatorLength)
    {
        for (var i = 0; i < data.Length; i++)
        {
            if (data[i] != (byte)'\n')
            {
                continue;
            }

            // The line just ended at i. An empty next line - LF, or CR LF - ends the head.
            if (i + 1 < data.Length && data[i + 1] == (byte)'\n')
            {
                terminatorLength = 2;
                return i;
            }

            if (i + 2 < data.Length && data[i + 1] == (byte)'\r' && data[i + 2] == (byte)'\n')
            {
                terminatorLength = 3;
                return i;
            }
        }

        terminatorLength = 0;
        return -1;
    }

    private static bool TryParseStatusLine(string line, out int minor, out int status, out string reason)
    {
        minor = 0;
        status = 0;
        reason = string.Empty;

        // HTTP/1.x SP 3DIGIT SP reason
        if (line.Length < 12 || !line.StartsWith("HTTP/1.", StringComparison.Ordinal) || line[8] != ' ')
        {
            return false;
        }

        if (line[7] is not ('0' or '1'))
        {
            return false;
        }

        minor = line[7] - '0';

        var code = line.AsSpan(9, 3);
        if (!int.TryParse(code, NumberStyles.None, CultureInfo.InvariantCulture, out status) || status < 100)
        {
            return false;
        }

        if (line.Length > 12)
        {
            if (line[12] != ' ')
            {
                return false;
            }

            reason = line[13..];
        }

        return true;
    }
}
