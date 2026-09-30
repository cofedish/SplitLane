using System.Text;

namespace SplitLane.Core.Proxy.Http;

/// <summary>
/// One challenge from a <c>Proxy-Authenticate</c> header, RFC 9110 §11.6.1 and §11.7.1.
/// </summary>
/// <param name="Scheme">As the proxy spelled it: <c>Basic</c>, <c>NTLM</c>, <c>Negotiate</c>, ...</param>
/// <param name="Token">
/// The token68 form: the base64 blob NTLM and Negotiate carry on their second leg. Null when the
/// challenge had parameters, or nothing, instead.
/// </param>
/// <param name="Parameters">The auth-param form, such as <c>realm</c>. Names are case-insensitive.</param>
public sealed record ProxyAuthenticationChallenge(
    string Scheme,
    string? Token,
    IReadOnlyDictionary<string, string> Parameters)
{
    /// <summary>Whether this challenge is for a scheme, compared case-insensitively.</summary>
    public bool Is(string scheme) => Scheme.Equals(scheme, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Every challenge in every <c>Proxy-Authenticate</c> value.
    /// </summary>
    /// <remarks>
    /// A proxy may send several headers, one per scheme, or one header listing them all:
    /// <c>Negotiate, NTLM, Basic realm="corp, main"</c>. The comma separates challenges and also
    /// separates the parameters of one challenge, and is allowed inside a quoted value. What starts a
    /// new challenge is a bare word that is not followed by <c>=</c>. Nothing malformed throws: an
    /// element that cannot be read is skipped, so one odd header cannot hide a usable scheme.
    /// </remarks>
    public static IReadOnlyList<ProxyAuthenticationChallenge> Parse(IEnumerable<string> headerValues)
    {
        ArgumentNullException.ThrowIfNull(headerValues);

        var challenges = new List<ProxyAuthenticationChallenge>();

        foreach (var value in headerValues)
        {
            string? scheme = null;
            string? token = null;
            Dictionary<string, string>? parameters = null;

            void Flush()
            {
                if (scheme is not null)
                {
                    challenges.Add(new ProxyAuthenticationChallenge(
                        scheme,
                        token,
                        parameters ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)));
                }

                scheme = null;
                token = null;
                parameters = null;
            }

            foreach (var raw in SplitOutsideQuotes(value))
            {
                var element = raw.Trim(' ', '\t');
                if (element.Length == 0)
                {
                    continue;
                }

                if (TryParseParameter(element, out var name, out var parameterValue))
                {
                    // A parameter of the challenge being read.
                    if (scheme is not null && token is null)
                    {
                        parameters ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        parameters[name] = parameterValue;
                    }

                    continue;
                }

                // A new challenge: a scheme, then optionally a token68 or its first parameter.
                Flush();

                var space = element.IndexOfAny([' ', '\t']);
                var candidate = space < 0 ? element : element[..space];
                if (!IsToken(candidate))
                {
                    continue;
                }

                scheme = candidate;

                if (space < 0)
                {
                    continue;
                }

                var rest = element[space..].Trim(' ', '\t');
                if (TryParseParameter(rest, out name, out parameterValue))
                {
                    parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [name] = parameterValue };
                }
                else if (IsToken68(rest))
                {
                    token = rest;
                }
            }

            Flush();
        }

        return challenges;
    }

    private static IEnumerable<string> SplitOutsideQuotes(string value)
    {
        var current = new StringBuilder();
        var quoted = false;

        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];

            if (quoted && c == '\\' && i + 1 < value.Length)
            {
                current.Append(c).Append(value[++i]);
                continue;
            }

            if (c == '"')
            {
                quoted = !quoted;
            }

            if (c == ',' && !quoted)
            {
                yield return current.ToString();
                current.Clear();
                continue;
            }

            current.Append(c);
        }

        yield return current.ToString();
    }

    /// <summary><c>name = value</c>, value a token or a quoted string. A token68 never matches.</summary>
    private static bool TryParseParameter(string element, out string name, out string value)
    {
        name = string.Empty;
        value = string.Empty;

        var equals = element.IndexOf('=');
        if (equals <= 0)
        {
            return false;
        }

        name = element[..equals].TrimEnd(' ', '\t');
        if (!IsToken(name))
        {
            return false;
        }

        var rest = element[(equals + 1)..].TrimStart(' ', '\t');

        // "abc==" is a token68 with padding, not a parameter with an empty value.
        if (rest.Length == 0 || rest[0] == '=')
        {
            return false;
        }

        if (rest[0] == '"')
        {
            var unquoted = new StringBuilder();
            for (var i = 1; i < rest.Length; i++)
            {
                if (rest[i] == '\\' && i + 1 < rest.Length)
                {
                    unquoted.Append(rest[++i]);
                }
                else if (rest[i] == '"')
                {
                    value = unquoted.ToString();
                    return rest[(i + 1)..].Trim(' ', '\t').Length == 0;
                }
                else
                {
                    unquoted.Append(rest[i]);
                }
            }

            return false;
        }

        if (!IsToken(rest))
        {
            return false;
        }

        value = rest;
        return true;
    }

    private static bool IsToken(string text)
        => text.Length > 0 && text.All(c => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9')
            or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~');

    private static bool IsToken68(string text)
    {
        var body = text.TrimEnd('=');
        return body.Length > 0 && body.All(c => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9')
            or '-' or '.' or '_' or '~' or '+' or '/');
    }
}
