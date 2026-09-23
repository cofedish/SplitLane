using System.Text;

namespace SplitLane.Core.Rules;

/// <summary>
/// The publisher half of a signed application's identity, in a form that survives the publisher's
/// own certificate changes.
/// </summary>
/// <remarks>
/// <para>
/// A publisher is keyed on the subject of the leaf signing certificate - common name, organisation,
/// locality, state and country - and on nothing else. Not the thumbprint and not the issuer: the two
/// copies of <c>codex.exe</c> on the machine this was written on are signed by different certificates,
/// issued by different intermediate CAs ("Microsoft ID Verified CS AOC CA 04" and "... EOC CA 04"),
/// with the same subject. Services such as Azure Trusted Signing issue a certificate that lives for
/// days, so a thumbprint would change with nearly every build.
/// </para>
/// <para>
/// The attributes left out are the ones that change without the publisher changing: an EV
/// certificate adds a serial number, a business category and a jurisdiction; an organisational unit
/// or a street address moves with the org chart. AppLocker's publisher rules draw the same line,
/// which is the reason to draw it here too rather than invent a new one.
/// </para>
/// <para>
/// Pure string work. The engine and the app extract the attributes from a certificate they have
/// already verified; this type only decides which of them are identity.
/// </para>
/// </remarks>
public static class PublisherName
{
    /// <summary>The attributes that make up a publisher, in the order they are written.</summary>
    private static readonly string[] IdentityAttributes = ["CN", "O", "L", "S", "C"];

    /// <summary>
    /// The canonical publisher key for a certificate subject, or empty when it has none of the
    /// identifying attributes.
    /// </summary>
    /// <param name="subject">
    /// Relative distinguished names as short attribute name and value. <c>ST</c> is accepted as a
    /// spelling of <c>S</c>. When an attribute repeats, the first occurrence counts.
    /// </param>
    public static string Canonical(IEnumerable<KeyValuePair<string, string>> subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (rawKey, rawValue) in subject)
        {
            var key = rawKey.Trim().Equals("ST", StringComparison.OrdinalIgnoreCase) ? "S" : rawKey.Trim();
            var value = Clean(rawValue);

            if (value.Length > 0 && !values.ContainsKey(key))
            {
                values[key] = value;
            }
        }

        var builder = new StringBuilder();
        foreach (var attribute in IdentityAttributes)
        {
            if (!values.TryGetValue(attribute, out var value))
            {
                continue;
            }

            if (builder.Length > 0)
            {
                builder.Append(';');
            }

            builder.Append(attribute).Append('=').Append(Escape(value.ToUpperInvariant()));
        }

        return builder.ToString();
    }

    /// <summary>Canonical key for a distinguished name written the way .NET formats one.</summary>
    public static string Canonical(string? distinguishedName) =>
        string.IsNullOrWhiteSpace(distinguishedName) ? string.Empty : Canonical(Parse(distinguishedName));

    /// <summary>
    /// Splits a distinguished name into attribute and value pairs.
    /// </summary>
    /// <remarks>
    /// Handles the form <c>X509Certificate2.Subject</c> produces - <c>CN="OpenAI OpCo, LLC", O=...</c> -
    /// where a value containing a separator is quoted and a quote inside it is doubled, and the
    /// backslash escapes of RFC 4514. A comma inside quotes is part of the value; getting that wrong is
    /// exactly how the previous picker recorded this publisher as "OpenAI OpCo".
    /// </remarks>
    public static IReadOnlyList<KeyValuePair<string, string>> Parse(string distinguishedName)
    {
        ArgumentNullException.ThrowIfNull(distinguishedName);

        var result = new List<KeyValuePair<string, string>>();
        var index = 0;
        var text = distinguishedName;

        while (index < text.Length)
        {
            while (index < text.Length && (text[index] is ',' or ';' or '+' || char.IsWhiteSpace(text[index])))
            {
                index++;
            }

            var equals = text.IndexOf('=', index);
            if (equals < 0)
            {
                break;
            }

            var key = text[index..equals].Trim();
            index = equals + 1;

            while (index < text.Length && char.IsWhiteSpace(text[index]))
            {
                index++;
            }

            var value = new StringBuilder();
            if (index < text.Length && text[index] == '"')
            {
                index++;
                while (index < text.Length)
                {
                    if (text[index] == '"')
                    {
                        if (index + 1 < text.Length && text[index + 1] == '"')
                        {
                            value.Append('"');
                            index += 2;
                            continue;
                        }

                        index++;
                        break;
                    }

                    value.Append(text[index++]);
                }

                while (index < text.Length && text[index] is not (',' or ';' or '+'))
                {
                    index++;
                }
            }
            else
            {
                while (index < text.Length && text[index] is not (',' or ';' or '+'))
                {
                    if (text[index] == '\\' && index + 1 < text.Length)
                    {
                        index++;
                    }

                    value.Append(text[index++]);
                }
            }

            if (key.Length > 0)
            {
                result.Add(new KeyValuePair<string, string>(key, value.ToString().Trim()));
            }
        }

        return result;
    }

    /// <summary>The common name inside a canonical key, for messages. Upper-cased, as stored.</summary>
    public static string? CommonNameOf(string? canonical)
    {
        if (string.IsNullOrEmpty(canonical) || !canonical.StartsWith("CN=", StringComparison.Ordinal))
        {
            return null;
        }

        var end = 3;
        while (end < canonical.Length && canonical[end] != ';')
        {
            end += canonical[end] == '\\' ? 2 : 1;
        }

        return Unescape(canonical[3..Math.Min(end, canonical.Length)]);
    }

    /// <summary>
    /// Whether a publisher string recorded by a build before schema 2 names this signer.
    /// </summary>
    /// <remarks>
    /// Those builds read the common name by splitting the subject on commas without honouring
    /// quotes, so <c>CN="OpenAI OpCo, LLC"</c> was stored as <c>OpenAI OpCo</c>. The comparison
    /// reproduces that reading rather than guessing at a prefix, so it accepts exactly what the old
    /// code would have written for this certificate and nothing else.
    /// </remarks>
    public static bool MatchesLegacyPublisher(string? legacy, string? signerCommonName)
    {
        if (string.IsNullOrWhiteSpace(legacy) || string.IsNullOrWhiteSpace(signerCommonName))
        {
            return false;
        }

        var cleanLegacy = legacy.Trim().Trim('"').Trim();
        var cleanSigner = signerCommonName.Trim();

        if (cleanLegacy.Equals(cleanSigner, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var truncated = cleanSigner.Split(',')[0].Trim().Trim('"').Trim();
        return cleanLegacy.Equals(truncated, StringComparison.OrdinalIgnoreCase);
    }

    private static string Clean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length);
        var pendingSpace = false;

        foreach (var character in value.Trim())
        {
            if (char.IsWhiteSpace(character))
            {
                pendingSpace = true;
                continue;
            }

            if (pendingSpace && builder.Length > 0)
            {
                builder.Append(' ');
            }

            pendingSpace = false;
            builder.Append(character);
        }

        return builder.ToString();
    }

    private static string Escape(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace(";", "\\;", StringComparison.Ordinal);

    private static string Unescape(string value) =>
        value.Replace("\\;", ";", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal);
}
