using System.Globalization;
using System.Net;

namespace SplitLane.Core.Rules;

/// <summary>A validated exact hostname or subdomain-only wildcard, compiled on reload.</summary>
public sealed class DomainPattern
{
    private DomainPattern(string suffix, bool wildcard)
    {
        Suffix = suffix;
        IsWildcard = wildcard;
    }

    /// <summary>The normalized ASCII suffix.</summary>
    public string Suffix { get; }

    /// <summary>Whether this matches subdomains, excluding the apex.</summary>
    public bool IsWildcard { get; }

    /// <summary>The canonical configuration spelling.</summary>
    public string Normalized => IsWildcard ? "*." + Suffix : Suffix;

    /// <summary>Validates a user pattern without throwing on malformed input.</summary>
    public static bool TryParse(string? value, out DomainPattern pattern, out string? error)
    {
        pattern = null!;
        var wildcard = value?.StartsWith("*.", StringComparison.Ordinal) == true;
        if (!TryNormalize(wildcard ? value![2..] : value, out var normalized))
        {
            error = "Use a hostname or *.hostname; wildcards match subdomains only.";
            return false;
        }

        pattern = new DomainPattern(normalized, wildcard);
        error = null;
        return true;
    }

    /// <summary>Normalizes case, a terminal root dot and IDNs, rejecting IP literals and bad labels.</summary>
    public static bool TryNormalize(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrEmpty(value) || value.Length > 1024 || value != value.Trim())
        {
            return false;
        }

        if (value.EndsWith('.'))
        {
            value = value[..^1];
        }

        try
        {
            var ascii = new IdnMapping { UseStd3AsciiRules = true }.GetAscii(value).ToLowerInvariant();
            if (ascii.Length is 0 or > 253 || IPAddress.TryParse(ascii, out _))
            {
                return false;
            }

            foreach (var label in ascii.Split('.'))
            {
                if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-' ||
                    label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
                {
                    return false;
                }
            }

            normalized = ascii;
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>Matches a hostname on label boundaries.</summary>
    public bool Matches(string? hostname) =>
        TryNormalize(hostname, out var normalized) && MatchesNormalized(normalized);

    /// <summary>Matches already normalized observer evidence without allocating.</summary>
    public bool MatchesNormalized(string hostname) => IsWildcard
        ? hostname.Length > Suffix.Length + 1 && hostname.EndsWith(Suffix, StringComparison.Ordinal) &&
          hostname[hostname.Length - Suffix.Length - 1] == '.'
        : string.Equals(hostname, Suffix, StringComparison.Ordinal);
}
