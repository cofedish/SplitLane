namespace SplitLane.Core.Rules;

/// <summary>
/// Reads the part of a packaged application's install path that survives an update.
/// </summary>
/// <remarks>
/// <para>
/// A packaged application lives in a directory whose name carries its version:
/// <c>C:\Program Files\WindowsApps\OpenAI.Codex_26.818.3698.0_x64__8wekyb3d8bbwe</c>. The next
/// update installs beside it under a different name, so a rule naming that directory - or the
/// executable inside it - stops matching the moment the application updates itself. Silently, which
/// is the failure this product exists to prevent.
/// </para>
/// <para>
/// The trick that works for ordinary applications does not work here. For Squirrel-style layouts the
/// family root climbs out of the versioned directory; for a packaged application the directory above
/// is <c>WindowsApps</c>, shared by every packaged application on the machine, and a family rule
/// rooted there would put all of them in the proxy lane at once.
/// </para>
/// <para>
/// What does survive is the package family name: the package's name and its publisher hash, with
/// only the version between them changing. <c>OpenAI.Codex_8wekyb3d8bbwe</c> identifies the
/// application across every version it will ever be installed as, and identifies nothing else -
/// the publisher hash is derived from the publisher's certificate subject, so another publisher
/// cannot produce the same one.
/// </para>
/// </remarks>
public static class PackagePath
{
    /// <summary>The directory every packaged application is installed under.</summary>
    private const string PackagesDirectory = @"Program Files\WindowsApps";

    /// <summary>
    /// The package family name for an executable path, or empty when it is not a packaged app.
    /// </summary>
    /// <remarks>
    /// Returns the name and publisher hash joined by an underscore, lower-cased, which is the form
    /// Windows itself uses for a package family name. The version and architecture between them are
    /// exactly what this discards.
    /// </remarks>
    public static string Family(string? executablePath)
    {
        var normalized = ExecutablePath.Normalize(executablePath);

        if (normalized.Length == 0 ||
            normalized.IndexOf(PackagesDirectory, StringComparison.OrdinalIgnoreCase) < 0)
        {
            return string.Empty;
        }

        foreach (var segment in normalized.Split('\\'))
        {
            var family = FamilyOfSegment(segment);
            if (family.Length > 0)
            {
                return family;
            }
        }

        return string.Empty;
    }

    /// <summary>Whether two paths belong to the same packaged application.</summary>
    public static bool SameFamily(string? candidate, string? family)
    {
        if (string.IsNullOrEmpty(family))
        {
            return false;
        }

        var candidateFamily = Family(candidate);
        return candidateFamily.Length > 0 &&
               candidateFamily.Equals(family, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Pulls the family out of one directory name, or returns empty if it is not one.
    /// </summary>
    /// <remarks>
    /// The double underscore before the publisher hash is the marker worth keying on. A single
    /// underscore appears in plenty of ordinary directory names; two in a row, in a directory under
    /// WindowsApps, with a name before the first single underscore and a hash after the double one,
    /// does not happen by accident.
    /// </remarks>
    private static string FamilyOfSegment(string segment)
    {
        var doubleUnderscore = segment.LastIndexOf("__", StringComparison.Ordinal);
        if (doubleUnderscore <= 0)
        {
            return string.Empty;
        }

        var hash = segment[(doubleUnderscore + 2)..];
        if (hash.Length == 0 || hash.Contains('_', StringComparison.Ordinal))
        {
            return string.Empty;
        }

        var firstUnderscore = segment.IndexOf('_', StringComparison.Ordinal);
        if (firstUnderscore <= 0 || firstUnderscore >= doubleUnderscore)
        {
            return string.Empty;
        }

        var name = segment[..firstUnderscore];
        return $"{name}_{hash}".ToLowerInvariant();
    }
}
