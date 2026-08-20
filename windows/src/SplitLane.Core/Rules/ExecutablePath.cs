namespace SplitLane.Core.Rules;

/// <summary>
/// Normalisation and family arithmetic for the Windows routing key.
/// </summary>
/// <remarks>
/// <para>
/// macOS routes on a code signing identifier because that is the only application identity
/// <c>NEFlowMetaData</c> hands the provider. Windows has no equivalent string on the flow: what the
/// kernel gives us at connect time is a <b>process id</b>, and the only stable, cheap identity
/// derivable from it is the <b>full image path</b> of the mapped executable. That is the routing
/// key here. See ADR W-0002.
/// </para>
/// <para>
/// Everything in this type is a pure string operation. It never touches the filesystem — no
/// <c>File.Exists</c>, no <c>GetFullPath</c>, no symlink resolution — because it is called on the
/// routing hot path and because a routing decision must not depend on whether a disk is spinning.
/// The engine normalises once, when it resolves a pid, and the snapshot compares normalised forms.
/// </para>
/// </remarks>
public static class ExecutablePath
{
    /// <summary>
    /// Comparer for every path key in the routing tables.
    /// </summary>
    /// <remarks>
    /// Windows paths are case-insensitive, so the comparer must be too. Using an ordinal
    /// (not culture-aware) comparison is the security-relevant half: culture-aware casing folds
    /// characters differently under a Turkish locale, and a routing table whose contents depend on
    /// the user's language is a table that can be made to miss.
    /// </remarks>
    public static readonly StringComparer Comparer = StringComparer.OrdinalIgnoreCase;

    /// <summary>
    /// Maximum number of ancestor directories examined when resolving a path against family rules.
    /// </summary>
    /// <remarks>
    /// A pathological path with a hundred components must not turn one flow into a hundred
    /// dictionary probes on the hot path. Twelve is well past any real install layout — Chrome's
    /// deepest shipped helper is three directories below its install root — while keeping the worst
    /// case flat.
    ///
    /// <para>
    /// Deriving the bound from the configured rules instead was considered and is wrong for the
    /// same reason it is wrong on macOS: the walk length depends on how deep the <i>flow's</i> path
    /// is relative to the rule, not on the rule's own depth.
    /// </para>
    /// </remarks>
    public const int AncestorWalkLimit = 12;

    /// <summary>
    /// Canonical form of a path, for use as a routing key.
    /// </summary>
    /// <remarks>
    /// Trims whitespace and surrounding quotes, converts forward slashes to backslashes, collapses
    /// runs of separators (except the leading pair of a UNC path), strips a trailing separator, and
    /// rewrites the NT prefixes Windows APIs sometimes hand back. Casing is left alone so the UI can
    /// show the path the way the user's disk spells it; <see cref="Comparer"/> is what makes
    /// comparison case-insensitive.
    /// </remarks>
    public static string Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var value = path.Trim().Trim('"');
        value = value.Replace('/', '\\');

        // \??\C:\... and \\?\C:\... are the same file as C:\..., and both turn up in Win32 API
        // output. Normalising them here means a rule created from one spelling still matches a flow
        // reported with the other.
        if (value.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            value = value[4..];
        }
        else if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            value = @"\\" + value[8..];
        }
        else if (value.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            value = value[4..];
        }

        var isUnc = value.StartsWith(@"\\", StringComparison.Ordinal);
        var body = isUnc ? value[2..] : value;

        while (body.Contains(@"\\", StringComparison.Ordinal))
        {
            body = body.Replace(@"\\", @"\", StringComparison.Ordinal);
        }

        value = isUnc ? @"\\" + body : body;

        // A trailing separator is dropped, except on a bare drive root where it is the path.
        if (value.Length > 3 && value.EndsWith('\\'))
        {
            value = value.TrimEnd('\\');
        }

        return value;
    }

    /// <summary>
    /// The directory a family rule is rooted at: the directory containing the selected executable.
    /// </summary>
    /// <remarks>
    /// This is the Windows analogue of trimming the last dotted label off a bundle identifier.
    /// Returns an empty string for a path with no directory part.
    /// </remarks>
    public static string FamilyRoot(string? executablePath)
    {
        var normalized = Normalize(executablePath);
        return Parent(normalized);
    }

    /// <summary>The parent directory of a normalised path, or empty when there is none.</summary>
    public static string Parent(string normalizedPath)
    {
        if (string.IsNullOrEmpty(normalizedPath))
        {
            return string.Empty;
        }

        var separator = normalizedPath.LastIndexOf('\\');
        if (separator <= 0)
        {
            return string.Empty;
        }

        // "C:\App.exe" -> "C:\", not "C:" — a bare drive letter is not a directory. A drive root has
        // no parent at all; returning itself would make the ancestor walk spin until the limit.
        if (separator == 2 && normalizedPath[1] == ':')
        {
            return normalizedPath.Length == 3 ? string.Empty : normalizedPath[..3];
        }

        // A UNC share root has nothing above it worth walking to.
        if (normalizedPath.StartsWith(@"\\", StringComparison.Ordinal) && separator < 3)
        {
            return string.Empty;
        }

        return normalizedPath[..separator];
    }

    /// <summary>
    /// Ancestor directories of a path, nearest first, bounded by <see cref="AncestorWalkLimit"/>.
    /// </summary>
    /// <remarks>
    /// Nearest-first is what makes a specific rule beat a general one: a family rule on
    /// <c>C:\Program Files\App\bin</c> wins over one on <c>C:\Program Files\App</c> for a binary
    /// living in <c>bin</c>.
    /// </remarks>
    public static IEnumerable<string> Ancestors(string normalizedPath)
    {
        var cursor = normalizedPath;
        for (var step = 0; step < AncestorWalkLimit; step++)
        {
            cursor = Parent(cursor);
            if (string.IsNullOrEmpty(cursor))
            {
                yield break;
            }

            yield return cursor;
        }
    }

    /// <summary>
    /// True when <paramref name="candidatePath"/> lies inside <paramref name="familyRoot"/>.
    /// </summary>
    /// <remarks>
    /// The separator boundary is the security-relevant part, and it is the exact analogue of cutting
    /// a bundle identifier on the dot. A raw prefix test would make a rule for
    /// <c>C:\Program Files\App</c> also match <c>C:\Program Files\Application\evil.exe</c>, which
    /// would let an unrelated program walk into the proxy lane (ADR W-0003).
    /// </remarks>
    public static bool IsUnderFamilyRoot(string candidatePath, string familyRoot)
    {
        if (string.IsNullOrEmpty(candidatePath) || string.IsNullOrEmpty(familyRoot))
        {
            return false;
        }

        if (candidatePath.Length <= familyRoot.Length)
        {
            return false;
        }

        if (!candidatePath.StartsWith(familyRoot, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // "C:\" already ends in the separator; anything else needs one at the cut point.
        var boundaryIndex = familyRoot.EndsWith('\\') ? familyRoot.Length - 1 : familyRoot.Length;
        return candidatePath[boundaryIndex] == '\\';
    }

    /// <summary>
    /// Whether a directory is specific enough to be used as a family root.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This guard has no macOS counterpart and it is the single most important Windows-specific
    /// safety check in the product. On macOS, the family of <c>com.apple.Safari</c> is Safari and
    /// its helpers, and nothing else can be in it. On Windows, the "family" of
    /// <c>C:\Windows\System32\curl.exe</c> would be <c>C:\Windows\System32</c> — every system
    /// binary on the machine. A user who ticks "include helper processes" on a system tool would
    /// silently put the entire operating system into the proxy lane.
    /// </para>
    /// <para>
    /// So shared directories are refused as family roots. The rule can still be created; it is
    /// simply forced to exact matching, which is correct and safe. See ADR W-0003.
    /// </para>
    /// </remarks>
    public static bool IsSafeFamilyRoot(string? familyRoot)
    {
        var root = Normalize(familyRoot);
        if (string.IsNullOrEmpty(root))
        {
            return false;
        }

        var segments = SegmentsAfterVolume(root, out var hasVolume);
        if (!hasVolume)
        {
            return false;
        }

        // A drive root, or a UNC server/share root, is never specific enough.
        if (segments.Length == 0)
        {
            return false;
        }

        var joined = string.Join('\\', segments);

        foreach (var shared in SharedRoots)
        {
            if (joined.Equals(shared, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // Per-user directories are spelled with a username nobody can enumerate ahead of time, so
        // they are matched structurally: users\<name>\<well-known> and everything above it.
        if (segments.Length >= 1 && segments[0].Equals("Users", StringComparison.OrdinalIgnoreCase))
        {
            if (segments.Length <= 2)
            {
                return false;
            }

            var tail = string.Join('\\', segments.Skip(2));
            foreach (var shared in SharedUserRoots)
            {
                if (tail.Equals(shared, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>Display form of a path: the file name, or the whole path when there is none.</summary>
    public static string FileName(string? path)
    {
        var normalized = Normalize(path);
        if (string.IsNullOrEmpty(normalized))
        {
            return string.Empty;
        }

        var separator = normalized.LastIndexOf('\\');
        return separator < 0 || separator == normalized.Length - 1
            ? normalized
            : normalized[(separator + 1)..];
    }

    /// <summary>Splits a normalised path into segments below its volume, drive or UNC share.</summary>
    private static string[] SegmentsAfterVolume(string normalizedRoot, out bool hasVolume)
    {
        hasVolume = false;

        if (normalizedRoot.StartsWith(@"\\", StringComparison.Ordinal))
        {
            // \\server\share\a\b -> server, share consumed as the volume.
            var parts = normalizedRoot[2..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                hasVolume = true;
                return [];
            }

            hasVolume = true;
            return parts.Skip(2).ToArray();
        }

        if (normalizedRoot.Length >= 2 && normalizedRoot[1] == ':')
        {
            hasVolume = true;
            var remainder = normalizedRoot.Length > 2 ? normalizedRoot[2..] : string.Empty;
            return remainder.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        }

        return [];
    }

    /// <summary>Directories shared by many unrelated programs, keyed without a drive letter.</summary>
    private static readonly string[] SharedRoots =
    [
        "Windows",
        @"Windows\System32",
        @"Windows\SysWOW64",
        @"Windows\SystemApps",
        @"Windows\Temp",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "Users",
        "Temp",
        "Tmp",
    ];

    /// <summary>Per-user directories, relative to <c>C:\Users\&lt;name&gt;</c>.</summary>
    private static readonly string[] SharedUserRoots =
    [
        "AppData",
        @"AppData\Local",
        @"AppData\LocalLow",
        @"AppData\Roaming",
        @"AppData\Local\Programs",
        @"AppData\Local\Temp",
        "Desktop",
        "Downloads",
        "Documents",
    ];
}
