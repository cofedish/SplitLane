using System.Text.Json.Serialization;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Models;

/// <summary>
/// Everything SplitLane knows about an application the user picked.
/// </summary>
/// <remarks>
/// <para>
/// The routing key is <see cref="ExecutablePath"/>, because the process image path is the only
/// application identity the Windows kernel makes available at connect time. The engine gets a
/// process id from the socket-layer event and turns it into a path; everything else in this record
/// is for display, for drift detection, and for the hardening path.
/// </para>
/// <para>
/// <see cref="Publisher"/> is the analogue of the macOS team identifier: captured at pick time,
/// deliberately <b>not</b> used for matching in the MVP, and present now so that adding signature
/// pinning later does not force every existing rule to be re-picked. Verifying an Authenticode
/// signature costs milliseconds and touches the disk, which rules it out of the hot path
/// (docs/THREAT_MODEL.md, F-2).
/// </para>
/// </remarks>
public sealed record AppIdentity
{
    /// <summary>
    /// Full path of the executable, in the canonical form produced by
    /// <see cref="Rules.ExecutablePath.Normalize"/>. The routing key.
    /// </summary>
    public required string ExecutablePath { get; init; }

    /// <summary>User-facing name. Falls back to the file name when no product name is available.</summary>
    public required string DisplayName { get; init; }

    /// <summary>
    /// Subject common name from the executable's Authenticode certificate, when it has a valid one.
    /// Null for unsigned binaries and for signatures that did not verify.
    /// </summary>
    /// <remarks>Not used for matching. See the type-level remarks and ADR W-0002.</remarks>
    public string? Publisher { get; init; }

    /// <summary>
    /// <c>FileDescription</c> from the executable's version resource, when present. Display only —
    /// this is the string Task Manager shows, so showing it too makes rules recognisable.
    /// </summary>
    public string? FileDescription { get; init; }

    /// <summary>Package family name for a packaged (MSIX/Store) application, when known.</summary>
    /// <remarks>
    /// Packaged apps run from a versioned directory under <c>C:\Program Files\WindowsApps</c>, so
    /// their path changes on every update. The family name is recorded so the UI can warn that a
    /// path-keyed rule for such an app will need re-picking, which is honest about a real
    /// limitation rather than silently breaking after an update (docs/windows/THREAT_MODEL.md, W-4).
    /// </remarks>
    public string? PackageFamilyName { get; init; }

    /// <summary>When the identity was captured. Used to explain a stale rule in the UI.</summary>
    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Stable identity of this record, equal to the routing key.</summary>
    [JsonIgnore]
    public string Id => ExecutablePath;

    /// <summary>The directory a family rule for this application would be rooted at.</summary>
    [JsonIgnore]
    public string FamilyRoot => Rules.ExecutablePath.FamilyRoot(ExecutablePath);

    /// <summary>
    /// Whether this application can safely use family matching, i.e. whether its install directory
    /// is specific to it rather than shared with unrelated programs.
    /// </summary>
    [JsonIgnore]
    public bool SupportsFamilyMatching => Rules.ExecutablePath.IsSafeFamilyRoot(FamilyRoot);

    /// <summary>True when the executable lives under the packaged-application store.</summary>
    [JsonIgnore]
    public bool IsPackaged =>
        PackageFamilyName is not null ||
        ExecutablePath.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The directory whose name carries a version, for a packaged application.
    /// </summary>
    /// <remarks>
    /// Packaged applications install to <c>WindowsApps\Publisher.Name_1.2.3.0_x64__hash</c>. The
    /// version sits in the directory name, so <b>the path changes on every update</b> and a
    /// path-keyed rule silently stops matching: the application keeps working and quietly goes
    /// DIRECT, which is precisely the failure this product exists to prevent (W-4).
    ///
    /// <para>
    /// Returned so the UI can name the thing that will change rather than warning vaguely. Null
    /// when the application is not packaged, or when the path has no versioned segment.
    /// </para>
    /// </remarks>
    [JsonIgnore]
    public string? VersionedSegment
    {
        get
        {
            if (!IsPackaged)
            {
                return null;
            }

            foreach (var segment in ExecutablePath.Split('\\'))
            {
                // A packaged directory name is Publisher.Name_version_arch__hash. The double
                // underscore before the publisher hash is the reliable marker; a plain underscore
                // appears in plenty of ordinary folder names.
                if (segment.Contains("__", StringComparison.Ordinal) &&
                    segment.Contains('_', StringComparison.Ordinal))
                {
                    return segment;
                }
            }

            return null;
        }
    }

    /// <summary>Value equality on the routing key alone, with Windows path casing rules.</summary>
    public bool Equals(AppIdentity? other)
        => other is not null && Rules.ExecutablePath.Comparer.Equals(ExecutablePath, other.ExecutablePath);

    /// <inheritdoc />
    public override int GetHashCode() => Rules.ExecutablePath.Comparer.GetHashCode(ExecutablePath);
}
