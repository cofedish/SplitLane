using System.Text.Json.Serialization;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Models;

/// <summary>
/// What an application is, for the purpose of recognising it again later.
/// </summary>
/// <remarks>
/// <para>
/// Only <see cref="Path"/> identifies an application by where it is. It is what every rule was before
/// schema 2, and it is why rules stopped matching: an update that moves an application into a new
/// version or hash directory, a folder the user moved, or a packaged application moved to another
/// drive all change the path and nothing else. The other kinds identify the application by something
/// that survives those, and that nothing else can copy. See ADR W-0013.
/// </para>
/// </remarks>
public enum IdentityKind
{
    /// <summary>
    /// The executable's path, as schema 1 recorded every rule. Kept so an old configuration keeps its
    /// meaning until it is migrated; never produced for a new rule.
    /// </summary>
    Path = 0,

    /// <summary>
    /// A verified Authenticode signer, the product name, and the file name. Location and version are
    /// deliberately not part of it.
    /// </summary>
    Signed = 1,

    /// <summary>A packaged (MSIX/Store) application's package family name.</summary>
    Package = 2,

    /// <summary>
    /// The SHA-256 of an unsigned executable's bytes. An unsigned file has nothing else that a copy or a
    /// replacement could not also have, so its identity is its content and it does not follow updates.
    /// </summary>
    Unsigned = 3,
}

/// <summary>
/// Everything SplitLane knows about an application the user picked.
/// </summary>
/// <remarks>
/// <para>
/// The engine resolves a process id to an image path at connect time; what it compares that process
/// against depends on <see cref="Kind"/>. <see cref="ExecutablePath"/> is kept for every kind - to show
/// where the application was picked, and as a location pin: a file at that path whose identity no
/// longer matches is refused rather than routed either way (<see cref="RouteReasonKind.IdentityMismatch"/>).
/// </para>
/// </remarks>
public sealed record AppIdentity
{
    /// <summary>
    /// Full path of the executable when it was picked, in the form produced by
    /// <see cref="Rules.ExecutablePath.Normalize"/>. The routing key only for <see cref="IdentityKind.Path"/>.
    /// </summary>
    public required string ExecutablePath { get; init; }

    /// <summary>User-facing name. Falls back to the file name when no product name is available.</summary>
    public required string DisplayName { get; init; }

    /// <summary>How the application is recognised. See <see cref="IdentityKind"/>.</summary>
    public IdentityKind Kind { get; init; }

    /// <summary>
    /// Common name of the signing certificate, for display.
    /// </summary>
    /// <remarks>
    /// Rules written before schema 2 stored this from a certificate that was extracted but never
    /// verified, and cut at the first comma (<c>OpenAI OpCo</c> for <c>"OpenAI OpCo, LLC"</c>).
    /// Migration compares it the way it was written; see <see cref="PublisherName.MatchesLegacyPublisher"/>.
    /// Never used for matching: <see cref="SignerSubject"/> is.
    /// </remarks>
    public string? Publisher { get; init; }

    /// <summary>
    /// Canonical key of the verified signer, for <see cref="IdentityKind.Signed"/>. See
    /// <see cref="PublisherName"/>.
    /// </summary>
    public string? SignerSubject { get; init; }

    /// <summary>
    /// <c>ProductName</c> from the version resource when the application was picked. Part of a signed
    /// identity when present; many command-line tools have no version resource at all.
    /// </summary>
    public string? ProductName { get; init; }

    /// <summary>
    /// The file name a signed or packaged identity is bound to, e.g. <c>codex.exe</c>.
    /// </summary>
    /// <remarks>
    /// The on-disk name rather than the version resource's <c>OriginalFilename</c>: every Electron
    /// application reports <c>chrome.exe</c> there - <c>ChatGPT.exe</c> does - and command-line tools
    /// written in Rust or Go usually have no version resource to report anything from.
    /// </remarks>
    public string? BinaryName { get; init; }

    /// <summary>
    /// <c>OriginalFilename</c> from the signed, language-neutral version resource, when it has one.
    /// </summary>
    /// <remarks>
    /// Checked in addition to <see cref="BinaryName"/>, not instead of it: the on-disk name finds the
    /// candidates, and this refuses one that was renamed. Without it, any binary a publisher signs
    /// could be copied under the selected binary's name and inherit its rule - every inbox Windows
    /// tool shares one signer and one product name, so for those the name was the only thing left.
    /// </remarks>
    public string? OriginalFileName { get; init; }

    /// <summary>
    /// Program database name from the image's CodeView record (<c>codex.pdb</c>), when it has one.
    /// </summary>
    /// <remarks>
    /// Checked only when there is no <see cref="OriginalFileName"/>: it is the one name a binary with no
    /// version resource carries inside its signature. Without it, a signed command-line tool's identity
    /// was its publisher and its file name, and a different binary from the same publisher, renamed, was
    /// the same application.
    /// </remarks>
    public string? DebugName { get; init; }

    /// <summary>Lower-case hex SHA-256 of the file, for <see cref="IdentityKind.Unsigned"/>.</summary>
    public string? FileSha256 { get; init; }

    /// <summary>Size of the file in bytes, for <see cref="IdentityKind.Unsigned"/>. A cheap first filter.</summary>
    public long? FileSize { get; init; }

    /// <summary>
    /// <c>FileDescription</c> from the executable's version resource, when present. Display only -
    /// this is the string Task Manager shows, so showing it too makes rules recognisable.
    /// </summary>
    public string? FileDescription { get; init; }

    /// <summary>
    /// Package family name of a packaged (MSIX/Store) application: the identity for
    /// <see cref="IdentityKind.Package"/>.
    /// </summary>
    /// <remarks>
    /// Compared case-insensitively. Windows spells it <c>OpenAI.Codex_2p2nqsd0c76g0</c>;
    /// <see cref="PackagePath.Family"/> produces the lower-case form from a path.
    /// </remarks>
    public string? PackageFamilyName { get; init; }

    /// <summary>When the identity was captured.</summary>
    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Stable identity of this record in the list: the path it was picked from.</summary>
    [JsonIgnore]
    public string Id => ExecutablePath;

    /// <summary>
    /// A string that is equal for two identities exactly when they recognise the same application.
    /// </summary>
    /// <remarks>Used to refuse adding the same application twice from two of its installations.</remarks>
    [JsonIgnore]
    public string MatchKey => Kind switch
    {
        IdentityKind.Signed =>
            $"signed|{SignerSubject}|{ProductFamily.Normalize(ProductName)}|{BinaryName?.ToUpperInvariant()}",
        IdentityKind.Package =>
            $"package|{PackageFamilyName?.ToUpperInvariant()}|{BinaryName?.ToUpperInvariant()}",
        IdentityKind.Unsigned => $"sha256|{FileSha256}",
        _ => $"path|{Rules.ExecutablePath.Normalize(ExecutablePath).ToUpperInvariant()}",
    };

    /// <summary>Whether the identity survives an update or a move, i.e. is anything but a path.</summary>
    [JsonIgnore]
    public bool IsVerified => Kind is IdentityKind.Signed or IdentityKind.Package or IdentityKind.Unsigned;

    /// <summary>The directory a path-keyed family rule for this application would be rooted at.</summary>
    [JsonIgnore]
    public string FamilyRoot => Rules.ExecutablePath.FamilyRoot(ExecutablePath);

    /// <summary>
    /// The install directory a signed family rule covers: above any version or hash directory the
    /// application's updater renames. See <see cref="Rules.ExecutablePath.InstallRoot"/>.
    /// </summary>
    [JsonIgnore]
    public string InstallRoot => Rules.ExecutablePath.InstallRoot(ExecutablePath);

    /// <summary>
    /// Whether "include helpers" can mean anything safe for this application.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    /// <item>Signed: the install directory is specific to it, or its product name is not a shared
    /// platform's (<see cref="ProductFamily.CanRootFamily"/>).</item>
    /// <item>Package: always; the package is the family.</item>
    /// <item>Unsigned: never. A family of unsigned files is a folder anyone who can write to it can join,
    /// which is how a dropped-in file inherited a rule before schema 2.</item>
    /// <item>Path: the install directory is not shared (ADR W-0003).</item>
    /// </list>
    /// </remarks>
    [JsonIgnore]
    public bool SupportsFamilyMatching => Kind switch
    {
        IdentityKind.Signed => Rules.ExecutablePath.IsSafeFamilyRoot(InstallRoot) || ProductFamily.CanRootFamily(ProductName, SignerSubject),
        IdentityKind.Package => true,
        IdentityKind.Unsigned => false,
        _ => Rules.ExecutablePath.IsSafeFamilyRoot(FamilyRoot),
    };

    /// <summary>True when the application is packaged, by identity or by where it was picked.</summary>
    [JsonIgnore]
    public bool IsPackaged =>
        Kind == IdentityKind.Package ||
        PackageFamilyName is not null ||
        ExecutablePath.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The package family a path-keyed rule would be matched on, or empty. See
    /// <see cref="Rules.PackagePath"/>.
    /// </summary>
    [JsonIgnore]
    public string PackageFamily => Kind == IdentityKind.Package && !string.IsNullOrEmpty(PackageFamilyName)
        ? PackageFamilyName.ToLowerInvariant()
        : Rules.PackagePath.Family(ExecutablePath);

    /// <summary>Whether this application can be matched by package family rather than by path.</summary>
    [JsonIgnore]
    public bool SupportsPackageMatching => PackageFamily.Length > 0;

    /// <summary>
    /// The directory name that carries a packaged application's version, e.g.
    /// <c>OpenAI.Codex_26.917.6896.0_x64__2p2nqsd0c76g0</c>; null when not packaged or not present.
    /// </summary>
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

    /// <summary>Value equality on the path it was picked from, with Windows path casing rules.</summary>
    public bool Equals(AppIdentity? other)
        => other is not null && Rules.ExecutablePath.Comparer.Equals(ExecutablePath, other.ExecutablePath);

    /// <inheritdoc />
    public override int GetHashCode() => Rules.ExecutablePath.Comparer.GetHashCode(ExecutablePath);
}
