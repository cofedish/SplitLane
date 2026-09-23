using System.Text.Json.Serialization;

namespace SplitLane.Core.Models;

/// <summary>
/// How much of an application a rule covers.
/// </summary>
/// <remarks>
/// What each mode compares depends on the identity's <see cref="IdentityKind"/>; the stored values
/// are the ones schema 1 used, so an old configuration keeps its meaning.
/// </remarks>
public enum MatchMode
{
    /// <summary>Match only this executable.</summary>
    /// <remarks>
    /// <para>
    /// For a signed application: this file name, signed by this publisher, with this product name -
    /// wherever it is installed and whatever version it is. For a packaged one: this file name in
    /// this package family. For an unsigned one: these exact bytes. For a schema 1 path rule: this
    /// path.
    /// </para>
    /// <para>
    /// On Windows this is far more often sufficient than the macOS equivalent, because Chromium and
    /// Electron helpers are the <i>same</i> binary re-launched with <c>--type=renderer</c> rather
    /// than a separate bundle. An exact rule on <c>chrome.exe</c> already covers every renderer.
    /// </para>
    /// </remarks>
    Exact = 0,

    /// <summary>
    /// Match this executable and the rest of its application.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The default, and not merely a convenience: applications that ship a separate networking
    /// helper, an updater, or a sandboxed child in a subdirectory would otherwise produce a rule
    /// that never matches the process actually opening the socket.
    /// </para>
    /// <para>
    /// For a signed application the rest is the same publisher's binaries that either carry the same
    /// product name or live under the same install directory, above any version or hash directory
    /// (<see cref="Rules.ExecutablePath.InstallRoot"/>). A file there that is unsigned, or signed by
    /// someone else, is not part of it. For a packaged application the rest is the package. For a
    /// schema 1 path rule it is everything under the directory, cut on the separator.
    /// </para>
    /// <para>
    /// Refused, and downgraded to <see cref="Exact"/> by the validator, for an unsigned application
    /// and when the install directory is a shared one such as <c>C:\Windows\System32</c> with no
    /// product name to fall back on. See ADR W-0003 and ADR W-0013.
    /// </para>
    /// </remarks>
    ExecutableFamily = 1,

    /// <summary>
    /// Match every version of this packaged application.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For applications installed from the Store, and only for those. Their install directory
    /// carries a version, so an exact rule stops matching the moment the application updates - and
    /// family matching cannot help, because the directory above is <c>WindowsApps</c>, shared with
    /// every other packaged application on the machine.
    /// </para>
    /// <para>
    /// This matches on the package family name instead: the package's name and publisher hash, which
    /// are the same across every version. It is no broader than an exact rule in what it covers -
    /// one application, one publisher - and unlike an exact rule it survives an update.
    /// </para>
    /// </remarks>
    PackageFamily = 2,
}

/// <summary>Whether a rule can take part in routing, or is waiting for the user.</summary>
public enum RuleStatus
{
    /// <summary>The rule routes.</summary>
    Active = 0,

    /// <summary>
    /// SplitLane could not establish what application this rule means, and will not guess.
    /// </summary>
    /// <remarks>
    /// Produced by migration when a schema 1 rule names a file that is gone and no newer build of the
    /// same publisher's application can be found in its place, or a file whose signature no longer
    /// names the publisher the rule was made for. The rule routes nothing - neither to the proxy nor,
    /// by being mistaken for another application, anywhere else - and the interface says so and offers
    /// to pick the application again. See <see cref="AppRule.StatusDetail"/>.
    /// </remarks>
    NeedsReselection = 1,
}

/// <summary>
/// A user-configured routing rule: "this application belongs in this lane".
/// </summary>
public sealed record AppRule
{
    /// <summary>The application this rule is about.</summary>
    public required AppIdentity Identity { get; init; }

    /// <summary>
    /// Lane assignment.
    /// </summary>
    /// <remarks>
    /// <see cref="RouteAction.Direct"/> is a meaningful stored value: it records an application the
    /// user looked at and deliberately left alone, which the UI shows differently from one it has
    /// never seen.
    /// </remarks>
    public RouteAction Action { get; init; } = RouteAction.Proxy;

    /// <summary>How much of the application the rule covers.</summary>
    public MatchMode MatchMode { get; init; } = MatchMode.ExecutableFamily;

    /// <summary>
    /// Whether the rule participates in routing at all.
    /// </summary>
    /// <remarks>
    /// A disabled rule is retained rather than deleted so that toggling an application off and on
    /// again does not lose its captured identity — including the publisher, which requires the
    /// executable to still be on disk to re-capture.
    /// </remarks>
    public bool IsEnabled { get; init; } = true;

    /// <summary>Optional user note, shown in the Applications list.</summary>
    public string? Note { get; init; }

    /// <summary>Whether the rule can route, or needs the user first.</summary>
    public RuleStatus Status { get; init; } = RuleStatus.Active;

    /// <summary>
    /// What happened to this rule that the user should know: why it needs re-selecting, or what a
    /// migration changed about it. Plain language, shown in the Applications list.
    /// </summary>
    public string? StatusDetail { get; init; }

    /// <summary>
    /// Whether the rule comes from the machine's managed policy rather than the user.
    /// </summary>
    /// <remarks>
    /// Set only by <see cref="Configuration.PolicyMerger"/>, never read from a document: it is not part
    /// of the JSON contract, so a user who writes <c>"isManaged": true</c> into their own configuration
    /// has it read past, and their rule stays theirs.
    /// </remarks>
    [JsonIgnore]
    public bool IsManaged { get; init; }

    /// <summary>Stable identity, equal to the path the application was picked from.</summary>
    [JsonIgnore]
    public string Id => Identity.ExecutablePath;

    /// <summary>The lane this rule actually routes to right now.</summary>
    [JsonIgnore]
    public RouteAction EffectiveAction => IsEnabled ? Action : RouteAction.Direct;

    /// <summary>Whether the rule is enabled and not waiting to be re-selected.</summary>
    [JsonIgnore]
    public bool ParticipatesInRouting => IsEnabled && Status == RuleStatus.Active;

    /// <summary>
    /// Whether family matching is both requested and permitted.
    /// </summary>
    /// <remarks>
    /// A rule can ask for family matching on a shared directory, or on an unsigned file; it does not
    /// get it. The snapshot consults this rather than <see cref="MatchMode"/> so that a configuration
    /// written by an older build, or hand-edited, cannot smuggle <c>C:\Windows\System32</c> - or a
    /// folder anyone can drop a file into - into the family tables.
    /// </remarks>
    [JsonIgnore]
    public bool UsesFamilyMatching => Identity.Kind switch
    {
        IdentityKind.Signed => MatchMode != MatchMode.Exact && Identity.SupportsFamilyMatching,
        IdentityKind.Path => MatchMode == MatchMode.ExecutableFamily && Identity.SupportsFamilyMatching,
        _ => false,
    };

    /// <summary>Whether package matching is both requested and possible.</summary>
    /// <remarks>
    /// <para>
    /// Asked of the identity rather than assumed from the mode, so a configuration written by hand,
    /// or by an older build, cannot ask for package matching on a path that has no package in it.
    /// </para>
    /// <para>
    /// <see cref="MatchMode.ExecutableFamily"/> counts too, for a packaged application. It means the
    /// same thing the user meant when they asked for it - cover the rest of this application, not
    /// only the file I picked - and for a packaged application the install directory cannot deliver
    /// that: the directory is named after the version, so a family rooted there covers one version
    /// and is left behind by the next update, and the directory above it is <c>WindowsApps</c>, which
    /// W-0003 refuses. Reading the request as the one mechanism that can honour it also means rules
    /// written before package matching existed started working rather than waiting to be re-made.
    /// </para>
    /// </remarks>
    [JsonIgnore]
    public bool UsesPackageMatching => Identity.Kind switch
    {
        IdentityKind.Package => MatchMode != MatchMode.Exact,
        IdentityKind.Path => MatchMode is MatchMode.PackageFamily or MatchMode.ExecutableFamily &&
                             Identity.SupportsPackageMatching,
        _ => false,
    };
}
