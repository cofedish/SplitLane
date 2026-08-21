using System.Text.Json.Serialization;

namespace SplitLane.Core.Models;

/// <summary>
/// How strictly a rule's executable path must match the one on a flow.
/// </summary>
public enum MatchMode
{
    /// <summary>Match only this exact executable.</summary>
    /// <remarks>
    /// On Windows this is far more often sufficient than the macOS equivalent, because Chromium and
    /// Electron helpers are the <i>same</i> binary re-launched with <c>--type=renderer</c> rather
    /// than a separate bundle. An exact rule on <c>chrome.exe</c> already covers every renderer.
    /// </remarks>
    Exact = 0,

    /// <summary>
    /// Match this executable and anything else under its install directory.
    /// </summary>
    /// <remarks>
    /// The default, and not merely a convenience: applications that ship a separate networking
    /// helper, an updater, or a sandboxed child in a subdirectory would otherwise produce a rule
    /// that never matches the process actually opening the socket. Cutting on the path-separator
    /// boundary is what keeps this from over-matching a sibling directory with a shared prefix.
    ///
    /// <para>
    /// Refused, and downgraded to <see cref="Exact"/> by the validator, when the install directory
    /// is a shared one such as <c>C:\Windows\System32</c>. See ADR W-0003.
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

    /// <summary>How the path is matched.</summary>
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

    /// <summary>Stable identity, equal to the routing key.</summary>
    [JsonIgnore]
    public string Id => Identity.ExecutablePath;

    /// <summary>The lane this rule actually routes to right now.</summary>
    [JsonIgnore]
    public RouteAction EffectiveAction => IsEnabled ? Action : RouteAction.Direct;

    /// <summary>
    /// Whether family matching is both requested and permitted.
    /// </summary>
    /// <remarks>
    /// A rule can ask for family matching on a shared directory; it does not get it. The snapshot
    /// consults this rather than <see cref="MatchMode"/> so that a configuration written by an older
    /// build, or hand-edited, cannot smuggle <c>C:\Windows\System32</c> into the family table.
    /// </remarks>
    [JsonIgnore]
    public bool UsesFamilyMatching =>
        MatchMode == MatchMode.ExecutableFamily && Identity.SupportsFamilyMatching;

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
    /// that: it is shared with every other packaged application, so family matching is refused and
    /// the rule quietly narrows to the one version installed at the time. Reading the request as the
    /// one mechanism that can honour it also means rules written before this existed start working
    /// rather than waiting to be re-made.
    /// </para>
    /// </remarks>
    [JsonIgnore]
    public bool UsesPackageMatching =>
        MatchMode is MatchMode.PackageFamily or MatchMode.ExecutableFamily &&
        Identity.SupportsPackageMatching;
}
