namespace SplitLane.Core.Models;

/// <summary>
/// Which lane a flow belongs in.
/// </summary>
public enum RouteAction
{
    /// <summary>
    /// Leave the flow alone. On Windows the connection's packets are still copied to user mode by the
    /// divert filter and reinjected byte-for-byte: unmodified, but not untouched (THREAT_MODEL W-1).
    ///
    /// This is the default for every application the user has not selected.
    /// </summary>
    Direct = 0,

    /// <summary>
    /// Relay the flow through the configured upstream proxy.
    /// </summary>
    Proxy = 1,

    /// <summary>
    /// Refuse the flow. A lane the user can choose for an application, and the answer for
    /// selected-application traffic SplitLane cannot carry safely: UDP when the proxy will not relay
    /// it, and a flow whose application identity is still being verified or no longer matches its
    /// rule.
    /// </summary>
    Block = 2,
}

/// <summary>
/// Why a flow ended up in the lane it did. Purely diagnostic — routing never branches on it.
/// </summary>
public enum RouteReasonKind
{
    /// <summary>No rule matched; the DIRECT default applied.</summary>
    NoMatchingRule = 0,

    /// <summary>A rule matched this exact executable path.</summary>
    ExactRule = 1,

    /// <summary>
    /// A rule matched an ancestor directory of this executable — typically a helper or updater
    /// living under the same install directory as the application the user picked (ADR W-0003).
    /// </summary>
    ExecutableFamilyRule = 2,

    /// <summary>
    /// The destination is loopback or link-local. Never proxied, for any app: this is the second
    /// layer of proxy-loop defence (docs/NETWORKING.md §6).
    /// </summary>
    LocalDestination = 3,

    /// <summary>
    /// The flow carried no usable source application identity. On Windows this happens when the
    /// owning process exited before the engine could resolve its image path, or when the process
    /// is protected and cannot be opened at all.
    /// </summary>
    UnidentifiedSource = 4,

    /// <summary>
    /// A selected application's UDP flow, refused because relaying UDP is turned off
    /// (<see cref="RuntimeConfiguration.ProxiesUdp"/>). It is never sent DIRECT instead.
    /// </summary>
    UdpNotSupported = 5,

    /// <summary>Routing is paused by the master switch.</summary>
    RoutingDisabled = 6,

    /// <summary>
    /// The flow originated from the SplitLane engine itself. First layer of proxy-loop defence:
    /// the engine's own upstream connection must never be re-diverted into the engine.
    /// </summary>
    EngineSelfTraffic = 7,

    /// <summary>A rule matched the process's package family, read from its token.</summary>
    PackageRule = 8,

    /// <summary>
    /// A rule matched this executable by its verified publisher, product and file name - wherever it
    /// is installed and whatever version it is.
    /// </summary>
    SignedIdentityRule = 9,

    /// <summary>
    /// A rule matched a helper of the selected application: signed by the same publisher, and either
    /// carrying the same product name or installed under the same install directory.
    /// </summary>
    SignedFamilyRule = 10,

    /// <summary>A rule matched the exact bytes of an unsigned executable.</summary>
    FileHashRule = 11,

    /// <summary>
    /// The process claims to be a selected application - its file name, folder or size points at a
    /// rule - and the signature or hash that would confirm it is still being checked. The flow is held,
    /// not sent anywhere, until the answer arrives.
    /// </summary>
    IdentityPending = 12,

    /// <summary>
    /// The file at a rule's recorded location is no longer the application the rule was made for: a
    /// different or missing signature, or different bytes. Refused, so neither the replacement
    /// inherits the rule nor the selected application's traffic leaks out DIRECT.
    /// </summary>
    IdentityMismatch = 13,
}

/// <summary>
/// The outcome of a routing decision, carrying enough context to log it and explain it in the UI
/// without re-deriving anything.
/// </summary>
/// <param name="Action">The lane.</param>
/// <param name="Reason">Why.</param>
/// <param name="RuleKey">
/// The rule that produced the decision, if any. Null for the DIRECT default and for blocks that
/// are protocol-driven rather than rule-driven.
/// </param>
/// <param name="MatchedPath">
/// For a family match, the executable path the flow actually carried — which is not the path on
/// the rule. Showing it verbatim is what explains family matching to a user looking at a helper
/// process they never selected.
/// </param>
/// <param name="Needs">
/// For <see cref="RouteReasonKind.IdentityPending"/>, what has to be read about the executable
/// before the flow can be decided.
/// </param>
public readonly record struct RouteDecision(
    RouteAction Action,
    RouteReasonKind Reason,
    string? RuleKey = null,
    string? MatchedPath = null,
    Rules.EvidenceNeeds Needs = Rules.EvidenceNeeds.None)
{
    /// <summary>No rule matched; DIRECT.</summary>
    public static readonly RouteDecision DirectDefault =
        new(RouteAction.Direct, RouteReasonKind.NoMatchingRule);

    /// <summary>True when the engine has to do something with this flow.</summary>
    public bool RequiresIntervention => Action != RouteAction.Direct;

    /// <summary>Short human-readable form, for logs and the Activity list.</summary>
    public string Explain() => Reason switch
    {
        RouteReasonKind.NoMatchingRule => "no rule matched — DIRECT by default",
        RouteReasonKind.ExactRule => $"exact rule for {RuleKey}",
        RouteReasonKind.ExecutableFamilyRule => $"family rule {RuleKey} matched {MatchedPath}",
        RouteReasonKind.LocalDestination => "destination is loopback or link-local",
        RouteReasonKind.UnidentifiedSource => "source process could not be identified",
        RouteReasonKind.UdpNotSupported => "selected-app UDP is refused because UDP relaying is off",
        RouteReasonKind.RoutingDisabled => "routing is paused",
        RouteReasonKind.EngineSelfTraffic => "flow belongs to the SplitLane engine itself",
        RouteReasonKind.PackageRule => $"package rule for {RuleKey}",
        RouteReasonKind.SignedIdentityRule => $"signed identity of {RuleKey}",
        RouteReasonKind.SignedFamilyRule => $"signed helper of {RuleKey}: {MatchedPath}",
        RouteReasonKind.FileHashRule => $"file hash pinned by {RuleKey}",
        RouteReasonKind.IdentityPending => $"held while {MatchedPath} is verified against {RuleKey}",
        RouteReasonKind.IdentityMismatch => $"{MatchedPath} is no longer the application {RuleKey} was made for",
        _ => Reason.ToString(),
    };
}
