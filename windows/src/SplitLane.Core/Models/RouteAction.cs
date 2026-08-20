namespace SplitLane.Core.Models;

/// <summary>
/// Which lane a flow belongs in.
/// </summary>
public enum RouteAction
{
    /// <summary>
    /// Leave the flow alone. On Windows this means the engine never diverts the connection's
    /// packets: they are reinjected byte-for-byte, or — for the overwhelming majority of traffic —
    /// never matched by a divert filter in the first place.
    ///
    /// This is the default for every application the user has not selected, and it is what makes
    /// "unselected apps are untouched" literally true rather than approximately true.
    /// </summary>
    Direct = 0,

    /// <summary>
    /// Relay the flow through the configured upstream proxy.
    /// </summary>
    Proxy = 1,

    /// <summary>
    /// Refuse the flow. Used for selected-app traffic SplitLane cannot carry safely — currently
    /// UDP, which would otherwise escape the proxy silently (ADR 0004).
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
    /// The destination is loopback or link-local. Never proxied, for any app: this is the third
    /// layer of proxy-loop defence (docs/NETWORKING.md §3).
    /// </summary>
    LocalDestination = 3,

    /// <summary>
    /// The flow carried no usable source application identity. On Windows this happens when the
    /// owning process exited before the engine could resolve its image path, or when the process
    /// is protected and cannot be opened at all.
    /// </summary>
    UnidentifiedSource = 4,

    /// <summary>A selected application's UDP flow, refused so it cannot bypass the proxy.</summary>
    UdpNotSupported = 5,

    /// <summary>Routing is paused by the master switch.</summary>
    RoutingDisabled = 6,

    /// <summary>
    /// The flow originated from the SplitLane engine itself. First layer of proxy-loop defence:
    /// the engine's own upstream connection must never be re-diverted into the engine.
    /// </summary>
    EngineSelfTraffic = 7,
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
public readonly record struct RouteDecision(
    RouteAction Action,
    RouteReasonKind Reason,
    string? RuleKey = null,
    string? MatchedPath = null)
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
        RouteReasonKind.UdpNotSupported => "selected-app UDP is refused, not proxied",
        RouteReasonKind.RoutingDisabled => "routing is paused",
        RouteReasonKind.EngineSelfTraffic => "flow belongs to the SplitLane engine itself",
        _ => Reason.ToString(),
    };
}
