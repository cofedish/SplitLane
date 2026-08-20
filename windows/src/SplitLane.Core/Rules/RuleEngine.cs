using SplitLane.Core.Models;

namespace SplitLane.Core.Rules;

/// <summary>
/// Precomputed, immutable lookup tables for one configuration generation.
/// </summary>
/// <remarks>
/// Built once per reload, read on every flow. The engine is consulted for <i>every</i> connection on
/// the system, including the overwhelming majority it will wave straight through, so the hot path
/// must not allocate, must not touch disk, and must not verify a signature. All of that work happens
/// here, once.
/// </remarks>
public sealed class RuleSnapshot
{
    private readonly Dictionary<string, AppRule> _exactRules;
    private readonly Dictionary<string, AppRule> _familyRules;

    /// <summary>Builds a snapshot from a configuration.</summary>
    public RuleSnapshot(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        _exactRules = new Dictionary<string, AppRule>(ExecutablePath.Comparer);
        _familyRules = new Dictionary<string, AppRule>(ExecutablePath.Comparer);

        foreach (var rule in configuration.Rules)
        {
            if (!rule.IsEnabled)
            {
                continue;
            }

            var key = ExecutablePath.Normalize(rule.Identity.ExecutablePath);

            // The validator rejects empty paths, but the snapshot is the last line before the hot
            // path: an empty key here would match every flow whose process could not be resolved.
            if (string.IsNullOrEmpty(key))
            {
                continue;
            }

            _exactRules[key] = rule;

            if (!rule.UsesFamilyMatching)
            {
                continue;
            }

            var root = ExecutablePath.FamilyRoot(key);

            // Belt and braces. `UsesFamilyMatching` already consults `IsSafeFamilyRoot`; repeating
            // it here means no future edit to that property can put `C:\Windows\System32` into the
            // family table, which would proxy the operating system.
            if (!string.IsNullOrEmpty(root) && ExecutablePath.IsSafeFamilyRoot(root))
            {
                _familyRules[root] = rule;
            }
        }

        Proxy = configuration.Proxy;
        Version = configuration.Version;
        IsRoutingEnabled = configuration.IsRoutingEnabled;
        LogsDirectFlows = configuration.LogsDirectFlows;
    }

    /// <summary>The upstream the PROXY lane points at for this generation.</summary>
    public ProxyConfiguration Proxy { get; }

    /// <summary>Schema and generation stamp of the configuration this was built from.</summary>
    public ConfigurationVersion Version { get; }

    /// <summary>Master switch.</summary>
    public bool IsRoutingEnabled { get; }

    /// <summary>Whether DIRECT decisions should be logged individually.</summary>
    public bool LogsDirectFlows { get; }

    /// <summary>An engine with no rules at all. Every flow goes DIRECT.</summary>
    public static readonly RuleSnapshot Empty = new(RuntimeConfiguration.Empty);

    /// <summary>Number of rules that can route traffic. Diagnostic only.</summary>
    public int ActiveRuleCount => _exactRules.Count;

    /// <summary>Number of rules participating in family matching. Diagnostic only.</summary>
    public int FamilyRuleCount => _familyRules.Count;

    /// <summary>
    /// Finds the most specific rule matching an executable path.
    /// </summary>
    /// <remarks>
    /// Exact match first, then ancestor directories nearest-first, so a rule for
    /// <c>C:\Program Files\App\bin</c> wins over one for <c>C:\Program Files\App</c>.
    /// </remarks>
    public bool TryGetRule(string executablePath, out AppRule rule, out bool isExact)
    {
        rule = null!;
        isExact = false;

        if (string.IsNullOrEmpty(executablePath))
        {
            return false;
        }

        if (_exactRules.TryGetValue(executablePath, out var exact))
        {
            rule = exact;
            isExact = true;
            return true;
        }

        if (_familyRules.Count == 0)
        {
            return false;
        }

        foreach (var ancestor in ExecutablePath.Ancestors(executablePath))
        {
            if (_familyRules.TryGetValue(ancestor, out var family))
            {
                rule = family;
                isExact = false;
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// Decides which lane a flow belongs in.
/// </summary>
/// <remarks>
/// Pure and synchronous by design: no I/O, no locking, no async. Concurrency is handled one level up
/// by the engine runtime, which swaps whole snapshots; this type only ever reads one.
/// </remarks>
public sealed class RuleEngine
{
    /// <summary>Builds an engine over a prepared snapshot.</summary>
    public RuleEngine(RuleSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        Snapshot = snapshot;
    }

    /// <summary>Builds an engine over a configuration, preparing the snapshot.</summary>
    public RuleEngine(RuntimeConfiguration configuration)
        : this(new RuleSnapshot(configuration))
    {
    }

    /// <summary>The tables this engine reads.</summary>
    public RuleSnapshot Snapshot { get; }

    /// <summary>
    /// The routing decision for a flow.
    /// </summary>
    /// <remarks>
    /// Order matters, and each early return encodes a rule from the threat model:
    /// <list type="number">
    /// <item>Engine's own traffic goes DIRECT, always. Without this the upstream connection would be
    /// re-diverted into the engine and loop, which is the one failure mode that takes the machine's
    /// networking with it.</item>
    /// <item>Routing disabled goes DIRECT. A paused SplitLane must be inert, not half-active.</item>
    /// <item>Local destination goes DIRECT, for every app. Second layer of loop defence.</item>
    /// <item>Unidentified source goes DIRECT. A process that could not be resolved is not a
    /// selected app.</item>
    /// <item>No rule goes DIRECT. The product's default.</item>
    /// <item>Selected app plus UDP is BLOCKED. Fail closed rather than let QUIC escape (ADR 0004).</item>
    /// <item>Selected app plus TCP goes to PROXY.</item>
    /// </list>
    /// </remarks>
    public RouteDecision Decide(in FlowDescriptor flow)
    {
        if (flow.IsEngineTraffic)
        {
            return new RouteDecision(RouteAction.Direct, RouteReasonKind.EngineSelfTraffic);
        }

        if (!Snapshot.IsRoutingEnabled)
        {
            return new RouteDecision(RouteAction.Direct, RouteReasonKind.RoutingDisabled);
        }

        if (flow.HasLocalDestination)
        {
            return new RouteDecision(RouteAction.Direct, RouteReasonKind.LocalDestination);
        }

        var path = flow.ExecutablePath;
        if (string.IsNullOrEmpty(path))
        {
            return new RouteDecision(RouteAction.Direct, RouteReasonKind.UnidentifiedSource);
        }

        if (!Snapshot.TryGetRule(path, out var rule, out var isExact))
        {
            return RouteDecision.DirectDefault;
        }

        var reason = isExact ? RouteReasonKind.ExactRule : RouteReasonKind.ExecutableFamilyRule;
        var ruleKey = rule.Identity.ExecutablePath;

        switch (rule.EffectiveAction)
        {
            case RouteAction.Direct:
                return new RouteDecision(RouteAction.Direct, reason, ruleKey, path);

            case RouteAction.Block:
                return new RouteDecision(RouteAction.Block, reason, ruleKey, path);

            case RouteAction.Proxy:
                // A selected app's UDP is refused, not passed through. Returning DIRECT here would
                // be the silent QUIC bypass the whole design exists to prevent; the app sees the
                // failure and falls back to TCP, which is proxied correctly.
                if (flow.Protocol == FlowProtocol.Udp)
                {
                    return new RouteDecision(
                        RouteAction.Block, RouteReasonKind.UdpNotSupported, ruleKey, path);
                }

                return new RouteDecision(RouteAction.Proxy, reason, ruleKey, path);

            default:
                return RouteDecision.DirectDefault;
        }
    }
}
