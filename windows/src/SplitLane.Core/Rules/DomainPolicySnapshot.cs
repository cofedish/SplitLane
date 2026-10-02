using System.Net;
using SplitLane.Core.Models;

namespace SplitLane.Core.Rules;

/// <summary>Compiled destination rules, consulted by the existing policy resolver.</summary>
internal sealed class DomainPolicySnapshot
{
    private readonly Entry[] _rules;

    public DomainPolicySnapshot(RuntimeConfiguration configuration)
    {
        _rules = configuration.DomainRules.Where(r => r.IsEnabled).Select(rule =>
        {
            if (!DomainPattern.TryParse(rule.Pattern, out var pattern, out _))
            {
                return null;
            }

            var app = rule.ProcessRuleId is { } id
                ? configuration.Rules.FirstOrDefault(r => ExecutablePath.Comparer.Equals(r.Id, id))
                : null;
            if (rule.ProcessRuleId is not null && (app is null || !app.ParticipatesInRouting))
            {
                return null;
            }

            // A scoped domain rule must verify exactly the identity the application selector captured.
            var process = app is null ? null : new RuleSnapshot(new RuntimeConfiguration
            {
                Rules = [app with { Action = RouteAction.ProxyOnly }],
            });
            IPNetwork? network = rule.Destination is null ? null : IPNetwork.Parse(rule.Destination);
            return new Entry(rule, pattern, process, network);
        }).OfType<Entry>()
          .OrderByDescending(e => e.Process is not null)
          .ThenByDescending(e => e.Pattern.Suffix.Length)
          .ThenBy(e => e.Pattern.IsWildcard)
          .ThenByDescending(e => e.Network?.PrefixLength ?? -1)
          .ThenByDescending(e => e.Rule.Protocol is not null)
          .ThenByDescending(e => SafetyRank(e.Rule.Action))
          .ThenBy(e => e.Pattern.Normalized, StringComparer.Ordinal)
          .ToArray();
    }

    public int Count => _rules.Length;
    public bool NeedsProductName => _rules.Any(e => e.Process?.NeedsProductName == true);
    public bool NeedsFileSize => _rules.Any(e => e.Process?.NeedsFileSize == true);

    public bool HasCandidate(in FlowDescriptor flow, bool strictOnly = false)
    {
        if (!DomainPattern.TryNormalize(flow.RemoteHostname, out var hostname))
        {
            return false;
        }

        foreach (var entry in _rules)
        {
            if (strictOnly && entry.Rule.Action is not (RouteAction.ProxyOnly or RouteAction.Block))
            {
                continue;
            }
            if (entry.Pattern.MatchesNormalized(hostname) &&
                (entry.Rule.Protocol is null || entry.Rule.Protocol == flow.Protocol) &&
                (entry.Network is null ||
                 (IPAddress.TryParse(flow.RemoteAddress, out var ip) && entry.Network.Value.Contains(ip))))
            {
                return true;
            }
        }

        return false;
    }

    public RouteDecision? Decide(in FlowDescriptor flow, bool proxiesUdp)
    {
        if (!DomainPattern.TryNormalize(flow.RemoteHostname, out var hostname))
        {
            return null;
        }

        foreach (var entry in _rules)
        {
            var rule = entry.Rule;
            if (!entry.Pattern.MatchesNormalized(hostname) ||
                (rule.Protocol is { } protocol && protocol != flow.Protocol) ||
                (entry.Network is { } network &&
                 (!IPAddress.TryParse(flow.RemoteAddress, out var ip) || !network.Contains(ip))))
            {
                continue;
            }

            if (entry.Process is { } process)
            {
                var match = process.Match(flow.Image ?? ImageEvidence.FromPath(flow.ExecutablePath));
                if (match.Needs != EvidenceNeeds.None)
                {
                    return new RouteDecision(RouteAction.Block, RouteReasonKind.IdentityPending,
                        rule.Pattern, flow.ExecutablePath, match.Needs);
                }

                if (!match.IsMatch)
                {
                    continue;
                }
            }

            var action = rule.Action;
            if (flow.Protocol == FlowProtocol.Udp && !proxiesUdp &&
                action is RouteAction.Proxy or RouteAction.ProxyOnly)
            {
                return new RouteDecision(RouteAction.Block, RouteReasonKind.UdpNotSupported,
                    rule.Pattern, flow.ExecutablePath);
            }

            return new RouteDecision(action, RouteReasonKind.DomainRule, rule.Pattern, flow.ExecutablePath);
        }

        return null;
    }

    private static int SafetyRank(RouteAction action) => action switch
    {
        RouteAction.Block => 3,
        RouteAction.ProxyOnly => 2,
        RouteAction.Proxy => 1,
        _ => 0,
    };

    private sealed record Entry(DomainRule Rule, DomainPattern Pattern, RuleSnapshot? Process, IPNetwork? Network);
}
