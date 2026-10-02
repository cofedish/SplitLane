using SplitLane.Core.Rules;

namespace SplitLane.Core.Models;

/// <summary>A destination policy in the same lane model as application rules.</summary>
public sealed record DomainRule
{
    /// <summary>Exact hostname or subdomain-only wildcard.</summary>
    public required string Pattern { get; init; }

    /// <summary>Optional existing application rule id. Its verified identity and scope are reused.</summary>
    public string? ProcessRuleId { get; init; }

    /// <summary>Optional IP/CIDR restriction, combined with the domain and application.</summary>
    public string? Destination { get; init; }

    /// <summary>Null matches TCP and UDP.</summary>
    public FlowProtocol? Protocol { get; init; }

    /// <summary>Selected lane.</summary>
    public RouteAction Action { get; init; } = RouteAction.ProxyOnly;

    /// <summary>A disabled rule is retained but takes no part in resolution.</summary>
    public bool IsEnabled { get; init; } = true;
}
