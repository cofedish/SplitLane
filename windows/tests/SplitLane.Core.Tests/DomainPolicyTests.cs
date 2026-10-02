using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

public sealed class DomainPolicyTests
{
    private const string Browser = @"C:\Program Files\Browser\browser.exe";

    private static AppIdentity Identity(string path) => new()
    {
        Kind = IdentityKind.Path,
        ExecutablePath = path,
        DisplayName = Path.GetFileNameWithoutExtension(path),
    };

    private static FlowDescriptor Flow(
        string path = Browser,
        string host = "api.example.com",
        string address = "203.0.113.10",
        FlowProtocol protocol = FlowProtocol.Tcp) =>
        new(42, path, address, 443, protocol, host);

    [Theory]
    [InlineData(RouteAction.Direct)]
    [InlineData(RouteAction.Proxy)]
    [InlineData(RouteAction.ProxyOnly)]
    [InlineData(RouteAction.Block)]
    public void EveryDomainActionIsResolved(RouteAction action)
    {
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            DomainRules = [new DomainRule { Pattern = "*.example.com", Action = action }],
        });

        Assert.Equal(action, engine.Decide(Flow()).Action);
    }

    [Fact]
    public void ProcessAndDomainBeatsDomainOnlyWhichBeatsProcessOnly()
    {
        var app = new AppRule { Identity = Identity(Browser), Action = RouteAction.Proxy };
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            Rules = [app],
            DomainRules =
            [
                new DomainRule { Pattern = "*.example.com", Action = RouteAction.Block },
                new DomainRule
                {
                    Pattern = "api.example.com",
                    ProcessRuleId = app.Id,
                    Action = RouteAction.Direct,
                },
            ],
        });

        Assert.Equal(RouteAction.Direct, engine.Decide(Flow()).Action);
        Assert.Equal(RouteAction.Block, engine.Decide(Flow(host: "cdn.example.com")).Action);
        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(host: "unrelated.test")).Action);
    }

    [Fact]
    public void RuleOrderDoesNotChangeSpecificity()
    {
        DomainRule broad = new() { Pattern = "*.example.com", Action = RouteAction.Block };
        DomainRule exact = new() { Pattern = "api.example.com", Action = RouteAction.ProxyOnly };

        var first = new RuleEngine(new RuntimeConfiguration { DomainRules = [broad, exact] });
        var second = new RuleEngine(new RuntimeConfiguration { DomainRules = [exact, broad] });

        Assert.Equal(RouteAction.ProxyOnly, first.Decide(Flow()).Action);
        Assert.Equal(RouteAction.ProxyOnly, second.Decide(Flow()).Action);
    }

    [Fact]
    public void ProtocolSpecificRuleBeatsAnyProtocolRule()
    {
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            DomainRules =
            [
                new DomainRule { Pattern = "api.example.com", Action = RouteAction.Direct },
                new DomainRule
                {
                    Pattern = "api.example.com",
                    Protocol = FlowProtocol.Udp,
                    Action = RouteAction.Block,
                },
            ],
        });

        Assert.Equal(RouteAction.Direct, engine.Decide(Flow()).Action);
        Assert.Equal(RouteAction.Block, engine.Decide(Flow(protocol: FlowProtocol.Udp)).Action);
    }

    [Fact]
    public void ProxyOnlyUdpFailsClosedWhenTheProxyCannotCarryDatagrams()
    {
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            ProxiesUdp = false,
            DomainRules = [new DomainRule { Pattern = "api.example.com", Action = RouteAction.ProxyOnly }],
        });

        var decision = engine.Decide(Flow(protocol: FlowProtocol.Udp));

        Assert.Equal(RouteAction.Block, decision.Action);
        Assert.Equal(RouteReasonKind.UdpNotSupported, decision.Reason);
    }

    [Fact]
    public void DomainOnlyRulesStillApplyWhenTheProcessIsUnknown()
    {
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            DomainRules = [new DomainRule { Pattern = "api.example.com", Action = RouteAction.Block }],
        });

        Assert.Equal(RouteAction.Block, engine.Decide(Flow(path: string.Empty)).Action);
    }

    [Fact]
    public void UnknownHostnameFallsBackToTheApplicationRule()
    {
        var app = new AppRule { Identity = Identity(Browser), Action = RouteAction.Proxy };
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            Rules = [app],
            DomainRules = [new DomainRule { Pattern = "api.example.com", Action = RouteAction.Block }],
        });

        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(host: null!)).Action);
    }
}
