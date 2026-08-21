using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>
/// The routing decision, exercised exhaustively.
/// </summary>
/// <remarks>
/// These are the tests that must never be allowed to go red. Everything else in the product is
/// plumbing around the question "does this flow go DIRECT or PROXY", and every silent-leak failure
/// mode the design exists to prevent shows up here first.
/// </remarks>
public sealed class RuleEngineTests
{
    private const string CodexPath = @"C:\Program Files\Codex\Codex.exe";
    private const string CodexHelper = @"C:\Program Files\Codex\bin\codex-helper.exe";
    private const string SafariPath = @"C:\Program Files\Safari\Safari.exe";

    private static AppIdentity Identity(string path, string? name = null) => new()
    {
        ExecutablePath = ExecutablePath.Normalize(path),
        DisplayName = name ?? ExecutablePath.FileName(path),
    };

    private static RuleEngine EngineWith(params AppRule[] rules) =>
        new(new RuntimeConfiguration { Rules = rules });

    private static FlowDescriptor Flow(
        string path,
        string address = "93.184.216.34",
        ushort port = 443,
        FlowProtocol protocol = FlowProtocol.Tcp)
        => new(1234, ExecutablePath.Normalize(path), address, port, protocol);

    // ---- The default ---------------------------------------------------------------------

    [Fact]
    public void UnknownApplicationGoesDirect()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });

        var decision = engine.Decide(Flow(SafariPath));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.NoMatchingRule, decision.Reason);
    }

    [Fact]
    public void EmptyConfigurationRoutesEverythingDirect()
    {
        var engine = new RuleEngine(RuntimeConfiguration.Empty);

        Assert.Equal(RouteAction.Direct, engine.Decide(Flow(CodexPath)).Action);
        Assert.Equal(0, engine.Snapshot.ActiveRuleCount);
    }

    // ---- Selection -----------------------------------------------------------------------

    [Fact]
    public void SelectedApplicationGoesToProxy()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });

        var decision = engine.Decide(Flow(CodexPath));

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.ExactRule, decision.Reason);
        Assert.Equal(ExecutablePath.Normalize(CodexPath), decision.RuleKey);
    }

    [Fact]
    public void MatchingIsCaseInsensitiveBecauseWindowsPathsAre()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });

        var decision = engine.Decide(Flow(@"c:\program files\codex\CODEX.EXE"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void ForwardSlashesAndDoubledSeparatorsStillMatch()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });

        var decision = engine.Decide(Flow(@"C:/Program Files//Codex/Codex.exe"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void DisabledRuleRoutesDirect()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath), IsEnabled = false });

        var decision = engine.Decide(Flow(CodexPath));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.NoMatchingRule, decision.Reason);
    }

    [Fact]
    public void ExplicitDirectRuleIsHonouredAndExplained()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath), Action = RouteAction.Direct });

        var decision = engine.Decide(Flow(CodexPath));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.ExactRule, decision.Reason);
    }

    [Fact]
    public void ExplicitBlockRuleRefusesTheFlow()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath), Action = RouteAction.Block });

        Assert.Equal(RouteAction.Block, engine.Decide(Flow(CodexPath)).Action);
    }

    // ---- Master switch -------------------------------------------------------------------

    [Fact]
    public void PausedRoutingIsInertNotHalfActive()
    {
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            Rules = [new AppRule { Identity = Identity(CodexPath) }],
            IsRoutingEnabled = false,
        });

        var decision = engine.Decide(Flow(CodexPath));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.RoutingDisabled, decision.Reason);
    }

    // ---- Loop defence --------------------------------------------------------------------

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.1")]                 // inet_aton short form
    [InlineData("0177.0.0.1")]            // octal
    [InlineData("0x7f000001")]            // hex
    [InlineData("2130706433")]            // single integer
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("169.254.10.1")]
    [InlineData("fe80::1")]
    public void LocalDestinationsAreNeverProxied(string address)
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });

        var decision = engine.Decide(Flow(CodexPath, address));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.LocalDestination, decision.Reason);
    }

    [Fact]
    public void EngineOwnTrafficIsNeverProxied()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });
        var flow = Flow(CodexPath) with { IsEngineTraffic = true };

        var decision = engine.Decide(flow);

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.EngineSelfTraffic, decision.Reason);
    }

    [Fact]
    public void EngineOwnTrafficWinsOverEverythingIncludingThePauseSwitch()
    {
        // Ordering matters: the self-traffic check is first precisely so that no other state can
        // route the engine's upstream connection back into the engine.
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            Rules = [new AppRule { Identity = Identity(CodexPath) }],
            IsRoutingEnabled = false,
        });

        var decision = engine.Decide(Flow(CodexPath) with { IsEngineTraffic = true });

        Assert.Equal(RouteReasonKind.EngineSelfTraffic, decision.Reason);
    }

    // ---- Unattributed flows --------------------------------------------------------------

    [Fact]
    public void UnresolvableProcessGoesDirect()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });

        var decision = engine.Decide(new FlowDescriptor(0, string.Empty, "93.184.216.34", 443, FlowProtocol.Tcp));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.UnidentifiedSource, decision.Reason);
    }

    [Fact]
    public void AnEmptyPathCanNeverBecomeARuleKey()
    {
        // The validator rejects it, but the snapshot is the last line of defence: if an empty key
        // reached the table, every unresolvable process on the machine would be proxied.
        var engine = EngineWith(new AppRule { Identity = new AppIdentity { ExecutablePath = "", DisplayName = "x" } });

        Assert.Equal(0, engine.Snapshot.ActiveRuleCount);
        Assert.Equal(RouteAction.Direct, engine.Decide(new FlowDescriptor(0, "", "1.2.3.4", 443, FlowProtocol.Tcp)).Action);
    }

    // ---- UDP goes through the proxy, or nowhere -------------------------------------------

    [Fact]
    public void SelectedApplicationUdpIsProxied()
    {
        // It used to be refused, on the reasoning that QUIC fails closed and falls back to TCP.
        // True for QUIC, and no help to anything with no TCP path: Discord voice sits on
        // "Connecting to RTC" forever, because there is no second way for it to try.
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });

        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(CodexPath, protocol: FlowProtocol.Udp)).Action);
    }

    [Fact]
    public void SelectedApplicationUdpIsRefusedWhenProxyingItIsTurnedOff()
    {
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            Rules = [new AppRule { Identity = Identity(CodexPath) }],
            ProxiesUdp = false,
        });

        var decision = engine.Decide(Flow(CodexPath, protocol: FlowProtocol.Udp));

        Assert.Equal(RouteAction.Block, decision.Action);
        Assert.Equal(RouteReasonKind.UdpNotSupported, decision.Reason);
    }

    [Fact]
    public void SelectedApplicationUdpIsNeverPassedThroughEitherWay()
    {
        // The promise that does not change with the setting. Whatever else happens to a selected
        // application's datagrams, they do not leave this machine from the user's own address.
        foreach (var proxiesUdp in new[] { true, false })
        {
            var engine = new RuleEngine(new RuntimeConfiguration
            {
                Rules = [new AppRule { Identity = Identity(CodexPath) }],
                ProxiesUdp = proxiesUdp,
            });

            Assert.NotEqual(
                RouteAction.Direct,
                engine.Decide(Flow(CodexPath, protocol: FlowProtocol.Udp)).Action);
        }
    }

    [Fact]
    public void UnselectedApplicationUdpIsUntouched()
    {
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });

        var decision = engine.Decide(Flow(SafariPath, protocol: FlowProtocol.Udp));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void SelectedApplicationUdpToLoopbackIsStillDirect()
    {
        // Blocking a selected app's loopback UDP would break local DNS, mDNS and every local IPC
        // that happens to use a datagram socket. The local-destination check runs first for a reason.
        var engine = EngineWith(new AppRule { Identity = Identity(CodexPath) });

        var decision = engine.Decide(Flow(CodexPath, "127.0.0.1", protocol: FlowProtocol.Udp));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    // ---- Family matching -----------------------------------------------------------------

    [Fact]
    public void FamilyRuleMatchesAHelperInASubdirectory()
    {
        var engine = EngineWith(new AppRule
        {
            Identity = Identity(CodexPath),
            MatchMode = MatchMode.ExecutableFamily,
        });

        var decision = engine.Decide(Flow(CodexHelper));

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.ExecutableFamilyRule, decision.Reason);
        Assert.Equal(ExecutablePath.Normalize(CodexHelper), decision.MatchedPath);
    }

    [Fact]
    public void FamilyRuleMatchesASiblingInTheSameDirectory()
    {
        var engine = EngineWith(new AppRule
        {
            Identity = Identity(CodexPath),
            MatchMode = MatchMode.ExecutableFamily,
        });

        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(@"C:\Program Files\Codex\updater.exe")).Action);
    }

    [Fact]
    public void ExactRuleDoesNotMatchAHelper()
    {
        var engine = EngineWith(new AppRule
        {
            Identity = Identity(CodexPath),
            MatchMode = MatchMode.Exact,
        });

        Assert.Equal(RouteAction.Direct, engine.Decide(Flow(CodexHelper)).Action);
    }

    [Fact]
    public void FamilyRuleDoesNotMatchASiblingDirectoryWithASharedPrefix()
    {
        // The whole point of cutting on the separator. Without it, a rule for
        // "C:\Program Files\Codex" would also capture "C:\Program Files\CodexEvil".
        var engine = EngineWith(new AppRule
        {
            Identity = Identity(CodexPath),
            MatchMode = MatchMode.ExecutableFamily,
        });

        var decision = engine.Decide(Flow(@"C:\Program Files\CodexEvil\evil.exe"));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.NoMatchingRule, decision.Reason);
    }

    [Fact]
    public void MoreSpecificFamilyRuleWins()
    {
        var engine = EngineWith(
            new AppRule
            {
                Identity = Identity(CodexPath),
                MatchMode = MatchMode.ExecutableFamily,
                Action = RouteAction.Proxy,
            },
            new AppRule
            {
                Identity = Identity(@"C:\Program Files\Codex\bin\anchor.exe"),
                MatchMode = MatchMode.ExecutableFamily,
                Action = RouteAction.Block,
            });

        // The helper lives in ...\Codex\bin, whose family rule is the nearer ancestor.
        var decision = engine.Decide(Flow(CodexHelper));

        Assert.Equal(RouteAction.Block, decision.Action);
    }

    [Fact]
    public void ExactRuleBeatsAFamilyRuleThatWouldAlsoMatch()
    {
        var engine = EngineWith(
            new AppRule
            {
                Identity = Identity(CodexPath),
                MatchMode = MatchMode.ExecutableFamily,
                Action = RouteAction.Proxy,
            },
            new AppRule
            {
                Identity = Identity(CodexHelper),
                MatchMode = MatchMode.Exact,
                Action = RouteAction.Direct,
            });

        var decision = engine.Decide(Flow(CodexHelper));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.ExactRule, decision.Reason);
    }

    // ---- The Windows-specific safety guard ------------------------------------------------

    [Fact]
    public void FamilyMatchingOnASharedSystemDirectoryIsRefused()
    {
        // This is the check with no macOS counterpart. Family-matching a System32 binary would put
        // every system executable into the proxy lane.
        var engine = EngineWith(new AppRule
        {
            Identity = Identity(@"C:\Windows\System32\curl.exe"),
            MatchMode = MatchMode.ExecutableFamily,
        });

        Assert.Equal(0, engine.Snapshot.FamilyRuleCount);
        Assert.Equal(RouteAction.Direct, engine.Decide(Flow(@"C:\Windows\System32\svchost.exe")).Action);

        // The rule itself still works, exactly.
        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(@"C:\Windows\System32\curl.exe")).Action);
    }

    [Theory]
    [InlineData(@"C:\Program Files\app.exe")]
    [InlineData(@"C:\Windows\notepad.exe")]
    [InlineData(@"C:\Users\alice\Downloads\thing.exe")]
    [InlineData(@"C:\Users\alice\AppData\Local\thing.exe")]
    [InlineData(@"C:\thing.exe")]
    public void SharedDirectoriesNeverEnterTheFamilyTable(string path)
    {
        var engine = EngineWith(new AppRule
        {
            Identity = Identity(path),
            MatchMode = MatchMode.ExecutableFamily,
        });

        Assert.Equal(0, engine.Snapshot.FamilyRuleCount);
    }

    [Theory]
    [InlineData(@"C:\Program Files\Codex\Codex.exe")]
    [InlineData(@"C:\Users\alice\AppData\Local\Programs\Codex\Codex.exe")]
    [InlineData(@"C:\Users\alice\Desktop\Codex\Codex.exe")]
    [InlineData(@"D:\Games\Steam\steam.exe")]
    public void ApplicationOwnedDirectoriesDoEnterTheFamilyTable(string path)
    {
        var engine = EngineWith(new AppRule
        {
            Identity = Identity(path),
            MatchMode = MatchMode.ExecutableFamily,
        });

        Assert.Equal(1, engine.Snapshot.FamilyRuleCount);
    }

    // ---- Hot-path bounds ------------------------------------------------------------------

    [Fact]
    public void AncestorWalkIsBounded()
    {
        // A pathological path must not turn one flow into an unbounded number of dictionary probes.
        var deep = @"C:\a" + string.Concat(Enumerable.Repeat(@"\b", 60)) + @"\deep.exe";
        var engine = EngineWith(new AppRule
        {
            Identity = Identity(@"C:\a\anchor.exe"),
            MatchMode = MatchMode.ExecutableFamily,
        });

        // The family root "C:\a" is far more than AncestorWalkLimit levels above the flow's path, so
        // the walk gives up rather than matching.
        Assert.Equal(RouteAction.Direct, engine.Decide(Flow(deep)).Action);
        Assert.Equal(ExecutablePath.AncestorWalkLimit, ExecutablePath.Ancestors(deep).Count());
    }

    [Fact]
    public void FamilyRuleWithinTheWalkLimitStillMatches()
    {
        var nested = @"C:\Program Files\Codex\a\b\c\nested.exe";
        var engine = EngineWith(new AppRule
        {
            Identity = Identity(CodexPath),
            MatchMode = MatchMode.ExecutableFamily,
        });

        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(nested)).Action);
    }

    // ---- Snapshot bookkeeping -------------------------------------------------------------

    [Fact]
    public void DisabledRulesDoNotCountAsActive()
    {
        var engine = EngineWith(
            new AppRule { Identity = Identity(CodexPath) },
            new AppRule { Identity = Identity(SafariPath), IsEnabled = false });

        Assert.Equal(1, engine.Snapshot.ActiveRuleCount);
    }

    [Fact]
    public void SnapshotCarriesTheGenerationItWasBuiltFrom()
    {
        var configuration = new RuntimeConfiguration { Version = new ConfigurationVersion(1, 7) };

        Assert.Equal(7UL, new RuleSnapshot(configuration).Version.Generation);
    }
}
