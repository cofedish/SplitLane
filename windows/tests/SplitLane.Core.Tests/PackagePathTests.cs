using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>Matching a packaged application across the versions it installs itself as.</summary>
public sealed class PackagePathTests
{
    private const string Codex818 =
        @"C:\Program Files\WindowsApps\OpenAI.Codex_26.818.3698.0_x64__8wekyb3d8bbwe\Codex.exe";

    private const string Codex901 =
        @"C:\Program Files\WindowsApps\OpenAI.Codex_26.901.4102.0_x64__8wekyb3d8bbwe\Codex.exe";

    [Fact]
    public void TheVersionIsWhatGetsDiscarded()
    {
        Assert.Equal("openai.codex_8wekyb3d8bbwe", PackagePath.Family(Codex818));
        Assert.Equal(PackagePath.Family(Codex818), PackagePath.Family(Codex901));
    }

    [Fact]
    public void AnUpdateStillMatches()
    {
        // The defect, in one assertion: a rule made at 26.818 has to survive the update to 26.901.
        Assert.True(PackagePath.SameFamily(Codex901, PackagePath.Family(Codex818)));
    }

    [Fact]
    public void ADifferentPackageDoesNot()
    {
        var other =
            @"C:\Program Files\WindowsApps\Microsoft.Todos_2.117.0_x64__8wekyb3d8bbwe\Todo.exe";

        Assert.False(PackagePath.SameFamily(other, PackagePath.Family(Codex818)));
    }

    [Fact]
    public void ADifferentPublisherDoesNot()
    {
        // Same package name, different publisher hash. The hash comes from the publisher's
        // certificate, so this is the case that stops one publisher answering for another's name.
        var impostor =
            @"C:\Program Files\WindowsApps\OpenAI.Codex_26.818.3698.0_x64__zzzzzzzzzzzzz\Codex.exe";

        Assert.False(PackagePath.SameFamily(impostor, PackagePath.Family(Codex818)));
    }

    [Theory]
    [InlineData(@"C:\Program Files\Vendor\Thing\thing.exe")]
    [InlineData(@"C:\Users\ann\AppData\Local\Discord\app-1.0.9254\Discord.exe")]
    [InlineData(@"C:\Windows\System32\curl.exe")]
    [InlineData("")]
    public void OrdinaryPathsHaveNoPackageFamily(string path) =>
        Assert.Equal(string.Empty, PackagePath.Family(path));

    [Fact]
    public void ADoubleUnderscoreOutsideWindowsAppsIsNotAPackage()
    {
        // The marker is only meaningful where packaged applications live. A directory that happens
        // to contain two underscores is not one.
        Assert.Equal(
            string.Empty,
            PackagePath.Family(@"C:\Tools\weird__name\tool.exe"));
    }

    [Fact]
    public void TheEngineRoutesAnUpdatedPackage()
    {
        var identity = new AppIdentity { ExecutablePath = Codex818, DisplayName = "Codex" };
        Assert.True(identity.SupportsPackageMatching);

        var engine = new RuleEngine(new RuntimeConfiguration
        {
            Rules =
            [
                new AppRule
                {
                    Identity = identity,
                    Action = RouteAction.Proxy,
                    MatchMode = MatchMode.PackageFamily,
                },
            ],
        });

        // The version it was selected at, and the one it updated itself to.
        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(Codex818)).Action);
        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(Codex901)).Action);

        // And nothing else that happens to live in WindowsApps.
        var neighbour =
            @"C:\Program Files\WindowsApps\Microsoft.Todos_2.117.0_x64__8wekyb3d8bbwe\Todo.exe";
        Assert.Equal(RouteAction.Direct, engine.Decide(Flow(neighbour)).Action);
    }

    private static FlowDescriptor Flow(string path) =>
        new(1234, path, "93.184.216.34", 443, FlowProtocol.Tcp);

    [Fact]
    public void ARuleWrittenBeforePackageMatchingExistedStartsWorking()
    {
        // A rule made when the only broad mode was ExecutableFamily. On a packaged application that
        // mode cannot be honoured as written - WindowsApps is shared - so it used to narrow to the
        // one installed version. It asked to cover the application; this is what covering it means.
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            Rules =
            [
                new AppRule
                {
                    Identity = new AppIdentity { ExecutablePath = Codex818, DisplayName = "Codex" },
                    Action = RouteAction.Proxy,
                    MatchMode = MatchMode.ExecutableFamily,
                },
            ],
        });

        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(Codex901)).Action);
    }

    [Fact]
    public void AnExactRuleOnAPackageStaysExact()
    {
        // Somebody who asked for this executable only gets this executable only, packaged or not.
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            Rules =
            [
                new AppRule
                {
                    Identity = new AppIdentity { ExecutablePath = Codex818, DisplayName = "Codex" },
                    Action = RouteAction.Proxy,
                    MatchMode = MatchMode.Exact,
                },
            ],
        });

        Assert.Equal(RouteAction.Proxy, engine.Decide(Flow(Codex818)).Action);
        Assert.Equal(RouteAction.Direct, engine.Decide(Flow(Codex901)).Action);
    }
}
