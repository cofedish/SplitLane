using System.Text.Json;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>
/// A machine's managed policy on top of its user's configuration: what the user can and cannot change.
/// </summary>
/// <remarks>
/// The acceptance criteria of the first fleet-management stage. Each test is one thing an organisation
/// needs to be true on ten thousand machines whose users can write their own configuration file.
/// </remarks>
public sealed class ManagedPolicyTests
{
    private const string ContosoSubject = "CN=Contoso Ltd, O=Contoso Ltd, L=Redmond, S=Washington, C=US";

    private static AppIdentity SignedChat(string path = @"C:\Program Files\Contoso\Chat\chat.exe") => new()
    {
        ExecutablePath = path,
        DisplayName = "Contoso Chat",
        Kind = IdentityKind.Signed,
        SignerSubject = PublisherName.Canonical(ContosoSubject),
        Publisher = "Contoso Ltd",
        ProductName = "Contoso Chat",
        BinaryName = "chat.exe",
    };

    private static ImageEvidence Running(string path, string product = "Contoso Chat") => new()
    {
        ExecutablePath = path,
        Signature = SignatureStatus.Valid,
        SignerSubject = PublisherName.Canonical(ContosoSubject),
        SignerName = "Contoso Ltd",
        ProductName = product,
        HasVersionInfo = true,
    };

    private static RouteDecision Route(RuntimeConfiguration effective, ImageEvidence process) =>
        new RuleEngine(effective).Decide(
            new FlowDescriptor(1, process.ExecutablePath, "93.184.216.34", 443, FlowProtocol.Tcp, Image: process));

    private static ManagedPolicy PolicyWith(params AppRule[] rules) => new() { Rules = rules };

    [Fact]
    public void AManagedRuleAppliesOnAMachineWhereTheApplicationIsInstalledSomewhereElse()
    {
        // Described on the administrator's machine; running from a user's profile on another.
        var policy = PolicyWith(new AppRule { Identity = SignedChat(), MatchMode = MatchMode.Exact });

        var effective = PolicyMerger.Merge(RuntimeConfiguration.Empty, policy).Effective;
        var decision = Route(effective, Running(@"C:\Users\bob\AppData\Local\Programs\Contoso Chat\chat.exe"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void TheUserCannotRemoveOrRedirectAManagedRule()
    {
        var policy = PolicyWith(new AppRule { Identity = SignedChat() });
        var user = new RuntimeConfiguration
        {
            Rules = [new AppRule { Identity = SignedChat(@"D:\Chat\chat.exe"), Action = RouteAction.Direct }],
        };

        var outcome = PolicyMerger.Merge(user, policy);

        Assert.Single(outcome.Effective.Rules);
        Assert.True(outcome.Effective.Rules[0].IsManaged);
        Assert.Equal(1, outcome.UserRulesDropped);
        Assert.Equal(RouteAction.Proxy, Route(outcome.Effective, Running(@"D:\Chat\chat.exe")).Action);
    }

    [Fact]
    public void AMoreSpecificUserRuleDoesNotShadowAManagedFamily()
    {
        // The managed rule covers the Chat product; the user tries to send one of its helpers DIRECT
        // with an exact rule, which on specificity alone would win.
        var policy = PolicyWith(new AppRule { Identity = SignedChat(), MatchMode = MatchMode.ExecutableFamily });
        var helper = SignedChat(@"C:\Program Files\Contoso\Chat\chat-helper.exe") with { BinaryName = "chat-helper.exe" };
        var user = new RuntimeConfiguration
        {
            Rules = [new AppRule { Identity = helper, Action = RouteAction.Direct, MatchMode = MatchMode.Exact }],
        };

        var effective = PolicyMerger.Merge(user, policy).Effective;
        var decision = Route(effective, Running(@"C:\Program Files\Contoso\Chat\chat-helper.exe"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void AManagedDirectRuleIsNotOverriddenByAUserFamily()
    {
        var policy = PolicyWith(new AppRule { Identity = SignedChat(), Action = RouteAction.Direct, MatchMode = MatchMode.Exact });
        var launcher = SignedChat(@"C:\Program Files\Contoso\Chat\launcher.exe") with { BinaryName = "launcher.exe" };
        var user = new RuntimeConfiguration
        {
            Rules = [new AppRule { Identity = launcher, Action = RouteAction.Proxy, MatchMode = MatchMode.ExecutableFamily }],
        };

        var effective = PolicyMerger.Merge(user, policy).Effective;

        Assert.Equal(RouteAction.Direct, Route(effective, Running(@"C:\Program Files\Contoso\Chat\chat.exe")).Action);
        Assert.Equal(RouteAction.Proxy, Route(effective, Running(@"C:\Program Files\Contoso\Chat\launcher.exe")).Action);
    }

    [Fact]
    public void UserRulesStillApplyToApplicationsThePolicyDoesNotGovern()
    {
        var policy = PolicyWith(new AppRule { Identity = SignedChat() });
        var other = SignedChat(@"C:\Program Files\Contoso\Mail\mail.exe") with
        {
            ProductName = "Contoso Mail",
            BinaryName = "mail.exe",
            DisplayName = "Contoso Mail",
        };
        var user = new RuntimeConfiguration { Rules = [new AppRule { Identity = other }] };

        var effective = PolicyMerger.Merge(user, policy).Effective;

        Assert.Equal(2, effective.Rules.Count);
        Assert.Equal(RouteAction.Proxy, Route(effective, Running(@"C:\Program Files\Contoso\Mail\mail.exe", "Contoso Mail")).Action);
    }

    [Fact]
    public void WhenUserRulesAreNotAllowedOnlyTheManagedOnesApply()
    {
        var policy = PolicyWith(new AppRule { Identity = SignedChat() }) with { AllowUserRules = false };
        var user = new RuntimeConfiguration
        {
            Rules = [new AppRule { Identity = new AppIdentity { ExecutablePath = @"C:\Tools\x.exe", DisplayName = "x" } }],
        };

        var outcome = PolicyMerger.Merge(user, policy);

        Assert.Single(outcome.Effective.Rules);
        Assert.Equal(1, outcome.UserRulesDropped);
        Assert.Equal(RouteAction.Direct, Route(outcome.Effective, ImageEvidence.FromPath(@"C:\Tools\x.exe")).Action);
    }

    [Fact]
    public void RemovingARuleFromThePolicyRevokesIt()
    {
        var withRule = PolicyWith(new AppRule { Identity = SignedChat() });
        var withoutRule = PolicyWith();
        var process = Running(@"C:\Program Files\Contoso\Chat\chat.exe");

        Assert.Equal(RouteAction.Proxy, Route(PolicyMerger.Merge(RuntimeConfiguration.Empty, withRule).Effective, process).Action);
        Assert.Equal(RouteAction.Direct, Route(PolicyMerger.Merge(RuntimeConfiguration.Empty, withoutRule).Effective, process).Action);
    }

    [Fact]
    public void ForcedRoutingOverridesTheUsersMasterSwitch()
    {
        var policy = PolicyWith(new AppRule { Identity = SignedChat() }) with { ForceRoutingEnabled = true };
        var user = RuntimeConfiguration.Empty with { IsRoutingEnabled = false };

        var effective = PolicyMerger.Merge(user, policy).Effective;

        Assert.True(effective.IsRoutingEnabled);
        Assert.Equal(RouteAction.Proxy, Route(effective, Running(@"C:\Program Files\Contoso\Chat\chat.exe")).Action);
    }

    [Fact]
    public void AManagedProxyReplacesTheUsers()
    {
        var corporate = ProxyConfiguration.Default with { Endpoint = new ProxyEndpoint { Host = "proxy.corp.example", Port = 1080 } };
        var policy = PolicyWith() with { Proxy = corporate };
        var user = RuntimeConfiguration.Empty with
        {
            Proxy = ProxyConfiguration.Default with { Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = 9999 } },
        };

        Assert.Equal("proxy.corp.example", PolicyMerger.Merge(user, policy).Effective.Proxy.Endpoint.Host);
    }

    [Fact]
    public void AManagedProxyRuleWithoutAManagedProxyIsReported()
    {
        // Found in review: without a proxy in the policy, the user decides where "must be proxied"
        // traffic goes - including a forwarder of their own that sends it straight out.
        var outcome = PolicyMerger.Merge(RuntimeConfiguration.Empty, PolicyWith(new AppRule { Identity = SignedChat() }));

        Assert.Contains(outcome.Notes, note => note.Contains("sets no proxy", StringComparison.Ordinal));
    }

    [Fact]
    public void AUserRuleForOneBinaryOfAPackageThePolicyGovernsIsSetAside()
    {
        AppIdentity Package(string binary) => new()
        {
            ExecutablePath = $@"C:\Program Files\WindowsApps\Contoso.Chat_1.0.0.0_x64__abc\{binary}",
            DisplayName = binary,
            Kind = IdentityKind.Package,
            PackageFamilyName = "Contoso.Chat_abc",
            BinaryName = binary,
        };

        var policy = PolicyWith(new AppRule { Identity = Package("chat.exe"), MatchMode = MatchMode.PackageFamily });
        var user = new RuntimeConfiguration
        {
            Rules = [new AppRule { Identity = Package("helper.exe"), Action = RouteAction.Direct, MatchMode = MatchMode.Exact }],
        };

        var outcome = PolicyMerger.Merge(user, policy);

        Assert.Equal(1, outcome.UserRulesDropped);
        Assert.Single(outcome.Effective.Rules);
    }

    [Fact]
    public void WithoutAPolicyTheUsersConfigurationIsUntouched()
    {
        var user = RuntimeConfiguration.Empty with { IsRoutingEnabled = false };

        Assert.Same(user, PolicyMerger.Merge(user, null).Effective);
    }

    [Fact]
    public void AManagedPathRuleIsRefusedAndReported()
    {
        var policy = PolicyWith(new AppRule
        {
            Identity = new AppIdentity { ExecutablePath = @"C:\Program Files\Contoso\Chat\chat.exe", DisplayName = "Chat by path" },
        });

        var outcome = PolicyMerger.Merge(RuntimeConfiguration.Empty, policy);

        Assert.Empty(outcome.Effective.Rules);
        Assert.Contains(outcome.Notes, note => note.Contains("Chat by path", StringComparison.Ordinal));
    }

    [Fact]
    public void AManagedRuleWithAnIncompleteIdentityIsRefused()
    {
        var policy = PolicyWith(new AppRule { Identity = SignedChat() with { SignerSubject = null } });

        var outcome = PolicyMerger.Merge(RuntimeConfiguration.Empty, policy);

        Assert.Empty(outcome.Effective.Rules);
        Assert.Single(outcome.Notes);
    }

    [Fact]
    public void AManagedRuleIsNotPinnedToThePathItWasDescribedAt()
    {
        // On this machine the administrator's reference path holds an unrelated, unsigned tool. That
        // is not the managed application being tampered with; it is a different machine.
        var policy = PolicyWith(new AppRule { Identity = SignedChat() });
        var effective = PolicyMerger.Merge(RuntimeConfiguration.Empty, policy).Effective;

        var decision = Route(effective, new ImageEvidence
        {
            ExecutablePath = @"C:\Program Files\Contoso\Chat\chat.exe",
            Signature = SignatureStatus.Unsigned,
            Sha256 = "00",
            HasVersionInfo = true,
        });

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AUserCannotMarkTheirOwnRuleManaged()
    {
        const string Forged = """
            {
              "version": { "schemaVersion": 2, "generation": 1 },
              "rules": [
                {
                  "identity": { "executablePath": "C:\\Tools\\x.exe", "displayName": "x" },
                  "isManaged": true
                }
              ]
            }
            """;

        // The field is not part of the contract, so the word is read past and the rule stays the
        // user's. Only PolicyMerger ever sets it, and only for rules from the policy file.
        var decoded = ConfigurationCodec.DecodeFromJson(Forged);

        Assert.False(decoded.Rules[0].IsManaged);
        Assert.Equal(0, new RuleSnapshot(decoded).ManagedRuleCount);
    }

    [Fact]
    public void APolicyRoundTripsAndANewerOneIsRefused()
    {
        var policy = PolicyWith(new AppRule { Identity = SignedChat() }) with { DisableSelfUpdate = true, ForceRoutingEnabled = true };

        var decoded = PolicyMerger.Decode(PolicyMerger.Encode(policy));

        Assert.True(decoded.DisableSelfUpdate);
        Assert.True(decoded.ForceRoutingEnabled);
        Assert.Equal(SignedChat().MatchKey, decoded.Rules[0].Identity.MatchKey);
        Assert.Throws<ConfigurationValidationException>(() => PolicyMerger.Decode("""{ "schemaVersion": 2, "rules": [] }"""));
        Assert.ThrowsAny<JsonException>(() => PolicyMerger.Decode("""{ "schemaVersion": 1, "rulez": [] }"""));
    }
}
