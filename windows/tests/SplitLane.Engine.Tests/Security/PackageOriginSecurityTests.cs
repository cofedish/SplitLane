using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Platform;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-016: a package claim counts only when its origin is verified. An untrusted registration is an
/// ordinary process; a claim whose origin could not be established - an API error, an unknown origin,
/// metadata that cannot be read - is refused by the rule it points at, never treated as verified.
/// </summary>
[Trait("Category", "Security")]
public sealed class PackageOriginSecurityTests
{
    [Theory]
    [InlineData("Contoso.App_8wekyb3d8bbwe")]
    [InlineData("?Contoso.App_8wekyb3d8bbwe")]
    [InlineData(null)]
    public void A_claim_survives_being_passed_on_for_a_later_decision(string? claim)
    {
        // A UDP socket re-decided after a configuration change rebuilds its evidence from this. An
        // unverified claim that came back as no claim would be matched as an unpackaged process.
        var evidence = new ImageEvidence { ExecutablePath = @"C:\Apps\app.exe" }.WithPackageClaim(claim);

        Assert.Equal(claim, evidence.PackageClaim);
        Assert.Equal(evidence, new ImageEvidence { ExecutablePath = @"C:\Apps\app.exe" }.WithPackageClaim(evidence.PackageClaim));
    }

    private const string Family = "Contoso.Chat_abc";
    private const string Executable = @"C:\Program Files\WindowsApps\Contoso.Chat_1.0.0.0_x64__abc\chat.exe";

    [Theory]
    [InlineData(2)] // Inbox
    [InlineData(3)] // Store
    [InlineData(5)] // DeveloperSigned (needs a certificate Windows trusts)
    [InlineData(6)] // LineOfBusiness
    public void Signed_origins_are_verified(int origin) =>
        Assert.Equal(PackageOriginVerdict.Verified, ProcessPackage.Classify(origin));

    [Theory]
    [InlineData(1)] // Unsigned
    [InlineData(4)] // DeveloperUnsigned
    public void Unsigned_registrations_are_untrusted(int origin) =>
        Assert.Equal(PackageOriginVerdict.Untrusted, ProcessPackage.Classify(origin));

    [Theory]
    [InlineData(null)] // the API failed or is missing
    [InlineData(0)]    // Unknown
    [InlineData(99)]   // not a value Windows defines
    public void Anything_else_is_a_failed_verification_not_a_pass(int? origin) =>
        Assert.Equal(PackageOriginVerdict.VerificationFailed, ProcessPackage.Classify(origin));

    [Fact]
    public void An_unpackaged_process_reports_no_package()
    {
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        var (family, verdict) = ProcessPackage.Read(self.Handle);

        Assert.Null(family);
        Assert.Equal(PackageOriginVerdict.NotPackaged, verdict);
    }

    [Fact]
    public void A_verified_package_matches_its_rule()
    {
        var decision = Decide(Family);

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.PackageRule, decision.Reason);
    }

    [Fact]
    public void An_unverified_claim_to_a_selected_package_is_refused_not_proxied_and_not_DIRECT()
    {
        var decision = Decide(ProcessPackage.UnverifiedPrefix + Family);

        Assert.Equal(RouteAction.Block, decision.Action);
        Assert.Equal(RouteReasonKind.IdentityMismatch, decision.Reason);
    }

    [Fact]
    public void An_untrusted_registration_is_an_ordinary_process()
    {
        // Untrusted origins produce no claim at all.
        Assert.Equal(RouteAction.Direct, Decide(claim: null).Action);
    }

    [Fact]
    public void A_malformed_claim_matches_nothing()
    {
        Assert.Equal(RouteAction.Direct, Decide(ProcessPackage.UnverifiedPrefix).Action);
    }

    [Theory]
    [InlineData("Contoso.Chat_abc", "Contoso.Chat_abc", null)]
    [InlineData("?Contoso.Chat_abc", null, "Contoso.Chat_abc")]
    [InlineData(null, null, null)]
    public void A_claim_lands_in_the_right_field(string? claim, string? verified, string? unverified)
    {
        var evidence = new ImageEvidence { ExecutablePath = Executable }.WithPackageClaim(claim);

        Assert.Equal(verified, evidence.PackageFamilyName);
        Assert.Equal(unverified, evidence.UnverifiedPackageFamilyName);
    }

    private static RouteDecision Decide(string? claim)
    {
        var rule = new AppRule
        {
            Identity = new AppIdentity
            {
                ExecutablePath = Executable,
                DisplayName = "Chat",
                Kind = IdentityKind.Package,
                PackageFamilyName = Family,
                BinaryName = "chat.exe",
            },
            MatchMode = MatchMode.PackageFamily,
        };

        var engine = new RuleEngine(ConfigurationValidator.Sanitize(new RuntimeConfiguration { Rules = [rule] }));
        var evidence = new ImageEvidence { ExecutablePath = ExecutablePath.Normalize(Executable) }.WithPackageClaim(claim);

        return engine.Decide(new FlowDescriptor(7, evidence.ExecutablePath, "203.0.113.1", 443, FlowProtocol.Tcp, Image: evidence));
    }
}
