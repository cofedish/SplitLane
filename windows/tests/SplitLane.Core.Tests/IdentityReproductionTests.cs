using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>
/// The lost-rule bug, scenario by scenario: a selected application updates, moves, or is joined by
/// look-alikes, and its rule has to keep meaning exactly that application.
/// </summary>
/// <remarks>
/// <para>
/// Each scenario was first written against the rules the picker created before schema 2 - a path and
/// an unverified publisher string - and every one of them failed: the updated or moved application
/// went DIRECT, and a file dropped into the folder was proxied. That run is kept in the engineering
/// log; these are the same scenarios expressed the way they are now decided, with the rule built by
/// <see cref="ConfigurationMigrator.IdentityFor"/> exactly as the picker builds it and the flow
/// carrying the evidence the engine reads.
/// </para>
/// <para>
/// The data is real. The subject is the one on both copies of <c>codex.exe</c> on the development
/// machine, which were signed by different certificates from different intermediate CAs; the hash
/// directories are the two the Codex updater actually used.
/// </para>
/// </remarks>
public sealed class IdentityReproductionTests
{
    private const string OpenAiSubject =
        "CN=\"OpenAI OpCo, LLC\", O=\"OpenAI OpCo, LLC\", L=San Francisco, S=California, C=US";

    private const string ContosoSubject =
        "CN=Contoso Ltd, O=Contoso Ltd, L=Redmond, S=Washington, C=US";

    private const string CodexBefore = @"C:\Users\alice\AppData\Local\OpenAI\Codex\bin\247581e40ee272fb\codex.exe";
    private const string CodexAfter = @"C:\Users\alice\AppData\Local\OpenAI\Codex\bin\d375f7df50d3b421\codex.exe";

    private static ImageEvidence Verified(
        string path, string subject, string? product = null, string? signerName = null) => new()
    {
        ExecutablePath = ExecutablePath.Normalize(path),
        Signature = SignatureStatus.Valid,
        SignerSubject = PublisherName.Canonical(subject),
        SignerName = signerName ?? PublisherName.Parse(subject)[0].Value,
        ProductName = product,
        HasVersionInfo = true,
    };

    private static ImageEvidence Unsigned(string path, string sha256, long size = 4096) => new()
    {
        ExecutablePath = ExecutablePath.Normalize(path),
        Signature = SignatureStatus.Unsigned,
        Sha256 = sha256,
        FileSize = size,
        HasVersionInfo = true,
    };

    private static AppRule RulePickedFrom(ImageEvidence evidence, MatchMode mode = MatchMode.ExecutableFamily) => new()
    {
        Identity = ConfigurationMigrator.IdentityFor(
            evidence.ExecutablePath, evidence.FileName, evidence)!,
        MatchMode = mode,
    };

    private static RouteDecision Route(AppRule rule, ImageEvidence process, FlowProtocol protocol = FlowProtocol.Tcp) =>
        new RuleEngine(ConfigurationValidator.Sanitize(new RuntimeConfiguration { Rules = [rule] }))
            .Decide(new FlowDescriptor(
                1, process.ExecutablePath, "93.184.216.34", 443, protocol, Image: process));

    // ---- Updates and moves: the rule follows the application ----------------------------------

    [Fact]
    public void CodexCliAfterAnUpdateIntoANewHashDirectory()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, Verified(CodexAfter, OpenAiSubject));

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.SignedIdentityRule, decision.Reason);
    }

    [Fact]
    public void AnUpdateWithANewPathAndANewVersionKeepsItsRule()
    {
        var rule = RulePickedFrom(Verified(
            @"C:\Users\alice\AppData\Local\JetBrains\Toolbox\apps\IDEA-U\ch-0\241.14494.240\bin\idea64.exe",
            "CN=JetBrains s.r.o., O=JetBrains s.r.o., L=Praha, S=Praha, C=CZ",
            "IntelliJ IDEA"));

        var decision = Route(rule, Verified(
            @"C:\Users\alice\AppData\Local\JetBrains\Toolbox\apps\IDEA-U\ch-0\242.20224.300\bin\idea64.exe",
            "CN=JetBrains s.r.o., O=JetBrains s.r.o., L=Praha, S=Praha, C=CZ",
            "IntelliJ IDEA"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void AnUpdateSignedWithANewCertificateFromTheSamePublisherKeepsItsRule()
    {
        // The certificate's thumbprint and issuing CA are not part of the identity. The two real
        // copies of codex.exe differ in both, and in their subjects' formatting not at all.
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, Verified(
            CodexAfter,
            "CN=\"OpenAI OpCo, LLC\",  O=\"OpenAI OpCo, LLC\", L=San Francisco, S=California, C=US, " +
            "SERIALNUMBER=12345, OU=Build Pipeline"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void TheInstallFolderMovedToAnotherDrive()
    {
        var rule = RulePickedFrom(Verified(@"D:\Tools\Contoso\contoso.exe", ContosoSubject, "Contoso Chat"));

        var decision = Route(rule, Verified(@"E:\Apps\Contoso\contoso.exe", ContosoSubject, "Contoso Chat"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void AnUnchangedApplicationStillMatches()
    {
        var rule = RulePickedFrom(Verified(@"C:\Program Files\Contoso\contoso.exe", ContosoSubject, "Contoso Chat"));

        var decision = Route(rule, Verified(@"C:\Program Files\Contoso\contoso.exe", ContosoSubject, "Contoso Chat"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.SignedIdentityRule, decision.Reason);
    }

    [Fact]
    public void ASecondInstallationOfTheSameApplicationIsTheSameApplication()
    {
        // The Codex CLI shipped inside the VS Code extension, next to the desktop one.
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, Verified(
            @"C:\Users\alice\.vscode\extensions\openai.chatgpt-26.917.62051-win32-x64\bin\windows-x86_64\codex.exe",
            OpenAiSubject));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void APackagedApplicationMovedToAnotherDrive()
    {
        var rule = RulePickedFrom(new ImageEvidence
        {
            ExecutablePath = @"C:\Program Files\WindowsApps\OpenAI.Codex_26.915.4065.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe",
            PackageFamilyName = "OpenAI.Codex_2p2nqsd0c76g0",
        });

        // Windows moves a packaged application to another volume on request; the token still carries
        // its family, whatever the path now says.
        var decision = Route(rule, new ImageEvidence
        {
            ExecutablePath = @"D:\WindowsApps\OpenAI.Codex_26.917.6896.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe",
            PackageFamilyName = "OpenAI.Codex_2p2nqsd0c76g0",
        });

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.PackageRule, decision.Reason);
    }

    [Fact]
    public void AFolderThatMerelyLooksLikeAPackageDoesNotClaimOne()
    {
        var rule = RulePickedFrom(new ImageEvidence
        {
            ExecutablePath = @"C:\Program Files\WindowsApps\OpenAI.Codex_26.915.4065.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe",
            PackageFamilyName = "OpenAI.Codex_2p2nqsd0c76g0",
        });

        // Anyone can create this directory. Only Windows can put the family in a process token.
        var decision = Route(rule, new ImageEvidence
        {
            ExecutablePath = @"C:\Users\mallory\WindowsApps\OpenAI.Codex_1.0.0.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe",
        });

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    // ---- Look-alikes: the rule does not spread --------------------------------------------------

    [Fact]
    public void AnotherApplicationFromTheSamePublisherDoesNotInheritTheRule()
    {
        var rule = RulePickedFrom(
            Verified(@"C:\Program Files\Contoso\Chat\chat.exe", ContosoSubject, "Contoso Chat"),
            MatchMode.Exact);

        var decision = Route(rule, Verified(@"C:\Program Files\Contoso\Chat Beta\chat.exe", ContosoSubject, "Contoso Chat Beta"));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AnotherProductFromTheSamePublisherIsNotPartOfTheFamily()
    {
        var rule = RulePickedFrom(Verified(@"C:\Program Files\Contoso\Chat\chat.exe", ContosoSubject, "Contoso Chat"));

        var decision = Route(rule, Verified(@"C:\Program Files\Contoso\Mail\mail.exe", ContosoSubject, "Contoso Mail"));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AnExecutableWithTheSameNameFromAnotherPublisherDoesNotInheritTheRule()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, Verified(@"C:\Users\alice\Downloads\codex.exe", ContosoSubject));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AnUnsignedExecutableWithTheSameNameDoesNotInheritTheRule()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, Unsigned(@"C:\Users\alice\Downloads\codex.exe", "ab12"));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AnotherBinaryOfTheSamePublisherRenamedToTheSelectedNameIsNotTheApplication()
    {
        // Every inbox Windows tool shares one signer and one product name; the signed original file
        // name is what still tells a copy of PowerShell renamed to curl.exe from curl.
        const string Windows = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
        var curl = Verified(@"C:\Windows\System32\curl.exe", Windows, "Microsoft® Windows® Operating System") with
        {
            OriginalFileName = "curl.exe",
        };
        var rule = RulePickedFrom(curl, MatchMode.Exact);
        var renamed = Verified(@"C:\Users\alice\Downloads\curl.exe", Windows, "Microsoft® Windows® Operating System") with
        {
            OriginalFileName = "PowerShell.EXE",
        };

        Assert.Equal("curl.exe", rule.Identity.OriginalFileName);
        Assert.Equal(RouteAction.Direct, Route(rule, renamed).Action);
        Assert.Equal(RouteAction.Proxy, Route(rule, curl with { ExecutablePath = @"D:\Tools\curl.exe" }).Action);
    }

    [Fact]
    public void ARenamedBinaryWithoutAVersionResourceIsToldApartByTheNameItWasBuiltWith()
    {
        // codex.exe has no version resource, so signer and file name were its whole identity. The
        // program database name in its signed CodeView record is codex.pdb, and survives a rename.
        var picked = Verified(CodexBefore, OpenAiSubject) with { DebugName = "codex.pdb" };
        var rule = RulePickedFrom(picked);

        var updated = Route(rule, Verified(CodexAfter, OpenAiSubject) with { DebugName = "codex.pdb" });
        var renamedHelper = Route(rule, Verified(@"C:\Users\alice\Downloads\codex.exe", OpenAiSubject) with
        {
            DebugName = "codex_code_mode_host.pdb",
        });
        var noRecord = Route(rule, Verified(@"C:\Users\alice\Downloads\codex.exe", OpenAiSubject));

        Assert.Equal("codex.pdb", rule.Identity.DebugName);
        Assert.Equal(RouteAction.Proxy, updated.Action);
        Assert.Equal(RouteAction.Direct, renamedHelper.Action);
        Assert.Equal(RouteAction.Direct, noRecord.Action);
    }

    [Fact]
    public void ATamperedCopyIsNotTheApplication()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, new ImageEvidence
        {
            ExecutablePath = @"C:\Users\alice\Downloads\codex.exe",
            Signature = SignatureStatus.Invalid,
        });

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AnUnsignedFileDroppedIntoTheFolderDoesNotInheritTheRule()
    {
        var rule = RulePickedFrom(Verified(@"C:\Program Files\Contoso\contoso.exe", ContosoSubject, "Contoso Chat"));

        var decision = Route(rule, Unsigned(@"C:\Program Files\Contoso\dropped.exe", "cd34"));

        Assert.NotEqual(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void AnUnsignedReplacementAtTheSelectedPathIsRefusedNotRoutedEitherWay()
    {
        var rule = RulePickedFrom(Verified(@"C:\Program Files\Contoso\contoso.exe", ContosoSubject, "Contoso Chat"));

        var decision = Route(rule, Unsigned(@"C:\Program Files\Contoso\contoso.exe", "ef56"));

        Assert.Equal(RouteAction.Block, decision.Action);
        Assert.Equal(RouteReasonKind.IdentityMismatch, decision.Reason);
    }

    [Fact]
    public void ASignerChangeAtTheSelectedPathIsRefusedAndReported()
    {
        var rule = RulePickedFrom(Verified(@"C:\Program Files\Contoso\contoso.exe", ContosoSubject, "Contoso Chat"));

        var decision = Route(rule, Verified(
            @"C:\Program Files\Contoso\contoso.exe",
            "CN=Contoso Holdings, O=Contoso Holdings, L=Redmond, S=Washington, C=US",
            "Contoso Chat"));

        Assert.Equal(RouteAction.Block, decision.Action);
        Assert.Equal(RouteReasonKind.IdentityMismatch, decision.Reason);
    }

    [Fact]
    public void ARuleWaitingToBeSelectedAgainRefusesItsOwnPathAndRoutesNothingElse()
    {
        var waiting = new AppRule
        {
            Identity = new AppIdentity { ExecutablePath = @"C:\Tools\notes.exe", DisplayName = "notes" },
            Status = RuleStatus.NeedsReselection,
            StatusDetail = "signed by someone else now",
        };
        var engine = new RuleEngine(new RuntimeConfiguration { Rules = [waiting] });

        var atItsPath = engine.Decide(new FlowDescriptor(1, @"C:\Tools\notes.exe", "93.184.216.34", 443, FlowProtocol.Tcp));
        var elsewhere = engine.Decide(new FlowDescriptor(1, @"D:\Other\notes.exe", "93.184.216.34", 443, FlowProtocol.Tcp));

        Assert.Equal(RouteAction.Block, atItsPath.Action);
        Assert.Equal(RouteReasonKind.IdentityMismatch, atItsPath.Reason);
        Assert.Equal(RouteAction.Direct, elsewhere.Action);
        Assert.Equal(0, engine.Snapshot.ActiveRuleCount);
    }

    // ---- Child processes --------------------------------------------------------------------------

    [Fact]
    public void AHelperFromTheSameInstallIsCoveredByTheFamily()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        // Picked in the old hash directory, running from the new one: the family is rooted above both.
        var decision = Route(rule, Verified(
            @"C:\Users\alice\AppData\Local\OpenAI\Codex\bin\d375f7df50d3b421\codex-code-mode-host.exe", OpenAiSubject));

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.SignedFamilyRule, decision.Reason);
    }

    [Fact]
    public void AFamilyPickedDeepInsideAVersionedBundleFollowsThatFolderAndNoFurther()
    {
        // Found on a live run: climbing out of the hash directory outright put the Node.js runtime
        // beside the picked tool into its family. The folder follows the update; the bundle does not
        // join.
        const string Runtime = @"C:\Users\alice\AppData\Local\OpenAI\Codex\runtimes\cua_node";
        var rule = RulePickedFrom(Verified(
            $@"{Runtime}\df473e5367fa2b42\bin\node_modules\@oai\sky\bin\windows\swift\x64\codex-computer-use-swift.exe",
            OpenAiSubject));

        var sameFolderNextVersion = Route(rule, Verified(
            $@"{Runtime}\f53823cd54b14f45\bin\node_modules\@oai\sky\bin\windows\swift\x64\swift-helper.exe",
            OpenAiSubject));
        var runtimeBeside = Route(rule, Verified($@"{Runtime}\f53823cd54b14f45\bin\node.exe", OpenAiSubject, "Node.js"));

        Assert.Equal(RouteAction.Proxy, sameFolderNextVersion.Action);
        Assert.Equal(RouteAction.Direct, runtimeBeside.Action);
    }

    [Fact]
    public void AHelperIsNotCoveredByAnExactRule()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject), MatchMode.Exact);

        var decision = Route(rule, Verified(
            @"C:\Users\alice\AppData\Local\OpenAI\Codex\bin\d375f7df50d3b421\codex-code-mode-host.exe", OpenAiSubject));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AHelperWithTheSameProductNameIsCoveredWherever()
    {
        var rule = RulePickedFrom(Verified(@"C:\Program Files\Contoso\Chat\chat.exe", ContosoSubject, "Contoso Chat"));

        var decision = Route(rule, Verified(
            @"C:\ProgramData\Contoso\Updater\chat-updater.exe", ContosoSubject, "Contoso Chat"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void AForeignProgramStartedByTheApplicationIsNotPartOfIt()
    {
        // Codex starts git, a shell, node. They are other people's applications that happen to be its
        // children, and a parent process id is something any process can choose for its children.
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, Verified(
            @"C:\Program Files\Git\cmd\git.exe",
            "CN=Johannes Schindelin, O=Johannes Schindelin, S=Nordrhein-Westfalen, C=DE",
            "Git"));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AnUnsignedHelperInTheInstallIsNotPartOfTheFamily()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, Unsigned(
            @"C:\Users\alice\AppData\Local\OpenAI\Codex\bin\d375f7df50d3b421\helper.exe", "9f9f"));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AFamilyOnAPlatformProductIsRefused()
    {
        // Every System32 binary is this product. A family on it would be the operating system.
        var rule = RulePickedFrom(Verified(
            @"C:\Tools\curl\curl.exe",
            "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
            "Microsoft® Windows® Operating System"));

        var decision = Route(rule, Verified(
            @"C:\Windows\System32\svchost.exe",
            "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
            "Microsoft® Windows® Operating System"));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AFamilyOnALocalisedOperatingSystemProductIsRefusedToo()
    {
        // Observed on the development machine, whose display language is Russian: Windows component
        // version strings are localised, so no list of product names can recognise them. The signer
        // is what gives them away.
        const string Windows = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
        var rule = RulePickedFrom(Verified(@"C:\Windows\System32\notepad.exe", Windows, "Операционная система Microsoft® Windows®"));

        var decision = Route(rule, Verified(@"C:\Windows\System32\svchost.exe", Windows, "Операционная система Microsoft® Windows®"));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.False(rule.UsesFamilyMatching);
    }

    // ---- Unsigned applications ---------------------------------------------------------------------

    [Fact]
    public void AnUnsignedApplicationIsRecognisedByItsBytesWhereverItIsMoved()
    {
        var rule = RulePickedFrom(Unsigned(@"D:\Tools\tool.exe", "aa11", size: 5000));

        var decision = Route(rule, Unsigned(@"E:\Moved\tool.exe", "aa11", size: 5000));

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.FileHashRule, decision.Reason);
    }

    [Fact]
    public void AnUnsignedApplicationChangedInPlaceIsRefusedUntilSelectedAgain()
    {
        var rule = RulePickedFrom(Unsigned(@"D:\Tools\tool.exe", "aa11", size: 5000));

        var decision = Route(rule, Unsigned(@"D:\Tools\tool.exe", "bb22", size: 5000));

        Assert.Equal(RouteAction.Block, decision.Action);
        Assert.Equal(RouteReasonKind.IdentityMismatch, decision.Reason);
    }

    [Fact]
    public void AnUnsignedApplicationGetsNoFamily()
    {
        var rule = RulePickedFrom(Unsigned(@"D:\Tools\App\tool.exe", "aa11", size: 5000));

        var decision = Route(rule, Unsigned(@"D:\Tools\App\other.exe", "cc33", size: 7000));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.False(rule.Identity.SupportsFamilyMatching);
    }

    // ---- Evidence that has not arrived yet ----------------------------------------------------------

    [Fact]
    public void AClaimWithoutAVerifiedSignatureIsHeldNotGuessed()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, ImageEvidence.FromPath(CodexAfter));

        Assert.Equal(RouteAction.Block, decision.Action);
        Assert.Equal(RouteReasonKind.IdentityPending, decision.Reason);
        Assert.Equal(EvidenceNeeds.Signature, decision.Needs);
    }

    [Fact]
    public void AnUnrelatedProgramIsNeverHeld()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, ImageEvidence.FromPath(@"C:\Program Files\Mozilla Firefox\firefox.exe"));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Equal(RouteReasonKind.NoMatchingRule, decision.Reason);
    }

    [Fact]
    public void AClaimOnAnUnsignedRuleWaitsForTheHash()
    {
        var rule = RulePickedFrom(Unsigned(@"D:\Tools\tool.exe", "aa11", size: 5000));

        var decision = Route(rule, new ImageEvidence { ExecutablePath = @"E:\Other\renamed.exe", FileSize = 5000 });

        Assert.Equal(RouteReasonKind.IdentityPending, decision.Reason);
        Assert.Equal(EvidenceNeeds.Hash, decision.Needs);
    }

    [Fact]
    public void ARuleForTheDirectLaneNeverHoldsAConnection()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject)) with { Action = RouteAction.Direct };

        var decision = Route(rule, ImageEvidence.FromPath(CodexAfter));

        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void SelectedUdpIsHeldTooWhileTheIdentityIsVerified()
    {
        var rule = RulePickedFrom(Verified(CodexBefore, OpenAiSubject));

        var decision = Route(rule, ImageEvidence.FromPath(CodexAfter), FlowProtocol.Udp);

        Assert.Equal(RouteAction.Block, decision.Action);
    }
}
