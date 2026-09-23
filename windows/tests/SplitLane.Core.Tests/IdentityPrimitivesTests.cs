using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>
/// The pieces identity is built from: the publisher key, the directories an updater renames, the
/// install root above them, and the product names too shared to be a family.
/// </summary>
public sealed class IdentityPrimitivesTests
{
    // ---- Publisher -----------------------------------------------------------------------------

    [Fact]
    public void AQuotedCommonNameKeepsItsComma()
    {
        var parsed = PublisherName.Parse(
            "CN=\"OpenAI OpCo, LLC\", O=\"OpenAI OpCo, LLC\", L=San Francisco, S=California, C=US");

        Assert.Equal("CN", parsed[0].Key);
        Assert.Equal("OpenAI OpCo, LLC", parsed[0].Value);
        Assert.Equal(5, parsed.Count);
    }

    [Fact]
    public void TheCanonicalKeyIsTheSameForBothRealCodexCertificates()
    {
        // Different certificates, different intermediate CAs, one publisher.
        var aoc = PublisherName.Canonical(
            "CN=\"OpenAI OpCo, LLC\", O=\"OpenAI OpCo, LLC\", L=San Francisco, S=California, C=US");
        var eoc = PublisherName.Canonical(
            "CN=\"OpenAI OpCo, LLC\", O=\"OpenAI OpCo, LLC\", L=San Francisco, S=California, C=US");

        Assert.Equal(aoc, eoc);
        Assert.Equal("CN=OPENAI OPCO, LLC;O=OPENAI OPCO, LLC;L=SAN FRANCISCO;S=CALIFORNIA;C=US", aoc);
    }

    [Fact]
    public void AttributesThatChangeBetweenCertificatesAreNotIdentity()
    {
        var ov = PublisherName.Canonical("CN=Contoso Ltd, O=Contoso Ltd, L=Redmond, S=Washington, C=US");
        var ev = PublisherName.Canonical(
            "SERIALNUMBER=601545, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=US, " +
            "CN=Contoso Ltd, O=Contoso Ltd, OU=Engineering, STREET=1 Microsoft Way, L=Redmond, ST=Washington, C=US");

        Assert.Equal(ov, ev);
    }

    [Fact]
    public void ADifferentOrganisationIsADifferentPublisher()
    {
        Assert.NotEqual(
            PublisherName.Canonical("CN=Contoso Ltd, O=Contoso Ltd, C=US"),
            PublisherName.Canonical("CN=Contoso Ltd, O=Contoso Holdings, C=US"));
    }

    [Fact]
    public void ASubjectWithNothingIdentifyingHasNoKey() =>
        Assert.Equal(string.Empty, PublisherName.Canonical("OU=Somewhere, E=someone@example.com"));

    [Fact]
    public void TheCommonNameCanBeReadBackForMessages() =>
        Assert.Equal("OPENAI OPCO, LLC", PublisherName.CommonNameOf(PublisherName.Canonical(
            "CN=\"OpenAI OpCo, LLC\", O=\"OpenAI OpCo, LLC\", C=US")));

    // ---- Directories an updater renames ----------------------------------------------------------

    [Theory]
    [InlineData("247581e40ee272fb")]
    [InlineData("d375f7df50d3b421")]
    [InlineData("app-1.0.9254")]
    [InlineData("241.14494.240")]
    [InlineData("{0F2B3C4D-1A2B-4C3D-8E9F-0123456789AB}")]
    [InlineData("0f2b3c4d-1a2b-4c3d-8e9f-0123456789ab")]
    public void GeneratedDirectoryNamesAreVolatile(string segment) =>
        Assert.True(ExecutablePath.IsVolatileDirectory(segment), segment);

    [Theory]
    [InlineData("bin")]
    [InlineData("x64")]
    [InlineData("deadbeef")]
    [InlineData("facade")]
    [InlineData("20240101")]
    [InlineData("v2")]
    [InlineData("Application")]
    [InlineData("1234567")]
    public void NamesAreNotVolatile(string segment) =>
        Assert.False(ExecutablePath.IsVolatileDirectory(segment), segment);

    [Theory]
    [InlineData(@"C:\Users\a\AppData\Local\OpenAI\Codex\bin\247581e40ee272fb\codex.exe", @"C:\Users\a\AppData\Local\OpenAI\Codex\bin")]
    [InlineData(@"C:\Users\a\AppData\Local\JetBrains\Toolbox\apps\IDEA-U\ch-0\241.14494.240\bin\idea64.exe", @"C:\Users\a\AppData\Local\JetBrains\Toolbox\apps\IDEA-U\ch-0")]
    [InlineData(@"C:\Users\a\AppData\Local\Discord\app-1.0.9254\Discord.exe", @"C:\Users\a\AppData\Local\Discord")]
    [InlineData(@"C:\Program Files\Contoso\contoso.exe", @"C:\Program Files\Contoso")]
    public void TheInstallRootIsAboveTheDirectoryTheUpdaterRenames(string executable, string expected) =>
        Assert.Equal(expected, ExecutablePath.InstallRoot(executable));

    [Fact]
    public void AnExecutableDirectlyInAVersionDirectoryCoversEverythingAboveIt()
    {
        var (root, below) = ExecutablePath.FamilyScope(@"C:\Users\a\AppData\Local\Discord\app-1.0.9254\Discord.exe");

        Assert.Equal(@"C:\Users\a\AppData\Local\Discord", root);
        Assert.Null(below);
        Assert.True(ExecutablePath.IsInFamilyScope(@"C:\Users\a\AppData\Local\Discord\Update.exe", root, below));
    }

    [Fact]
    public void AnExecutableDeepInsideAVersionDirectoryCoversItsOwnFolderInAnyVersion()
    {
        var (root, below) = ExecutablePath.FamilyScope(@"C:\A\cua_node\df473e5367fa2b42\bin\swift\x64\tool.exe");

        Assert.Equal(@"C:\A\cua_node", root);
        Assert.Equal(@"bin\swift\x64", below);
        Assert.True(ExecutablePath.IsInFamilyScope(@"C:\A\cua_node\f53823cd54b14f45\bin\swift\x64\other.exe", root, below));
        Assert.True(ExecutablePath.IsInFamilyScope(@"C:\A\cua_node\f53823cd54b14f45\bin\swift\x64\sub\deeper.exe", root, below));
        Assert.False(ExecutablePath.IsInFamilyScope(@"C:\A\cua_node\f53823cd54b14f45\bin\node.exe", root, below));
        Assert.False(ExecutablePath.IsInFamilyScope(@"C:\A\cua_node\not-a-version\bin\swift\x64\other.exe", root, below));
        Assert.False(ExecutablePath.IsInFamilyScope(@"C:\A\cua_node\f53823cd54b14f45\bin\swift\x64evil\other.exe", root, below));
    }

    [Fact]
    public void TheInstallRootNeverClimbsIntoASharedDirectory() =>
        // Climbing out of the version directory would give Program Files, which is refused; the
        // executable's own directory is the answer instead.
        Assert.Equal(@"C:\Program Files\1.2.3", ExecutablePath.InstallRoot(@"C:\Program Files\1.2.3\tool.exe"));

    [Fact]
    public void AMovedOnBuildIsLookedForInTheVolatileDirectorysSiblings()
    {
        Assert.True(ExecutablePath.TrySplitAtVolatileDirectory(
            @"C:\A\Codex\runtimes\cua_node\df473e5367fa2b42\bin\swift\x64\tool.exe",
            out var root, out var segment, out var rest));

        Assert.Equal(@"C:\A\Codex\runtimes\cua_node", root);
        Assert.Equal("df473e5367fa2b42", segment);
        Assert.Equal(@"bin\swift\x64\tool.exe", rest);
    }

    // ---- Product families -------------------------------------------------------------------------

    [Theory]
    [InlineData("Microsoft® Windows® Operating System")]
    [InlineData("Microsoft (R) Windows (R) Operating System")]
    [InlineData("Electron")]
    [InlineData("Node.js")]
    [InlineData("OpenJDK Platform binary")]
    [InlineData("")]
    [InlineData(null)]
    public void PlatformProductsCannotRootAFamily(string? product) =>
        Assert.False(ProductFamily.CanRootFamily(product));

    [Theory]
    [InlineData("Codex")]
    [InlineData("Microsoft Outlook")]
    [InlineData("IntelliJ IDEA")]
    public void ApplicationProductsCan(string product) =>
        Assert.True(ProductFamily.CanRootFamily(product));

    [Theory]
    [InlineData("CN=Microsoft Windows, O=Microsoft Corporation, C=US")]
    [InlineData("CN=Microsoft Windows Publisher, O=Microsoft Corporation, C=US")]
    [InlineData("CN=Microsoft 3rd Party Application Component, O=Microsoft Corporation, C=US")]
    public void NothingTheOperatingSystemsSignersSignRootsAFamily(string subject) =>
        Assert.False(ProductFamily.CanRootFamily("Операционная система Microsoft® Windows®", PublisherName.Canonical(subject)));

    [Fact]
    public void AnApplicationMicrosoftSignsAsAnApplicationCanStillRootAFamily() =>
        Assert.True(ProductFamily.CanRootFamily(
            "Microsoft Outlook", PublisherName.Canonical("CN=Microsoft Corporation, O=Microsoft Corporation, C=US")));

    [Fact]
    public void ProductNamesCompareWithoutTrademarksOrCase() =>
        Assert.True(ProductFamily.Same("Contoso® Chat", "contoso  chat"));

    // ---- Identity as a whole ------------------------------------------------------------------------

    [Fact]
    public void TwoInstallationsOfOneApplicationHaveOneMatchKey()
    {
        var subject = PublisherName.Canonical("CN=Contoso Ltd, O=Contoso Ltd, C=US");
        var first = new AppIdentity
        {
            ExecutablePath = @"C:\A\tool.exe", DisplayName = "tool", Kind = IdentityKind.Signed,
            SignerSubject = subject, BinaryName = "tool.exe", ProductName = "Tool",
        };
        var second = first with { ExecutablePath = @"D:\B\tool.exe", BinaryName = "TOOL.EXE" };

        Assert.Equal(first.MatchKey, second.MatchKey);
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void AnUnsignedIdentityNeverSupportsAFamily() =>
        Assert.False(new AppIdentity
        {
            ExecutablePath = @"C:\Program Files\Contoso\tool.exe", DisplayName = "tool",
            Kind = IdentityKind.Unsigned, FileSha256 = "aa",
        }.SupportsFamilyMatching);
}
