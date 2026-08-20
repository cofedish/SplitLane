using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>
/// Detection of packaged applications, whose install path carries a version.
/// </summary>
/// <remarks>
/// This is W-4 in the threat model, and it matters more than it sounds. A packaged application moves
/// on every update, so a path-keyed rule stops matching without any error: the application keeps
/// working and quietly goes DIRECT, which is exactly the failure the product exists to prevent.
/// Detecting the case is what lets the UI warn instead of leaving it to be discovered.
/// </remarks>
public sealed class PackagedApplicationTests
{
    private static AppIdentity Identity(string path, string? familyName = null) => new()
    {
        ExecutablePath = ExecutablePath.Normalize(path),
        DisplayName = ExecutablePath.FileName(path),
        PackageFamilyName = familyName,
    };

    [Theory]
    [InlineData(@"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.18.3181.0_x64__8wekyb3d8bbwe\wt.exe")]
    [InlineData(@"C:\Program Files\WindowsApps\AppleInc.AppleDevices_1.1540.23042.0_x64__nzyj5cx\AppleMobileDeviceLauncher.exe")]
    [InlineData(@"c:\program files\windowsapps\Some.App_1.0.0.0_x64__abc\app.exe")]
    public void PackagedPathsAreDetected(string path) =>
        Assert.True(Identity(path).IsPackaged, path);

    [Theory]
    [InlineData(@"C:\Program Files\Codex\Codex.exe")]
    [InlineData(@"C:\Users\alice\AppData\Local\Programs\Editor\editor.exe")]
    [InlineData(@"C:\Windows\System32\curl.exe")]
    public void OrdinaryPathsAreNot(string path) =>
        Assert.False(Identity(path).IsPackaged, path);

    [Fact]
    public void APackageFamilyNameAloneMarksItPackaged() =>
        Assert.True(Identity(@"D:\Odd\Location\app.exe", "Contoso.App_8wekyb3d8bbwe").IsPackaged);

    [Fact]
    public void TheVersionedSegmentIsNamedSoTheWarningCanBeSpecific()
    {
        var identity = Identity(
            @"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.18.3181.0_x64__8wekyb3d8bbwe\wt.exe");

        Assert.Equal("Microsoft.WindowsTerminal_1.18.3181.0_x64__8wekyb3d8bbwe", identity.VersionedSegment);
    }

    [Fact]
    public void AnUnpackagedApplicationHasNoVersionedSegment() =>
        Assert.Null(Identity(@"C:\Program Files\Codex\Codex.exe").VersionedSegment);

    [Fact]
    public void APackagedApplicationWithNoVersionedSegmentDoesNotInventOne()
    {
        // Marked packaged by its family name, but installed somewhere without the versioned
        // directory convention. The warning has to degrade to the general form rather than
        // reporting a segment that is not there.
        var identity = Identity(@"D:\Odd\Location\app.exe", "Contoso.App_8wekyb3d8bbwe");

        Assert.True(identity.IsPackaged);
        Assert.Null(identity.VersionedSegment);
    }

    [Fact]
    public void APlainUnderscoreInAFolderNameIsNotAVersionedSegment()
    {
        // "my_tools" is an ordinary folder. The double underscore before the publisher hash is what
        // makes a packaged directory recognisable; keying on a single underscore would flag half the
        // folders on a developer's disk.
        var identity = Identity(@"C:\Program Files\WindowsApps\my_tools\app.exe");

        Assert.True(identity.IsPackaged);
        Assert.Null(identity.VersionedSegment);
    }

    [Fact]
    public void PackagedApplicationsStillRouteNormallyWhileTheirPathIsCurrent()
    {
        // The warning is about the future. Until the path changes, the rule works like any other,
        // and a packaged app must not be treated as second class.
        var path = @"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.18.3181.0_x64__8wekyb3d8bbwe\wt.exe";
        var engine = new RuleEngine(new RuntimeConfiguration
        {
            Rules = [new AppRule { Identity = Identity(path) }],
        });

        var decision = engine.Decide(
            new FlowDescriptor(42, ExecutablePath.Normalize(path), "93.184.216.34", 443, FlowProtocol.Tcp));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void TheWindowsAppsStoreIsNotASafeFamilyRoot()
    {
        // Every packaged application on the machine lives under WindowsApps, so family matching
        // there would be the System32 mistake in a different folder.
        var identity = Identity(
            @"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.18.3181.0_x64__8wekyb3d8bbwe\wt.exe");

        // The versioned directory itself belongs to one application, so it is a legitimate root.
        Assert.True(identity.SupportsFamilyMatching);

        // The store root above it is not.
        Assert.False(ExecutablePath.IsSafeFamilyRoot(@"C:\Program Files\WindowsApps"));
    }
}
