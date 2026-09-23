using SplitLane.Engine.Flows;
using SplitLane.Platform;

namespace SplitLane.Engine.Tests;

/// <summary>
/// Which files the LocalSystem engine is willing to open, and what it reads from them.
/// </summary>
/// <remarks>
/// From the security review: a rule path, or the image of a process started from a network share,
/// made the engine open <c>\\host\share\...</c> as LocalSystem - the machine authenticating to a host
/// of the user's choosing. These tests pin that nothing off the machine is touched.
/// </remarks>
public sealed class ImageLocationTests
{
    [Theory]
    [InlineData(@"\\attacker.example\share\codex.exe")]
    [InlineData(@"\\?\UNC\attacker.example\share\codex.exe")]
    [InlineData(@"\\.\pipe\splitlane")]
    [InlineData(@"\\?\GLOBALROOT\Device\Mup\attacker\share\x.exe")]
    [InlineData(@"relative\codex.exe")]
    [InlineData("")]
    public void NothingOffALocalDriveIsOpened(string path)
    {
        Assert.False(ImageFile.IsLocalPath(path));
        Assert.False(ImageFile.TryGetStamp(path, out _));
        Assert.Null(ImageFile.Inspect(path, computeSha256: true));
        Assert.Equal((null, null, null), ImageFile.ReadVersion(path));
        Assert.Null(WindowsImageInspector.Read(path, computeSha256: true));
        Assert.Empty(WindowsImageInspector.Instance.ChildDirectories(path));
    }

    [Fact]
    public void EveryProcessOnTheMachineCanBeAskedForItsPackage()
    {
        // The engine asks this of every new process, on the thread every connection goes through. An
        // import from the wrong DLL passed every other test - none of them had a packaged process - and
        // threw on the first packaged process of a live run. Whatever is running here is asked.
        var packaged = 0;

        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            using (process)
            {
                if (ProcessPackage.FamilyName((uint)process.Id) is not null)
                {
                    packaged++;
                }
            }
        }

        Assert.True(packaged >= 0);

        // And the import itself resolves: the check above tolerates a missing entry point so that the
        // engine keeps routing, which would also let a wrong import pass unnoticed.
        var result = ImageInspectionNative.GetStagedPackageOrigin("Not.A.Package_1.0.0.0_x64__0000000000000", out _);
        Assert.NotEqual(0, result);
    }

    [Fact]
    public void TheProgramDatabaseNameIsReadFromTheSignedImage()
    {
        // Measured on the development machine: dotnet.exe -> dotnet.pdb, codex.exe -> codex.pdb,
        // ChatGPT.exe -> chrome.exe.pdb. The host is what every build agent has.
        var dotnet = Environment.ProcessPath is { } host && host.EndsWith("dotnet.exe", StringComparison.OrdinalIgnoreCase)
            ? host
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");

        Assert.Equal("dotnet.pdb", PeDebugInfo.ReadPdbName(dotnet));
        Assert.Equal("dotnet.pdb", WindowsImageInspector.Read(dotnet, computeSha256: false)?.DebugName);
    }

    [Fact]
    public void ACodeViewRecordYieldsOnlyTheFileNameOfItsPath()
    {
        var path = System.Text.Encoding.UTF8.GetBytes(@"D:\a\_work\1\s\target\release\deps\codex.pdb");
        var record = new byte[24 + path.Length + 1];
        BitConverter.GetBytes(0x53445352u).CopyTo(record, 0);
        path.CopyTo(record, 24);

        Assert.Equal("codex.pdb", PeDebugInfo.PdbName(record));
        Assert.Null(PeDebugInfo.PdbName(new byte[40]));
        Assert.Null(PeDebugInfo.ReadPdbName(Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts")));
    }

    [Fact]
    public void TheSystemDriveIsLocal() =>
        Assert.True(ImageFile.IsLocalPath(Path.Combine(Environment.SystemDirectory, "PING.EXE")));

    [Fact]
    public void AProcessImageOnAShareIsNeverVerified()
    {
        var catalog = new ImageCatalog(workers: 1);

        var record = catalog.Refresh(@"\\attacker.example\share\codex.exe");
        var evidence = catalog.VerifyNow(record, Core.Rules.EvidenceNeeds.Signature | Core.Rules.EvidenceNeeds.Hash);

        Assert.Equal(Core.Rules.SignatureStatus.Invalid, evidence.Signature);
        Assert.Equal(string.Empty, evidence.Sha256);
    }

    [Fact]
    public void TheVersionResourceIsReadLanguageNeutral()
    {
        // Windows components localise their version strings through MUI satellites, which the
        // executable's signature does not cover. The neutral resource is what the signature covers and
        // reads the same in every display language - English, for Windows.
        var (product, original, _) = ImageFile.ReadVersion(Path.Combine(Environment.SystemDirectory, "notepad.exe"));

        Assert.NotNull(product);
        Assert.Contains("Windows", product, StringComparison.Ordinal);
        Assert.DoesNotContain("Операционная", product, StringComparison.Ordinal);
        Assert.NotNull(original);
    }

    [Fact]
    public void AShortNameIsExpandedToTheLongOne()
    {
        // %TEMP% is an 8.3 path on the machine this was written on (C:\Users\JOHNSM~1\...); on one where
        // it is not, the path comes back unchanged, which is the other half of the contract.
        var temp = Path.GetTempPath();
        var expanded = ImageFile.LongPath(temp);

        Assert.DoesNotContain("~", expanded, StringComparison.Ordinal);
        Assert.True(Directory.Exists(expanded));
    }
}
