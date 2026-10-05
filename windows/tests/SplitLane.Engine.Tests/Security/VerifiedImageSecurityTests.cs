using SplitLane.Core.Rules;
using SplitLane.Engine.Flows;
using SplitLane.Platform;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-014: a signature verdict is applied only to the file version it was computed for. A process
/// whose file was swapped between its start and its verification does not inherit the verdict of
/// whatever file is at the path now.
/// </summary>
[Trait("Category", "Security")]
public sealed class VerifiedImageSecurityTests
{
    private const string Path = @"C:\Vendor\app.exe";

    private static readonly FileStamp Original = new(1000, 1, 1, 11);
    private static readonly FileStamp Swapped = new(1000, 1, 1, 22);

    private static ImageEvidence Signed() => new()
    {
        ExecutablePath = Path,
        Signature = SignatureStatus.Valid,
        SignerSubject = "CN=Vendor",
        SignerName = "Vendor",
        HasVersionInfo = true,
    };

    [Fact]
    public async Task A_verdict_for_another_version_of_the_file_is_not_applied()
    {
        // The process was first seen with the original file; by verification time the path holds a
        // different (genuinely signed) file.
        await using var catalog = ImageCatalog.ForVerifiedVersions((_, _) => (Signed(), Swapped), _ => Original);

        var record = catalog.Refresh(Path);
        var evidence = catalog.VerifyNow(record, EvidenceNeeds.Signature);

        Assert.NotEqual(SignatureStatus.Valid, evidence.Signature);
        Assert.Null(evidence.SignerSubject);
    }

    [Fact]
    public async Task A_verdict_for_the_same_version_is_applied()
    {
        await using var catalog = ImageCatalog.ForVerifiedVersions((_, _) => (Signed(), Original), _ => Original);

        var record = catalog.Refresh(Path);
        var evidence = catalog.VerifyNow(record, EvidenceNeeds.Signature);

        Assert.Equal(SignatureStatus.Valid, evidence.Signature);
        Assert.Equal("CN=Vendor", evidence.SignerSubject);
    }

    [Fact]
    public async Task A_swap_and_swap_back_is_still_caught_by_the_verified_handle()
    {
        // A -> B -> A: the stamp at the path matches the record again by the time anyone looks, but the
        // handle that was verified belonged to B.
        await using var catalog = ImageCatalog.ForVerifiedVersions((_, _) => (Signed(), Swapped), _ => Original);

        var record = catalog.Refresh(Path);
        var evidence = catalog.VerifyNow(record, EvidenceNeeds.Signature);

        Assert.NotEqual(SignatureStatus.Valid, evidence.Signature);
    }

    [Fact]
    public void The_real_inspector_reports_the_stamp_of_the_file_it_verified()
    {
        var tool = System.IO.Path.Combine(Environment.SystemDirectory, "notepad.exe");

        var (evidence, stamp) = WindowsImageInspector.ReadWithStamp(tool, computeSha256: false);

        Assert.NotNull(evidence);
        Assert.True(ImageFile.TryGetStamp(ExecutablePath.Normalize(tool), out var now));
        Assert.Equal(now, stamp);
    }
}
