using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>
/// The Windows routing key: normalisation, the family boundary, and the shared-directory guard.
/// </summary>
public sealed class ExecutablePathTests
{
    [Theory]
    [InlineData(@"C:\App\App.exe", @"C:\App\App.exe")]
    [InlineData(@"  C:\App\App.exe  ", @"C:\App\App.exe")]
    [InlineData("\"C:\\App\\App.exe\"", @"C:\App\App.exe")]
    [InlineData(@"C:/App/App.exe", @"C:\App\App.exe")]
    [InlineData(@"C:\App\\App.exe", @"C:\App\App.exe")]
    [InlineData(@"C:\App\", @"C:\App")]
    [InlineData(@"C:\", @"C:\")]
    [InlineData(@"\??\C:\App\App.exe", @"C:\App\App.exe")]
    [InlineData(@"\\?\C:\App\App.exe", @"C:\App\App.exe")]
    [InlineData(@"\\?\UNC\server\share\App.exe", @"\\server\share\App.exe")]
    [InlineData(@"\\server\share\App.exe", @"\\server\share\App.exe")]
    [InlineData(null, "")]
    [InlineData("   ", "")]
    public void NormalisationIsCanonical(string? input, string expected) =>
        Assert.Equal(expected, ExecutablePath.Normalize(input));

    [Fact]
    public void NormalisationPreservesCasingForDisplay() =>
        Assert.Equal(@"C:\Program Files\Codex\Codex.exe",
            ExecutablePath.Normalize(@"C:\Program Files\Codex\Codex.exe"));

    [Fact]
    public void ComparerIgnoresCaseOrdinally()
    {
        Assert.True(ExecutablePath.Comparer.Equals(@"C:\App\App.exe", @"c:\app\APP.EXE"));
        Assert.False(ExecutablePath.Comparer.Equals(@"C:\App\App.exe", @"C:\App\App2.exe"));
    }

    [Theory]
    [InlineData(@"C:\Program Files\Codex\Codex.exe", @"C:\Program Files\Codex")]
    [InlineData(@"C:\App.exe", @"C:\")]
    [InlineData(@"\\server\share\App.exe", @"\\server\share")]
    [InlineData("App.exe", "")]
    public void FamilyRootIsTheContainingDirectory(string path, string expected) =>
        Assert.Equal(expected, ExecutablePath.FamilyRoot(path));

    [Fact]
    public void AncestorsAreNearestFirstAndBounded()
    {
        var ancestors = ExecutablePath.Ancestors(@"C:\a\b\c\d.exe").ToArray();

        Assert.Equal([@"C:\a\b\c", @"C:\a\b", @"C:\a", @"C:\"], ancestors);
    }

    [Fact]
    public void AncestorWalkStopsAtTheLimit()
    {
        var deep = @"C:" + string.Concat(Enumerable.Repeat(@"\x", 40)) + @"\deep.exe";

        Assert.Equal(ExecutablePath.AncestorWalkLimit, ExecutablePath.Ancestors(deep).Count());
    }

    [Theory]
    [InlineData(@"C:\Program Files\Codex\bin\helper.exe", @"C:\Program Files\Codex", true)]
    [InlineData(@"C:\Program Files\Codex\helper.exe", @"C:\Program Files\Codex", true)]
    [InlineData(@"C:\Program Files\CodexEvil\helper.exe", @"C:\Program Files\Codex", false)]
    [InlineData(@"C:\Program Files\Codex", @"C:\Program Files\Codex", false)]
    [InlineData(@"C:\App.exe", @"C:\", true)]
    [InlineData(@"C:\a\b.exe", "", false)]
    public void FamilyContainmentCutsOnTheSeparator(string candidate, string root, bool expected) =>
        Assert.Equal(expected, ExecutablePath.IsUnderFamilyRoot(candidate, root));

    [Fact]
    public void FamilyContainmentIsCaseInsensitive() =>
        Assert.True(ExecutablePath.IsUnderFamilyRoot(
            @"c:\program files\codex\bin\HELPER.EXE", @"C:\Program Files\Codex"));

    [Theory]
    [InlineData(@"C:\Program Files\Codex")]
    [InlineData(@"C:\Program Files (x86)\Codex")]
    [InlineData(@"C:\Users\alice\AppData\Local\Programs\Codex")]
    [InlineData(@"C:\Users\alice\Desktop\Codex")]
    [InlineData(@"D:\Games\Steam")]
    [InlineData(@"\\server\share\apps\Codex")]
    [InlineData(@"C:\Windows\SystemApps\Something")]
    public void SpecificDirectoriesAreSafeFamilyRoots(string root) =>
        Assert.True(ExecutablePath.IsSafeFamilyRoot(root), root);

    [Theory]
    [InlineData(@"C:\")]
    [InlineData(@"C:\Windows")]
    [InlineData(@"C:\Windows\System32")]
    [InlineData(@"C:\Windows\SysWOW64")]
    [InlineData(@"c:\windows\system32")]
    [InlineData(@"C:\Program Files")]
    [InlineData(@"C:\Program Files (x86)")]
    [InlineData(@"C:\ProgramData")]
    [InlineData(@"C:\Users")]
    [InlineData(@"C:\Users\alice")]
    [InlineData(@"C:\Users\alice\AppData")]
    [InlineData(@"C:\Users\alice\AppData\Local")]
    [InlineData(@"C:\Users\alice\AppData\Roaming")]
    [InlineData(@"C:\Users\alice\AppData\Local\Programs")]
    [InlineData(@"C:\Users\alice\Downloads")]
    [InlineData(@"C:\Users\alice\Desktop")]
    [InlineData(@"C:\Temp")]
    [InlineData(@"\\server\share")]
    [InlineData("")]
    [InlineData(null)]
    public void SharedDirectoriesAreNotSafeFamilyRoots(string? root) =>
        Assert.False(ExecutablePath.IsSafeFamilyRoot(root), root ?? "<null>");

    [Theory]
    [InlineData(@"C:\Program Files\Codex\Codex.exe", "Codex.exe")]
    [InlineData(@"C:\App.exe", "App.exe")]
    [InlineData("App.exe", "App.exe")]
    [InlineData("", "")]
    public void FileNameIsTheLastSegment(string path, string expected) =>
        Assert.Equal(expected, ExecutablePath.FileName(path));
}
