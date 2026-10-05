using SplitLane.Core.Update;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-024: a signed manifest may point the engine only at this repository's release downloads, and
/// the WinDivert fetch refuses to skip its hash check unless asked by name.
/// </summary>
[Trait("Category", "Security")]
public sealed class ReleaseSourceSecurityTests
{
    [Theory]
    [InlineData("https://github.com/cofedish/SplitLane/releases/download/v0.13.0/SplitLane-0.13.0-x64.msi", true)]
    [InlineData("https://GITHUB.com/cofedish/SplitLane/releases/download/v0.13.0/x.msi", true)]
    [InlineData("https://github.com/Cofedish/splitlane/releases/download/v0.13.0/x.msi", true)]     // GitHub ignores case
    [InlineData("https://github.com/someone-else/SplitLane/releases/download/v9/x.msi", false)]   // another repository
    [InlineData("https://github.com/cofedish/SplitLane/archive/refs/tags/v9.zip", false)]         // not a release asset
    [InlineData("https://gist.github.com/cofedish/SplitLane/releases/download/v9/x.msi", false)]  // another GitHub host
    [InlineData("https://objects.githubusercontent.com/cofedish/SplitLane/releases/download/v9/x.msi", false)]
    [InlineData("https://github.com:8443/cofedish/SplitLane/releases/download/v9/x.msi", false)]  // another port
    [InlineData("https://user@github.com/cofedish/SplitLane/releases/download/v9/x.msi", false)]  // user information
    [InlineData("https://github.com.evil.example/cofedish/SplitLane/releases/download/v9/x.msi", false)]
    [InlineData("http://github.com/cofedish/SplitLane/releases/download/v9/x.msi", false)]
    public void Only_this_repositorys_release_downloads_are_acceptable(string url, bool accepted) =>
        Assert.Equal(accepted, ManifestVerifier.IsAcceptableUrl(url));

    [Fact]
    public void The_driver_fetch_refuses_an_empty_hash_unless_told_by_name()
    {
        var script = File.ReadAllText(Path.Combine(WindowsRoot(), "tools", "fetch-windivert.ps1"));

        Assert.Contains("[switch]$AllowUnverified", script, StringComparison.Ordinal);
        Assert.Contains("if (-not $Sha256 -and -not $AllowUnverified)", script, StringComparison.Ordinal);
    }

    private static string WindowsRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "SplitLane.Windows.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("The windows/ directory was not found above the test binaries.");
    }
}
