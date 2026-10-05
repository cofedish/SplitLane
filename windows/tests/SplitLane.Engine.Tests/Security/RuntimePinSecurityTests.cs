using System.Text.RegularExpressions;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-012: the runtime a self-contained package carries is pinned, not left to whichever SDK built
/// it, and the packaging script refuses anything older.
/// </summary>
[Trait("Category", "Security")]
public sealed partial class RuntimePinSecurityTests
{
    /// <summary>The first patch with none of the runtime CVEs the audit found in 10.0.10.</summary>
    private static readonly Version FirstClean = new(10, 0, 12);

    [Fact]
    public void The_pinned_runtime_patch_is_not_older_than_the_first_clean_one()
    {
        var targets = File.ReadAllText(Path.Combine(WindowsRoot(), "Directory.Build.targets"));
        var pinned = Pin().Match(targets);

        Assert.True(pinned.Success, "Directory.Build.targets no longer pins SplitLaneMinimumRuntimePatch");
        Assert.True(Version.Parse(pinned.Groups[1].Value) >= FirstClean);
        Assert.Contains("KnownFrameworkReference Update=\"Microsoft.NETCore.App\"", targets, StringComparison.Ordinal);
        Assert.Contains("KnownFrameworkReference Update=\"Microsoft.WindowsDesktop.App\"", targets, StringComparison.Ordinal);
    }

    [Fact]
    public void The_packaging_script_refuses_an_older_runtime()
    {
        var script = File.ReadAllText(Path.Combine(WindowsRoot(), "tools", "build-installer.ps1"));

        Assert.Contains("SplitLaneMinimumRuntimePatch", script, StringComparison.Ordinal);
        Assert.Contains("older than the pinned", script, StringComparison.Ordinal);
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

    [GeneratedRegex(@"<SplitLaneMinimumRuntimePatch>([0-9.]+)</SplitLaneMinimumRuntimePatch>")]
    private static partial Regex Pin();
}
