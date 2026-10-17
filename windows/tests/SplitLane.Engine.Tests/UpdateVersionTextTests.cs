using SplitLane.App.Services;

namespace SplitLane.Engine.Tests;

public sealed class UpdateVersionTextTests
{
    [Theory]
    [InlineData("0.11.0+58dfa93cf584b4b6079e7f3075497634c93b0312", "0.11.0")]
    [InlineData("0.9.1", "0.9.1")]
    [InlineData(null, "unknown")]
    public void DisplayVersionDropsBuildMetadata(string? version, string expected)
        => Assert.Equal(expected, UpdateVersionText.DisplayVersion(version));
}
