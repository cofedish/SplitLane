using SplitLane.Core.Update;

namespace SplitLane.Core.Tests;

/// <summary>Comparing versions that arrive spelled three different ways.</summary>
public sealed class ProductVersionTests
{
    [Theory]
    [InlineData("0.6.0", 0, 6, 0, 0)]
    [InlineData("v0.6.0", 0, 6, 0, 0)]
    [InlineData("0.6.0.12", 0, 6, 0, 12)]
    [InlineData("1", 1, 0, 0, 0)]
    [InlineData("  0.6  ", 0, 6, 0, 0)]
    public void VersionsAreParsedHoweverTheyAreSpelled(
        string text, int major, int minor, int patch, int build)
    {
        Assert.True(ProductVersion.TryParse(text, out var version));
        Assert.Equal(new ProductVersion(major, minor, patch, build), version);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("nightly")]
    [InlineData("0.6.x")]
    [InlineData("0.6.0.1.2")]
    [InlineData("-1.0")]
    public void AnythingElseIsNotAVersion(string? text) =>
        Assert.False(ProductVersion.TryParse(text, out _));

    [Fact]
    public void MissingFieldsAreZeroRatherThanUnknown()
    {
        // The reason this exists rather than System.Version: a tag says 0.6.0 and the MSI it built
        // says 0.6.0.0, and an installation must not offer itself as an update to itself.
        Assert.Equal(ProductVersion.Parse("0.6.0"), ProductVersion.Parse("0.6.0.0"));
        Assert.False(ProductVersion.Parse("0.6.0").IsNewerThan(ProductVersion.Parse("0.6.0.0")));
    }

    [Theory]
    [InlineData("0.7.0", "0.6.0")]
    [InlineData("0.6.1", "0.6.0")]
    [InlineData("1.0.0", "0.99.99")]
    [InlineData("0.6.0.2", "0.6.0.1")]
    [InlineData("0.10.0", "0.9.0")]
    public void NewerIsNewer(string newer, string older) =>
        Assert.True(ProductVersion.Parse(newer).IsNewerThan(ProductVersion.Parse(older)));

    [Fact]
    public void OlderIsNotOfferedAsAnUpdate() =>
        Assert.False(ProductVersion.Parse("0.5.0").IsNewerThan(ProductVersion.Parse("0.6.0")));
}
