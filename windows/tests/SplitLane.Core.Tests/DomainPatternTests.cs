using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

public sealed class DomainPatternTests
{
    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "EXAMPLE.COM", true)]
    [InlineData("example.com", "example.com.", true)]
    [InlineData("example.com", "api.example.com", false)]
    [InlineData("example.com", "evil-example.com", false)]
    [InlineData("example.com", "example.com.evil.org", false)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData("*.example.com", "api.example.com", true)]
    [InlineData("*.example.com", "foo.bar.example.com", true)]
    [InlineData("*.example.com", "evil-example.com", false)]
    public void ExactAndWildcardPatternsHaveLabelBoundaries(string pattern, string hostname, bool expected)
    {
        Assert.True(DomainPattern.TryParse(pattern, out var parsed, out _));
        Assert.Equal(expected, parsed.Matches(hostname));
    }

    [Fact]
    public void InternationalNamesUseOneAsciiForm()
    {
        Assert.True(DomainPattern.TryParse("bücher.example", out var pattern, out _));
        Assert.True(pattern.Matches("xn--bcher-kva.example"));
        Assert.Equal("xn--bcher-kva.example", pattern.Normalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("*example.com")]
    [InlineData("foo.*.example.com")]
    [InlineData("example..com")]
    [InlineData("-bad.example")]
    [InlineData("bad-.example")]
    [InlineData("192.0.2.1")]
    public void MalformedPatternsAreRejected(string value) =>
        Assert.False(DomainPattern.TryParse(value, out _, out _));
}
