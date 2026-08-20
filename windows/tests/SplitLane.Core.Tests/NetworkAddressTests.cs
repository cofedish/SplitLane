using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>
/// Address classification.
/// </summary>
/// <remarks>
/// The abbreviated-form cases are the reason this parser is hand-written instead of delegating to
/// <c>IPAddress.TryParse</c>. Each of them is a real spelling of loopback that a strict parser calls
/// "not loopback", and being wrong in that direction is what produces a proxy loop.
/// </remarks>
public sealed class NetworkAddressTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.0.0.2")]
    [InlineData("127.255.255.254")]
    [InlineData("127.1")]
    [InlineData("127.0.1")]
    [InlineData("2130706433")]
    [InlineData("0x7f000001")]
    [InlineData("0177.0.0.1")]
    [InlineData("::1")]
    [InlineData("0:0:0:0:0:0:0:1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:127.1.2.3")]
    public void LoopbackIsRecognised(string address) =>
        Assert.True(NetworkAddress.IsLoopbackAddress(address), address);

    [Theory]
    [InlineData("128.0.0.1")]
    [InlineData("8.8.8.8")]
    [InlineData("126.255.255.255")]
    [InlineData("::2")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("::ffff:8.8.8.8")]
    [InlineData("")]
    [InlineData("not-an-address")]
    public void NonLoopbackIsNotRecognised(string address) =>
        Assert.False(NetworkAddress.IsLoopbackAddress(address), address);

    [Theory]
    [InlineData("169.254.0.1")]
    [InlineData("169.254.255.255")]
    [InlineData("fe80::1")]
    [InlineData("febf::1")]
    [InlineData("::ffff:169.254.1.1")]
    public void LinkLocalIsRecognised(string address) =>
        Assert.True(NetworkAddress.IsLinkLocalAddress(address), address);

    [Theory]
    [InlineData("169.255.0.1")]
    [InlineData("168.254.0.1")]
    [InlineData("fec0::1")]
    [InlineData("fe00::1")]
    public void NonLinkLocalIsNotRecognised(string address) =>
        Assert.False(NetworkAddress.IsLinkLocalAddress(address), address);

    [Fact]
    public void LocalDestinationCoversBothFamiliesAndBothScopes()
    {
        Assert.True(NetworkAddress.IsLocalDestination("127.0.0.1"));
        Assert.True(NetworkAddress.IsLocalDestination("169.254.1.1"));
        Assert.True(NetworkAddress.IsLocalDestination("::1"));
        Assert.True(NetworkAddress.IsLocalDestination("fe80::abcd"));
        Assert.False(NetworkAddress.IsLocalDestination("93.184.216.34"));
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("LOCALHOST")]
    [InlineData("app.localhost")]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public void LoopbackHostsAreRecognised(string host) =>
        Assert.True(NetworkAddress.IsLoopbackHost(host), host);

    [Theory]
    [InlineData("localhost.evil.com")]
    [InlineData("notlocalhost")]
    [InlineData("example.com")]
    public void HostsThatMerelyContainLocalhostAreNot(string host) =>
        Assert.False(NetworkAddress.IsLoopbackHost(host), host);

    [Fact]
    public void ZoneSuffixIsStrippedBeforeClassification() =>
        Assert.True(NetworkAddress.IsLinkLocalAddress("fe80::1%12"));

    [Fact]
    public void BracketedIPv6IsAccepted() =>
        Assert.True(NetworkAddress.IsLoopbackAddress("[::1]"));

    [Theory]
    [InlineData("1.2.3.4", 1, 2, 3, 4)]
    [InlineData("1.2.3", 1, 2, 0, 3)]
    [InlineData("1.2", 1, 0, 0, 2)]
    [InlineData("16909060", 1, 2, 3, 4)]
    [InlineData("0x01020304", 1, 2, 3, 4)]
    public void AbbreviatedFormsExpandTheWayInetAtonDoes(string address, byte a, byte b, byte c, byte d)
    {
        Assert.True(NetworkAddress.TryParseIPv4(address, out var octets));
        Assert.Equal(new byte[] { a, b, c, d }, octets);
    }

    [Theory]
    [InlineData("1.2.3.4.5")]
    [InlineData("256.0.0.1")]
    [InlineData("1.2.3.256")]
    [InlineData("4294967296")]
    [InlineData("1..2")]
    [InlineData("1.2.3.")]
    [InlineData("0x")]
    [InlineData("09")]      // 9 is not an octal digit
    [InlineData("abc")]
    public void MalformedIPv4IsRejected(string address) =>
        Assert.False(NetworkAddress.TryParseIPv4(address, out _), address);

    [Fact]
    public void IPLiteralDetectionCoversBothFamilies()
    {
        Assert.True(NetworkAddress.IsIPLiteral("8.8.8.8"));
        Assert.True(NetworkAddress.IsIPLiteral("2001:db8::1"));
        Assert.False(NetworkAddress.IsIPLiteral("example.com"));
    }
}
