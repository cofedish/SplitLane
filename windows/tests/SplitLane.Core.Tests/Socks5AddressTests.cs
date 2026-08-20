using System.Text;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Core.Tests;

/// <summary>Address encoding, and the hostname-over-IP preference that makes CDNs behave.</summary>
public sealed class Socks5AddressTests
{
    [Fact]
    public void IPv4LiteralEncodesAsFourRawOctets()
    {
        var address = Socks5Address.Destination(null, "93.184.216.34");

        Assert.Equal(Socks5AddressType.IPv4, address.Type);
        Assert.Equal([(byte)Socks5AddressType.IPv4, 93, 184, 216, 34], address.Encode());
    }

    [Fact]
    public void IPv6LiteralEncodesAsSixteenRawOctets()
    {
        var address = Socks5Address.Destination(null, "2001:db8::1");

        Assert.Equal(Socks5AddressType.IPv6, address.Type);
        Assert.Equal(17, address.Encode().Length);
    }

    [Fact]
    public void HostnameEncodesLengthPrefixed()
    {
        var address = Socks5Address.Destination("example.com", "93.184.216.34");

        Assert.Equal(Socks5AddressType.Domain, address.Type);

        var expected = new List<byte> { (byte)Socks5AddressType.Domain, 11 };
        expected.AddRange(Encoding.UTF8.GetBytes("example.com"));
        Assert.Equal(expected, address.Encode());
    }

    [Fact]
    public void AHostnameIsPreferredOverAnAddressSoTheUpstreamResolvesIt()
    {
        var address = Socks5Address.Destination("cdn.example.com", "1.2.3.4");

        Assert.Equal(Socks5AddressType.Domain, address.Type);
        Assert.Equal("cdn.example.com", address.Domain);
    }

    [Fact]
    public void AHostnameThatIsActuallyAnIPLiteralIsEmittedAsOne()
    {
        // ATYP=DOMAIN carrying "93.184.216.34" would make the server do a pointless lookup.
        var address = Socks5Address.Destination("93.184.216.34", null);

        Assert.Equal(Socks5AddressType.IPv4, address.Type);
    }

    [Fact]
    public void AnAddressIsUsedWhenNoHostnameIsKnown()
    {
        var address = Socks5Address.Destination(null, "8.8.8.8");

        Assert.Equal(Socks5AddressType.IPv4, address.Type);
    }

    [Fact]
    public void NeitherHostnameNorAddressIsAnError()
    {
        var error = Assert.Throws<Socks5Exception>(() => Socks5Address.Destination(null, null));

        Assert.Equal(Socks5ErrorCode.InvalidDestinationAddress, error.Code);
    }

    [Fact]
    public void AnUnparseableAddressWithNoHostnameIsAnError()
    {
        var error = Assert.Throws<Socks5Exception>(() => Socks5Address.Destination(null, "not-an-address"));

        Assert.Equal(Socks5ErrorCode.InvalidDestinationAddress, error.Code);
    }

    [Fact]
    public void AHostnameLongerThanOneLengthByteIsRefused()
    {
        var name = string.Join('.', Enumerable.Repeat("abcdefghij", 30));

        var error = Assert.Throws<Socks5Exception>(() => Socks5Address.Destination(name, null));

        Assert.Equal(Socks5ErrorCode.DomainNameTooLong, error.Code);
    }

    [Fact]
    public void AHostnameOfExactlyTwoHundredAndFiftyFiveBytesIsAccepted()
    {
        var name = new string('a', 255);

        Assert.Equal(Socks5AddressType.Domain, Socks5Address.FromDomain(name).Type);
    }

    [Fact]
    public void AMultiByteHostnameIsMeasuredInBytesNotCharacters()
    {
        // 200 characters, but 600 UTF-8 bytes.
        var name = new string('д', 200);

        Assert.Throws<Socks5Exception>(() => Socks5Address.FromDomain(name));
    }

    [Fact]
    public void DisplayFormRoundTripsForBothFamilies()
    {
        Assert.Equal("93.184.216.34", Socks5Address.Destination(null, "93.184.216.34").ToString());
        Assert.Equal("2001:db8::1", Socks5Address.Destination(null, "2001:db8::1").ToString());
        Assert.Equal("example.com", Socks5Address.FromDomain("example.com").ToString());
    }

    [Fact]
    public void EqualityIsByValue()
    {
        Assert.Equal(Socks5Address.FromDomain("a.example"), Socks5Address.FromDomain("a.example"));
        Assert.NotEqual(Socks5Address.FromDomain("a.example"), Socks5Address.FromDomain("b.example"));
        Assert.Equal(
            Socks5Address.Destination(null, "1.2.3.4"),
            Socks5Address.Destination(null, "1.2.3.4"));
    }

    [Fact]
    public void WrongLengthLiteralsAreRefused()
    {
        Assert.Throws<Socks5Exception>(() => Socks5Address.FromIPv4([1, 2, 3]));
        Assert.Throws<Socks5Exception>(() => Socks5Address.FromIPv6([1, 2, 3]));
    }
}
