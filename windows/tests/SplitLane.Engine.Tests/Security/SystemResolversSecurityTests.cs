using System.Net;
using SplitLane.Engine.Net;

namespace SplitLane.Engine.Tests.Security;

[Trait("Category", "Security")]
public sealed class SystemResolversSecurityTests
{
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("::1")]
    [InlineData("fe80::1%7")]
    public void Resolver_addresses_match_packet_address_bytes_without_scope(string text)
    {
        var address = IPAddress.Parse(text);
        Assert.Equal(new IPAddress(address.GetAddressBytes()), SystemResolvers.WithoutScope(address));
    }

    [Fact]
    public void Configured_IPv4_resolvers_do_not_break_the_resolver_trust_boundary()
    {
        // The real Windows API supplies IPv4 entries on ordinary adapters. Reading ScopeId from
        // any of them used to poison the type initializer permanently, including for loopback DNS.
        var error = Record.Exception(() => SystemResolvers.Contains(IPAddress.Loopback));
        Assert.Null(error);
    }
}
