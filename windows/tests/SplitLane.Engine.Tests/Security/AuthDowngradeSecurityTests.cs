using System.Security.Principal;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Http;
using SplitLane.Core.Proxy.Socks5;
using SplitLane.Engine.Relay;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-011: the strongest scheme the proxy offers is used; the password goes out with Basic to a
/// proxy elsewhere only by the user's explicit choice; and after NTLM or Negotiate has worked, an offer
/// of Basic alone is refused as a downgrade.
/// </summary>
[Trait("Category", "Security")]
public sealed class AuthDowngradeSecurityTests
{
    private static ProxyConfiguration Remote => new()
    {
        Type = ProxyProtocolType.Http,
        Endpoint = new ProxyEndpoint { Host = "proxy.corp.example", Port = 3128 },
        Credential = new CredentialReference { Username = "alice" },
    };

    private static ProxyConfiguration Local => Remote with { Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = 3128 } };

    private static Socks5Credential Credential(bool allowBasic = false) => new("alice", "secret") { AllowPlaintextBasic = allowBasic };

    [Theory]
    [InlineData(new[] { "Basic", "NTLM", "Negotiate" }, "Negotiate")]
    [InlineData(new[] { "Basic", "NTLM" }, "NTLM")]
    [InlineData(new[] { "Basic" }, "Basic")]
    [InlineData(new[] { "Digest" }, null)]
    public void The_strongest_offered_scheme_is_chosen(string[] offered, string? expected)
    {
        var challenges = ProxyAuthenticationChallenge.Parse(offered);
        Assert.Equal(expected, HttpProxyAuthentication.Choose(challenges));
    }

    [Fact]
    public void Basic_to_a_proxy_elsewhere_needs_the_users_explicit_choice()
    {
        Assert.NotNull(HttpProxyAuthentication.BasicRefusal("Basic", Remote, Credential(), strongestAccepted: null));
        Assert.Null(HttpProxyAuthentication.BasicRefusal("Basic", Remote, Credential(allowBasic: true), strongestAccepted: null));
    }

    [Fact]
    public void Basic_to_a_proxy_on_this_machine_is_allowed()
    {
        Assert.Null(HttpProxyAuthentication.BasicRefusal("Basic", Local, Credential(), strongestAccepted: null));
    }

    [Theory]
    [InlineData("NTLM")]
    [InlineData("Negotiate")]
    public void Basic_after_a_stronger_scheme_worked_is_a_downgrade_and_refused_even_when_allowed(string strongest)
    {
        Assert.NotNull(HttpProxyAuthentication.BasicRefusal("Basic", Remote, Credential(allowBasic: true), strongest));
        Assert.NotNull(HttpProxyAuthentication.BasicRefusal("Basic", Local, Credential(), strongest));
    }

    [Fact]
    public void Falling_back_from_Negotiate_to_NTLM_is_not_a_downgrade_to_plaintext()
    {
        Assert.Null(HttpProxyAuthentication.BasicRefusal("NTLM", Remote, Credential(), "Negotiate"));
    }

    [Fact]
    public void The_strongest_scheme_accepted_survives_a_refusal_and_is_never_lowered()
    {
        var memory = new HttpAuthenticationMemory();
        var credential = Credential();

        memory.Remember(Remote, credential, "NTLM");
        memory.Forget(Remote, credential);
        memory.Remember(Remote, credential, "Basic");

        Assert.Equal("NTLM", memory.StrongestAccepted(Remote, credential));
    }

    [Fact]
    public void A_refusal_never_contains_the_password()
    {
        var refusal = HttpProxyAuthentication.BasicRefusal("Basic", Remote, Credential(), null)!;
        Assert.DoesNotContain("secret", refusal, StringComparison.Ordinal);
    }

    [Fact]
    public void The_users_choice_is_stored_with_the_password_and_comes_back_with_it()
    {
        var root = Path.Combine(Path.GetTempPath(), "sl-sec011-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new ProxyCredentialStore(new ProtectedDirectory(
                Path.Combine(root, "Secrets"), UserAccess.None, [WindowsIdentity.GetCurrent().User!], checkAncestry: false));

            store.Save(ProxyCredentialBinding.For(Remote)!, "secret");
            Assert.False(store.Resolve(Remote)!.AllowPlaintextBasic);

            store.Save(ProxyCredentialBinding.For(Remote)!, "secret", allowPlaintextBasic: true);
            Assert.True(store.Resolve(Remote)!.AllowPlaintextBasic);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
