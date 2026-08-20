using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>Validation, sanitisation, and the promise that a stored configuration holds no secrets.</summary>
public sealed class ConfigurationTests
{
    private static AppIdentity Identity(string path) => new()
    {
        ExecutablePath = ExecutablePath.Normalize(path),
        DisplayName = ExecutablePath.FileName(path),
    };

    private static RuntimeConfiguration WithRules(params AppRule[] rules) => new() { Rules = rules };

    // ---- Validation ------------------------------------------------------------------------

    [Fact]
    public void ADefaultConfigurationIsValid() =>
        ConfigurationValidator.Validate(RuntimeConfiguration.Empty);

    [Fact]
    public void AnEmptyExecutablePathIsRejected()
    {
        var configuration = WithRules(new AppRule
        {
            Identity = new AppIdentity { ExecutablePath = "  ", DisplayName = "x" },
        });

        var error = Assert.Throws<ConfigurationValidationException>(
            () => ConfigurationValidator.Validate(configuration));

        Assert.Equal(ConfigurationValidationCode.EmptyExecutablePath, error.Code);
    }

    [Fact]
    public void ARelativePathIsRejected()
    {
        var configuration = WithRules(new AppRule
        {
            Identity = new AppIdentity { ExecutablePath = @"App\App.exe", DisplayName = "x" },
        });

        var error = Assert.Throws<ConfigurationValidationException>(
            () => ConfigurationValidator.Validate(configuration));

        Assert.Equal(ConfigurationValidationCode.RelativeExecutablePath, error.Code);
    }

    [Fact]
    public void DuplicateRulesAreRejectedRatherThanHalfApplied()
    {
        var configuration = WithRules(
            new AppRule { Identity = Identity(@"C:\App\App.exe") },
            new AppRule { Identity = Identity(@"c:\app\APP.EXE") });

        var error = Assert.Throws<ConfigurationValidationException>(
            () => ConfigurationValidator.Validate(configuration));

        Assert.Equal(ConfigurationValidationCode.DuplicateExecutablePath, error.Code);
    }

    [Fact]
    public void ANewerSchemaVersionIsRefusedRatherThanGuessedAt()
    {
        var configuration = RuntimeConfiguration.Empty with
        {
            Version = new ConfigurationVersion(ConfigurationVersion.CurrentSchema + 1, 0),
        };

        var error = Assert.Throws<ConfigurationValidationException>(
            () => ConfigurationValidator.Validate(configuration));

        Assert.Equal(ConfigurationValidationCode.UnsupportedSchemaVersion, error.Code);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AnEmptyProxyHostIsRejected(string host)
    {
        var proxy = ProxyConfiguration.Default with { Endpoint = new ProxyEndpoint { Host = host, Port = 1080 } };

        var error = Assert.Throws<ConfigurationValidationException>(() => ConfigurationValidator.Validate(proxy));

        Assert.Equal(ConfigurationValidationCode.EmptyProxyHost, error.Code);
    }

    [Fact]
    public void AZeroProxyPortIsRejected()
    {
        var proxy = ProxyConfiguration.Default with
        {
            Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = 0 },
        };

        var error = Assert.Throws<ConfigurationValidationException>(() => ConfigurationValidator.Validate(proxy));

        Assert.Equal(ConfigurationValidationCode.InvalidProxyPort, error.Code);
    }

    [Fact]
    public void ANonPositiveTimeoutIsRejected()
    {
        var proxy = ProxyConfiguration.Default with { HandshakeTimeoutMilliseconds = 0 };

        var error = Assert.Throws<ConfigurationValidationException>(() => ConfigurationValidator.Validate(proxy));

        Assert.Equal(ConfigurationValidationCode.NonPositiveTimeout, error.Code);
    }

    [Fact]
    public void AuthenticationWithNoUsernameIsRejected()
    {
        var proxy = ProxyConfiguration.Default with { Credential = new CredentialReference { Username = "" } };

        var error = Assert.Throws<ConfigurationValidationException>(() => ConfigurationValidator.Validate(proxy));

        Assert.Equal(ConfigurationValidationCode.EmptyUsername, error.Code);
    }

    [Fact]
    public void ARedirectPortEqualToTheUpstreamPortIsRejected()
    {
        var configuration = RuntimeConfiguration.Empty with { RedirectPort = 10808 };

        var error = Assert.Throws<ConfigurationValidationException>(
            () => ConfigurationValidator.Validate(configuration));

        Assert.Equal(ConfigurationValidationCode.RedirectPortCollision, error.Code);
    }

    [Fact]
    public void ARedirectPortMatchingARemoteProxyPortIsFine()
    {
        // Only a loopback upstream can actually collide with a loopback listener.
        var configuration = RuntimeConfiguration.Empty with
        {
            RedirectPort = 1080,
            Proxy = ProxyConfiguration.Default with
            {
                Endpoint = new ProxyEndpoint { Host = "proxy.example.com", Port = 1080 },
            },
        };

        ConfigurationValidator.Validate(configuration);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("proxy.example.com")]
    [InlineData("my_proxy")]
    [InlineData("a-b.example")]
    public void PlausibleHostsAreAccepted(string host) =>
        Assert.True(ConfigurationValidator.IsPlausibleHost(host), host);

    [Theory]
    [InlineData(".example.com")]
    [InlineData("example.com.")]
    [InlineData("-bad.example")]
    [InlineData("bad-.example")]
    [InlineData("a..b")]
    [InlineData("has space")]
    public void ImplausibleHostsAreRejected(string host) =>
        Assert.False(ConfigurationValidator.IsPlausibleHost(host), host);

    // ---- Sanitisation ----------------------------------------------------------------------

    [Fact]
    public void SanitiseDowngradesUnsafeFamilyMatchingInsteadOfFailingTheLoad()
    {
        var configuration = WithRules(new AppRule
        {
            Identity = Identity(@"C:\Windows\System32\curl.exe"),
            MatchMode = MatchMode.ExecutableFamily,
        });

        var sanitised = ConfigurationValidator.Sanitize(configuration);

        Assert.Equal(MatchMode.Exact, sanitised.Rules[0].MatchMode);
    }

    [Fact]
    public void SanitiseKeepsSafeFamilyMatching()
    {
        var configuration = WithRules(new AppRule
        {
            Identity = Identity(@"C:\Program Files\Codex\Codex.exe"),
            MatchMode = MatchMode.ExecutableFamily,
        });

        Assert.Equal(MatchMode.ExecutableFamily, ConfigurationValidator.Sanitize(configuration).Rules[0].MatchMode);
    }

    [Fact]
    public void SanitiseDropsUnusableRulesAndDeduplicates()
    {
        var configuration = WithRules(
            new AppRule { Identity = new AppIdentity { ExecutablePath = "", DisplayName = "empty" } },
            new AppRule { Identity = new AppIdentity { ExecutablePath = @"relative\x.exe", DisplayName = "rel" } },
            new AppRule { Identity = Identity(@"C:\App\App.exe") },
            new AppRule { Identity = Identity(@"C:\APP\app.EXE") });

        var sanitised = ConfigurationValidator.Sanitize(configuration);

        Assert.Single(sanitised.Rules);
        ConfigurationValidator.Validate(sanitised);
    }

    [Fact]
    public void SanitiseNormalisesPathsSoLaterComparisonsAreExact()
    {
        var configuration = WithRules(new AppRule
        {
            Identity = new AppIdentity { ExecutablePath = @"C:/Program Files//Codex/Codex.exe", DisplayName = "Codex" },
        });

        Assert.Equal(@"C:\Program Files\Codex\Codex.exe", ConfigurationValidator.Sanitize(configuration).Rules[0].Id);
    }

    // ---- Round-tripping --------------------------------------------------------------------

    [Fact]
    public void ConfigurationRoundTripsThroughJson()
    {
        var original = new RuntimeConfiguration
        {
            Version = new ConfigurationVersion(1, 42),
            Rules =
            [
                new AppRule
                {
                    Identity = Identity(@"C:\Program Files\Codex\Codex.exe") with
                    {
                        Publisher = "OpenAI, Inc.",
                        FileDescription = "Codex",
                    },
                    Action = RouteAction.Proxy,
                    MatchMode = MatchMode.ExecutableFamily,
                    Note = "work",
                },
            ],
            Proxy = ProxyConfiguration.Default with
            {
                Credential = new CredentialReference { Username = "user", SecretKey = "splitlane/proxy" },
            },
            LogsDirectFlows = true,
            RedirectPort = 24444,
        };

        var decoded = ConfigurationCodec.DecodeFromJson(ConfigurationCodec.EncodeToJson(original));

        Assert.Equal(original.Version, decoded.Version);
        Assert.Equal(original.RedirectPort, decoded.RedirectPort);
        Assert.Equal(original.Rules[0].Id, decoded.Rules[0].Id);
        Assert.Equal("OpenAI, Inc.", decoded.Rules[0].Identity.Publisher);
        Assert.Equal(MatchMode.ExecutableFamily, decoded.Rules[0].MatchMode);
        Assert.Equal("user", decoded.Proxy.Credential!.Username);
    }

    [Fact]
    public void EnumsAreStoredAsNamesSoInsertingAMemberCannotReinterpretStoredRules()
    {
        var json = ConfigurationCodec.EncodeToJson(WithRules(new AppRule
        {
            Identity = Identity(@"C:\App\App.exe"),
            Action = RouteAction.Block,
        }));

        Assert.Contains("\"Block\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"action\": 2", json, StringComparison.Ordinal);
    }

    [Fact]
    public void EncodedConfigurationNeverContainsSecrets()
    {
        // The property this test defends is structural: there is no field on ProxyConfiguration that
        // could hold a password, only a locator. If someone adds one, this goes red.
        var configuration = RuntimeConfiguration.Empty with
        {
            Proxy = ProxyConfiguration.Default with
            {
                Credential = new CredentialReference { Username = "user", SecretKey = "splitlane/proxy" },
            },
        };

        var json = ConfigurationCodec.EncodeToJson(configuration);

        Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret\"", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secretKey", json, StringComparison.Ordinal);
    }

    [Fact]
    public void DecodingAConfigurationFromANewerSchemaFailsWithAClearCode()
    {
        var json = """{"version":{"schemaVersion":99,"generation":1},"rules":[]}""";

        var error = Assert.Throws<ConfigurationValidationException>(() => ConfigurationCodec.DecodeFromJson(json));

        Assert.Equal(ConfigurationValidationCode.UnsupportedSchemaVersion, error.Code);
    }

    // ---- Version arithmetic ------------------------------------------------------------------

    [Fact]
    public void GenerationAdvancesAndRestampsTheSchema()
    {
        var version = new ConfigurationVersion(1, 7).NextGeneration();

        Assert.Equal(8UL, version.Generation);
        Assert.Equal(ConfigurationVersion.CurrentSchema, version.SchemaVersion);
    }

    [Fact]
    public void VersionsOrderBySchemaThenGeneration()
    {
        Assert.True(new ConfigurationVersion(1, 1).CompareTo(new ConfigurationVersion(1, 2)) < 0);
        Assert.True(new ConfigurationVersion(1, 99).CompareTo(new ConfigurationVersion(2, 0)) < 0);
    }

    // ---- Derived properties -------------------------------------------------------------------

    [Fact]
    public void PlaintextExposureIsOnlyReportedForRemoteProxies()
    {
        var credential = new CredentialReference { Username = "user" };

        var local = ProxyConfiguration.Default with { Credential = credential };
        var remote = ProxyConfiguration.Default with
        {
            Credential = credential,
            Endpoint = new ProxyEndpoint { Host = "proxy.example.com", Port = 1080 },
        };

        Assert.False(local.HasPlaintextCredentialExposure);
        Assert.True(remote.HasPlaintextCredentialExposure);
    }

    [Fact]
    public void FallbackToDirectIsOffByDefaultBecauseSilentFallbackIsALeak() =>
        Assert.False(ProxyConfiguration.Default.AllowDirectFallback);
}
