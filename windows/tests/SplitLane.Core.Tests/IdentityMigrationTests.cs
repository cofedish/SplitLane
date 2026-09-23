using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Tests;

/// <summary>
/// Schema 1 path rules becoming identity rules, and the one thing migration must never do: hand a
/// rule to a different application.
/// </summary>
/// <remarks>
/// The configuration under test is the one found on the development machine, byte for byte apart from
/// the user name: three Codex rules written by a schema 1 picker, two of which name hash directories
/// the Codex updater has since deleted.
/// </remarks>
public sealed class IdentityMigrationTests
{
    private const string OpenAiSubject =
        "CN=\"OpenAI OpCo, LLC\", O=\"OpenAI OpCo, LLC\", L=San Francisco, S=California, C=US";

    private const string Codex = @"C:\Users\alice\AppData\Local\OpenAI\Codex";

    private const string SchemaOneDocument = """
        {
          "version": { "schemaVersion": 1, "generation": 35 },
          "rules": [
            {
              "identity": {
                "executablePath": "C:\\Program Files\\WindowsApps\\OpenAI.Codex_26.915.4065.0_x64__2p2nqsd0c76g0\\app\\ChatGPT.exe",
                "displayName": "Codex",
                "publisher": "OpenAI OpCo",
                "fileDescription": "Codex",
                "capturedAt": "2026-09-19T08:10:47.8659512+00:00"
              },
              "action": "Proxy",
              "matchMode": "PackageFamily",
              "isEnabled": true
            },
            {
              "identity": {
                "executablePath": "C:\\Users\\alice\\AppData\\Local\\OpenAI\\Codex\\bin\\247581e40ee272fb\\codex.exe",
                "displayName": "codex",
                "publisher": "OpenAI OpCo",
                "capturedAt": "2026-09-19T08:10:52.9937469+00:00"
              },
              "action": "Proxy",
              "matchMode": "ExecutableFamily",
              "isEnabled": true
            },
            {
              "identity": {
                "executablePath": "C:\\Users\\alice\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node\\df473e5367fa2b42\\bin\\node_modules\\@oai\\sky\\bin\\windows\\swift\\x64\\codex-computer-use-swift.exe",
                "displayName": "codex-computer-use-swift",
                "publisher": "OpenAI OpCo",
                "capturedAt": "2026-09-19T08:10:56.9630126+00:00"
              },
              "action": "Proxy",
              "matchMode": "ExecutableFamily",
              "isEnabled": true
            }
          ],
          "proxy": {
            "id": "d275f7d8-86ef-4330-b7ab-277a6b74e577",
            "displayName": "Local SOCKS5",
            "type": "Socks5",
            "endpoint": { "host": "127.0.0.1", "port": 10808 },
            "isEnabled": true,
            "handshakeTimeoutMilliseconds": 10000,
            "allowDirectFallback": false,
            "preferHostnames": true
          },
          "isRoutingEnabled": true,
          "logsDirectFlows": true,
          "proxiesUdp": true,
          "redirectPort": 0
        }
        """;

    /// <summary>A disk that holds exactly the files a test puts on it.</summary>
    private sealed class FakeDisk : IImageInspector
    {
        private readonly Dictionary<string, ImageEvidence> _files = new(ExecutablePath.Comparer);

        public List<string> Inspected { get; } = [];

        public FakeDisk Signed(string path, string subject = OpenAiSubject, string? product = null)
        {
            _files[ExecutablePath.Normalize(path)] = new ImageEvidence
            {
                ExecutablePath = ExecutablePath.Normalize(path),
                Signature = SignatureStatus.Valid,
                SignerSubject = PublisherName.Canonical(subject),
                SignerName = PublisherName.Parse(subject)[0].Value,
                ProductName = product,
                HasVersionInfo = true,
                FileSize = 1000,
            };
            return this;
        }

        public FakeDisk Unsigned(string path, string sha256)
        {
            _files[ExecutablePath.Normalize(path)] = new ImageEvidence
            {
                ExecutablePath = ExecutablePath.Normalize(path),
                Signature = SignatureStatus.Unsigned,
                HasVersionInfo = true,
                FileSize = 2000,
                Sha256 = sha256,
            };
            return this;
        }

        public FakeDisk Invalid(string path)
        {
            _files[ExecutablePath.Normalize(path)] = new ImageEvidence
            {
                ExecutablePath = ExecutablePath.Normalize(path),
                Signature = SignatureStatus.Invalid,
            };
            return this;
        }

        public ImageEvidence? Inspect(string executablePath, bool computeSha256)
        {
            Inspected.Add(executablePath);
            return _files.GetValueOrDefault(ExecutablePath.Normalize(executablePath));
        }

        public IReadOnlyList<string> ChildDirectories(string directory)
        {
            var prefix = ExecutablePath.Normalize(directory) + @"\";
            return [.. _files.Keys
                .Where(path => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .Select(path => prefix + path[prefix.Length..].Split('\\')[0])
                .Distinct(StringComparer.OrdinalIgnoreCase)];
        }
    }

    private static AppRule PathRule(string path, string? publisher = "OpenAI OpCo", MatchMode mode = MatchMode.ExecutableFamily) => new()
    {
        Identity = new AppIdentity
        {
            ExecutablePath = ExecutablePath.Normalize(path),
            DisplayName = ExecutablePath.FileName(path),
            Publisher = publisher,
        },
        MatchMode = mode,
    };

    private static MigrationResult Migrate(FakeDisk disk, params AppRule[] rules) =>
        ConfigurationMigrator.Migrate(new RuntimeConfiguration
        {
            Version = new ConfigurationVersion(ConfigurationVersion.PathSchema, 7),
            Rules = rules,
        }, disk);

    // ---- The old format -------------------------------------------------------------------------

    [Fact]
    public void ASchemaOneDocumentStillDecodes()
    {
        var configuration = ConfigurationCodec.DecodeFromJson(SchemaOneDocument);

        Assert.Equal(1, configuration.Version.SchemaVersion);
        Assert.Equal(3, configuration.Rules.Count);
        Assert.All(configuration.Rules, rule => Assert.Equal(IdentityKind.Path, rule.Identity.Kind));
        Assert.All(configuration.Rules, rule => Assert.Equal(RuleStatus.Active, rule.Status));
        Assert.True(ConfigurationMigrator.NeedsMigration(configuration));
    }

    [Fact]
    public void TheRealConfigurationMigratesAndTheUpdatedCodexIsRoutedAgain()
    {
        var disk = new FakeDisk()
            .Signed($@"{Codex}\bin\d375f7df50d3b421\codex.exe")
            .Signed($@"{Codex}\bin\d375f7df50d3b421\codex-code-mode-host.exe")
            .Signed($@"{Codex}\runtimes\cua_node\f53823cd54b14f45\bin\node_modules\@oai\sky\bin\windows\swift\x64\codex-computer-use-swift.exe");

        var legacy = ConfigurationValidator.Sanitize(ConfigurationCodec.DecodeFromJson(SchemaOneDocument));
        var result = ConfigurationMigrator.Migrate(legacy, disk);
        var rules = result.Configuration.Rules;

        Assert.Equal(ConfigurationVersion.CurrentSchema, result.Configuration.Version.SchemaVersion);
        Assert.Equal(35UL, result.Configuration.Version.Generation);

        Assert.Equal(IdentityKind.Package, rules[0].Identity.Kind);
        Assert.Equal(MigrationOutcome.Verified, result.Rules[0].Outcome);

        Assert.Equal(IdentityKind.Signed, rules[1].Identity.Kind);
        Assert.Equal(MigrationOutcome.Reanchored, result.Rules[1].Outcome);
        Assert.Equal(ExecutablePath.Normalize($@"{Codex}\bin\d375f7df50d3b421\codex.exe"), rules[1].Identity.ExecutablePath);
        Assert.Contains("247581e40ee272fb", rules[1].StatusDetail);

        Assert.Equal(MigrationOutcome.Reanchored, result.Rules[2].Outcome);

        var engine = new RuleEngine(result.Configuration);
        var running = new ImageEvidence
        {
            ExecutablePath = $@"{Codex}\bin\d375f7df50d3b421\codex.exe",
            Signature = SignatureStatus.Valid,
            SignerSubject = PublisherName.Canonical(OpenAiSubject),
            HasVersionInfo = true,
        };

        var decision = engine.Decide(new FlowDescriptor(
            1, running.ExecutablePath, "93.184.216.34", 443, FlowProtocol.Tcp, Image: running));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void TheSchemaOnePublisherIsComparedTheWayItWasWritten()
    {
        // Schema 1 split the subject on commas without honouring quotes. "OpenAI OpCo" is what it
        // stored for CN="OpenAI OpCo, LLC", and it must be recognised as that and nothing looser.
        Assert.True(PublisherName.MatchesLegacyPublisher("OpenAI OpCo", "OpenAI OpCo, LLC"));
        Assert.True(PublisherName.MatchesLegacyPublisher("Contoso Ltd", "Contoso Ltd"));
        Assert.False(PublisherName.MatchesLegacyPublisher("OpenAI", "OpenAI OpCo, LLC"));
        Assert.False(PublisherName.MatchesLegacyPublisher("OpenAI OpCo", "OpenAI OpCo Evil, LLC"));
        Assert.False(PublisherName.MatchesLegacyPublisher(null, "OpenAI OpCo, LLC"));
    }

    // ---- Migrated, or explicitly waiting: never reassigned ----------------------------------------

    [Fact]
    public void ASignedFileWhereTheRuleSaysIsMigratedToItsIdentity()
    {
        var disk = new FakeDisk().Signed(@"C:\Program Files\Contoso\app.exe",
            "CN=Contoso Ltd, O=Contoso Ltd, L=Redmond, S=Washington, C=US", "Contoso App");

        var result = Migrate(disk, PathRule(@"C:\Program Files\Contoso\app.exe", "Contoso Ltd"));
        var identity = result.Configuration.Rules[0].Identity;

        Assert.Equal(MigrationOutcome.Verified, result.Rules[0].Outcome);
        Assert.Equal(IdentityKind.Signed, identity.Kind);
        Assert.Equal("CN=CONTOSO LTD;O=CONTOSO LTD;L=REDMOND;S=WASHINGTON;C=US", identity.SignerSubject);
        Assert.Equal("Contoso App", identity.ProductName);
        Assert.Equal("app.exe", identity.BinaryName);
    }

    [Fact]
    public void AMissingFileWithNoNewerBuildIsMarkedForReselectionAndRoutesNothing()
    {
        var result = Migrate(new FakeDisk(), PathRule($@"{Codex}\bin\247581e40ee272fb\codex.exe"));
        var rule = result.Configuration.Rules[0];

        Assert.Equal(MigrationOutcome.NeedsReselection, result.Rules[0].Outcome);
        Assert.Equal(RuleStatus.NeedsReselection, rule.Status);
        Assert.False(string.IsNullOrWhiteSpace(rule.StatusDetail));

        var engine = new RuleEngine(result.Configuration);
        Assert.Equal(0, engine.Snapshot.ActiveRuleCount);
    }

    [Fact]
    public void ANewerBuildSignedBySomebodyElseIsNotAdopted()
    {
        var disk = new FakeDisk().Signed($@"{Codex}\bin\d375f7df50d3b421\codex.exe",
            "CN=Mallory Software, O=Mallory Software, C=US");

        var result = Migrate(disk, PathRule($@"{Codex}\bin\247581e40ee272fb\codex.exe"));

        Assert.Equal(MigrationOutcome.NeedsReselection, result.Rules[0].Outcome);
    }

    [Fact]
    public void AnUnsignedFileInTheNewBuildsPlaceIsNotAdopted()
    {
        var disk = new FakeDisk().Unsigned($@"{Codex}\bin\d375f7df50d3b421\codex.exe", "ab");

        var result = Migrate(disk, PathRule($@"{Codex}\bin\247581e40ee272fb\codex.exe"));

        Assert.Equal(MigrationOutcome.NeedsReselection, result.Rules[0].Outcome);
    }

    [Fact]
    public void AMissingFileWithNoRecordedPublisherCannotBeReanchored()
    {
        var disk = new FakeDisk().Signed($@"{Codex}\bin\d375f7df50d3b421\codex.exe");

        var result = Migrate(disk, PathRule($@"{Codex}\bin\247581e40ee272fb\codex.exe", publisher: null));

        Assert.Equal(MigrationOutcome.NeedsReselection, result.Rules[0].Outcome);
    }

    [Fact]
    public void CandidatesThatDisagreeAboutWhatTheyAreAreNotChosenBetween()
    {
        var disk = new FakeDisk()
            .Signed($@"{Codex}\bin\d375f7df50d3b421\codex.exe", product: "Codex CLI")
            .Signed($@"{Codex}\bin\681770561a4656a5\codex.exe", product: "Something Else");

        var result = Migrate(disk, PathRule($@"{Codex}\bin\247581e40ee272fb\codex.exe"));

        Assert.Equal(MigrationOutcome.NeedsReselection, result.Rules[0].Outcome);
    }

    [Fact]
    public void AFileNowSignedByAnotherPublisherIsMarkedForReselection()
    {
        var disk = new FakeDisk().Signed(@"C:\Tools\app.exe", "CN=Somebody Else, O=Somebody Else, C=US");

        var result = Migrate(disk, PathRule(@"C:\Tools\app.exe", "Contoso Ltd"));

        Assert.Equal(MigrationOutcome.NeedsReselection, result.Rules[0].Outcome);
        Assert.Contains("Somebody Else", result.Configuration.Rules[0].StatusDetail);
    }

    [Fact]
    public void ASignedFileWhereTheRuleRecordedNoPublisherIsNotAdopted()
    {
        // Found in review. Schema 1 recorded no publisher for an unsigned program - or for one signed
        // only through a catalog, which it could not read. A signed file there now may be a different
        // application altogether, and adopting it would let the family scope follow that one.
        var disk = new FakeDisk().Signed(@"C:\Tools\notes.exe", "CN=Unrelated Vendor, O=Unrelated Vendor, C=US", "Vendor Suite");

        var result = Migrate(disk, PathRule(@"C:\Tools\notes.exe", publisher: null));

        Assert.Equal(MigrationOutcome.NeedsReselection, result.Rules[0].Outcome);
        Assert.Equal(RuleStatus.NeedsReselection, result.Configuration.Rules[0].Status);
        Assert.Contains("Unrelated Vendor", result.Configuration.Rules[0].StatusDetail);
    }

    [Fact]
    public void AFileThatWasSignedAndIsNowUnsignedIsMarkedForReselection()
    {
        var disk = new FakeDisk().Unsigned(@"C:\Tools\app.exe", "ab");

        var result = Migrate(disk, PathRule(@"C:\Tools\app.exe", "Contoso Ltd"));

        Assert.Equal(MigrationOutcome.NeedsReselection, result.Rules[0].Outcome);
    }

    [Fact]
    public void AnInvalidSignatureIsMarkedForReselection()
    {
        var disk = new FakeDisk().Invalid(@"C:\Tools\app.exe");

        var result = Migrate(disk, PathRule(@"C:\Tools\app.exe", "Contoso Ltd"));

        Assert.Equal(MigrationOutcome.NeedsReselection, result.Rules[0].Outcome);
    }

    [Fact]
    public void AnUnsignedApplicationIsPinnedToItsBytesAndLosesItsFamilyVisibly()
    {
        var disk = new FakeDisk().Unsigned(@"C:\Tools\App\tool.exe", "0123abcd");

        var result = Migrate(disk, PathRule(@"C:\Tools\App\tool.exe", publisher: null));
        var rule = result.Configuration.Rules[0];

        Assert.Equal(MigrationOutcome.Narrowed, result.Rules[0].Outcome);
        Assert.Equal(IdentityKind.Unsigned, rule.Identity.Kind);
        Assert.Equal("0123abcd", rule.Identity.FileSha256);
        Assert.Equal(MatchMode.Exact, rule.MatchMode);
        Assert.Contains("not signed", rule.StatusDetail);
    }

    [Fact]
    public void RulesThatAlreadyHaveAnIdentityAreLeftAlone()
    {
        var disk = new FakeDisk();
        var identityRule = new AppRule
        {
            Identity = new AppIdentity
            {
                ExecutablePath = @"C:\Tools\app.exe",
                DisplayName = "app",
                Kind = IdentityKind.Unsigned,
                FileSha256 = "ff",
            },
        };

        var result = Migrate(disk, identityRule);

        Assert.Equal(MigrationOutcome.Unchanged, result.Rules[0].Outcome);
        Assert.Empty(disk.Inspected);
        Assert.False(result.Changed);
    }

    [Fact]
    public void AMigratedConfigurationRoundTripsThroughTheCodec()
    {
        var disk = new FakeDisk().Signed($@"{Codex}\bin\d375f7df50d3b421\codex.exe");
        var result = Migrate(disk, PathRule($@"{Codex}\bin\247581e40ee272fb\codex.exe"));

        var decoded = ConfigurationCodec.DecodeFromJson(ConfigurationCodec.EncodeToJson(result.Configuration));

        Assert.Equal(result.Configuration.Rules[0].Identity.MatchKey, decoded.Rules[0].Identity.MatchKey);
        Assert.Equal(IdentityKind.Signed, decoded.Rules[0].Identity.Kind);
        Assert.Equal(2, decoded.Version.SchemaVersion);
    }

    [Fact]
    public void AnIncompleteStoredIdentityIsMarkedRatherThanTrusted()
    {
        var configuration = new RuntimeConfiguration
        {
            Rules =
            [
                new AppRule
                {
                    Identity = new AppIdentity
                    {
                        ExecutablePath = @"C:\Tools\app.exe",
                        DisplayName = "app",
                        Kind = IdentityKind.Signed,
                        BinaryName = "app.exe",
                    },
                },
            ],
        };

        var sanitized = ConfigurationValidator.Sanitize(configuration);

        Assert.Equal(RuleStatus.NeedsReselection, sanitized.Rules[0].Status);
        Assert.Equal(0, new RuleSnapshot(sanitized).ActiveRuleCount);
    }
}
