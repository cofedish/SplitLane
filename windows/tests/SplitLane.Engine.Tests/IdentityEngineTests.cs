using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Relay;
using SplitLane.Engine.Runtime;
using SplitLane.Platform;
using SplitLane.Testbed.Socks5;
using Xunit.Abstractions;

namespace SplitLane.Engine.Tests;

/// <summary>
/// Application identity in the engine, against real files and real processes.
/// </summary>
/// <remarks>
/// <para>
/// Everything here is real except the divert layer: the executables are copies of a Windows binary
/// signed through a system catalog, laid out the way a self-updating application lays itself out -
/// <c>Vendor\bin\&lt;hash&gt;\probe.exe</c> - and "updated" by copying into a new hash directory. The
/// process is started for real, resolved from its pid with the same calls the socket pump makes, its
/// signature verified with WinVerifyTrust, and the resulting decision relayed through a real SOCKS5
/// server.
/// </para>
/// <para>
/// What is not exercised is WinDivert attributing a live socket to that process; that needs an
/// elevated prompt and a loaded driver, and lives in <c>tools/verify-identity.ps1</c>.
/// </para>
/// </remarks>
public sealed class IdentityEngineTests : IDisposable
{
    private readonly string _root;
    private readonly ITestOutputHelper _output;
    private readonly List<Process> _processes = [];

    public IdentityEngineTests(ITestOutputHelper output)
    {
        _output = output;
        _root = Path.Combine(Path.GetTempPath(), "splitlane-identity-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_root);
    }

    /// <summary>A catalog-signed binary that stays running when asked to: ping.</summary>
    private static string SignedProbe => Path.Combine(Environment.SystemDirectory, "PING.EXE");

    /// <summary>An unsigned executable: the SOCKS5 testbed's apphost, built alongside the tests.</summary>
    private static string UnsignedProbe => Path.Combine(AppContext.BaseDirectory, "SplitLane.Testbed.Socks5.exe");

    private string Place(string source, string relative)
    {
        var destination = Path.Combine(_root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(source, destination, overwrite: true);
        return destination;
    }

    private Process Run(string executable)
    {
        var process = Process.Start(new ProcessStartInfo(executable, "-n 30 127.0.0.1")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
        })!;

        _processes.Add(process);
        return process;
    }

    private static AppRule RuleFor(string executable, MatchMode mode = MatchMode.ExecutableFamily)
    {
        var evidence = WindowsImageInspector.Read(executable, computeSha256: true)
            ?? throw new InvalidOperationException($"{executable} could not be read");

        return new AppRule
        {
            Identity = ConfigurationMigrator.IdentityFor(executable, "probe", evidence)
                ?? throw new InvalidOperationException($"{executable} has no usable identity"),
            MatchMode = mode,
        };
    }

    private static RuleEngine EngineWith(params AppRule[] rules) =>
        new(ConfigurationValidator.Sanitize(new RuntimeConfiguration { Rules = rules }));

    private static RouteDecision Decide(RuleEngine engine, ImageEvidence evidence, out AppRule? rule) =>
        engine.Decide(
            new FlowDescriptor(1, evidence.ExecutablePath, "93.184.216.34", 443, FlowProtocol.Tcp, Image: evidence),
            out rule);

    [Fact]
    public void ARealProcessFromAnUpdatedCopyIsHeldThenVerifiedThenProxied()
    {
        var picked = Place(SignedProbe, @"Vendor\bin\1a2b3c4d5e6f7a8b\probe.exe");
        var engine = EngineWith(RuleFor(picked));

        // The update: a new build in a new hash directory, the old one gone.
        var updated = Place(SignedProbe, @"Vendor\bin\9f8e7d6c5b4a3921\probe.exe");
        Directory.Delete(Path.GetDirectoryName(picked)!, recursive: true);
        using var process = Run(updated);

        var catalog = new ImageCatalog(workers: 1);
        var resolver = new ProcessResolver(images: catalog);
        var info = resolver.ResolveInfo((uint)process.Id);

        Assert.False(info.IsUnknown);
        Assert.Null(info.PackageFamilyName);
        Assert.EndsWith(@"9f8e7d6c5b4a3921\probe.exe", info.ExecutablePath, StringComparison.OrdinalIgnoreCase);

        var claim = catalog.EvidenceFor(info.Image!, info.PackageFamilyName, engine.Snapshot.NeedsProductName);
        var held = Decide(engine, claim, out _);

        Assert.Equal(RouteReasonKind.IdentityPending, held.Reason);
        Assert.Equal(RouteAction.Block, held.Action);

        var watch = Stopwatch.StartNew();
        var verified = catalog.VerifyNow(info.Image!, held.Needs);
        _output.WriteLine($"verified {info.ExecutablePath} in {watch.ElapsedMilliseconds} ms: {verified.SignerName}");

        var decision = Decide(engine, verified, out var rule);

        Assert.Equal(SignatureStatus.Valid, verified.Signature);
        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.SignedIdentityRule, decision.Reason);
        Assert.NotNull(rule);
    }

    [Fact]
    public async Task TheBackgroundWorkerCompletesAHeldImage()
    {
        var executable = Place(SignedProbe, @"Vendor\bin\1a2b3c4d5e6f7a8b\probe.exe");
        await using var catalog = new ImageCatalog(workers: 1);
        var record = catalog.Refresh(executable);
        var done = new TaskCompletionSource<ImageRecord>(TaskCreationOptions.RunContinuationsAsynchronously);
        catalog.Verified += verified => done.TrySetResult(verified);

        catalog.RequestVerification(record, EvidenceNeeds.Signature);
        catalog.RequestVerification(record, EvidenceNeeds.Signature);

        var completed = await done.Task.WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Same(record, completed);
        Assert.Equal(SignatureStatus.Valid, completed.Evidence.Signature);
        Assert.Equal(1, catalog.Verifications);
    }

    [Fact]
    public void AFileThatCannotBeReadIsDecidedRatherThanHeldForever()
    {
        // An unsigned rule pins a size; a file of that size cannot be opened for hashing.
        var engine = EngineWith(RuleFor(Place(UnsignedProbe, @"Tools\tool.exe")));
        var size = new FileInfo(UnsignedProbe).Length;
        var catalog = new ImageCatalog((_, _) => null, _ => new FileStamp(size, 1, 1, 1), workers: 1);
        var record = catalog.Refresh(@"C:\Locked\tool-copy.exe");

        var held = Decide(engine, catalog.EvidenceFor(record, null, false), out _);
        var afterwards = Decide(engine, catalog.VerifyNow(record, held.Needs), out _);

        Assert.Equal(RouteReasonKind.IdentityPending, held.Reason);
        Assert.NotEqual(RouteReasonKind.IdentityPending, afterwards.Reason);
        Assert.Equal(RouteAction.Direct, afterwards.Action);
    }

    [Fact]
    public async Task AVerificationThatThrowsStillReleasesWhatWasHeld()
    {
        await using var catalog = new ImageCatalog(
            (_, _) => throw new InvalidOperationException("simulated"), _ => new FileStamp(10, 1, 1, 1), workers: 1);
        var record = catalog.Refresh(@"C:\Somewhere\probe.exe");
        var done = new TaskCompletionSource<ImageRecord>(TaskCreationOptions.RunContinuationsAsynchronously);
        catalog.Verified += verified => done.TrySetResult(verified);

        catalog.RequestVerification(record, EvidenceNeeds.Signature);
        var completed = await done.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(SignatureStatus.Invalid, completed.Evidence.Signature);
    }

    [Fact]
    public void AnUnsignedExecutableWithTheSameNameInTheSameInstallIsNotTheApplication()
    {
        var picked = Place(SignedProbe, @"Vendor\bin\1a2b3c4d5e6f7a8b\probe.exe");
        var engine = EngineWith(RuleFor(picked));
        var impostor = Place(UnsignedProbe, @"Vendor\bin\77aa88bb99cc00dd\probe.exe");

        var catalog = new ImageCatalog(workers: 1);
        var record = catalog.Refresh(impostor);
        var verified = catalog.VerifyNow(record, EvidenceNeeds.Signature);
        var decision = Decide(engine, verified, out _);

        Assert.Equal(SignatureStatus.Unsigned, verified.Signature);
        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AnUnsignedReplacementAtTheSelectedPathIsRefused()
    {
        var picked = Place(SignedProbe, @"Vendor\probe.exe");
        var engine = EngineWith(RuleFor(picked));
        var catalog = new ImageCatalog(workers: 1);
        var before = catalog.Refresh(picked);

        Place(UnsignedProbe, @"Vendor\probe.exe");
        var after = catalog.Refresh(picked);
        var verified = catalog.VerifyNow(after, EvidenceNeeds.Signature);
        var decision = Decide(engine, verified, out _);

        // A replaced file is a new record: an answer earned by the old bytes does not vouch for these.
        Assert.NotSame(before, after);
        Assert.Equal(RouteAction.Block, decision.Action);
        Assert.Equal(RouteReasonKind.IdentityMismatch, decision.Reason);
    }

    [Fact]
    public void ATamperedCopyIsNotTheApplication()
    {
        var picked = Place(SignedProbe, @"Vendor\bin\1a2b3c4d5e6f7a8b\probe.exe");
        var engine = EngineWith(RuleFor(picked));
        var tampered = Place(SignedProbe, @"Elsewhere\probe.exe");
        var bytes = File.ReadAllBytes(tampered);
        bytes[bytes.Length / 2] ^= 0xFF;
        File.WriteAllBytes(tampered, bytes);

        var catalog = new ImageCatalog(workers: 1);
        var verified = catalog.VerifyNow(catalog.Refresh(tampered), EvidenceNeeds.Signature);
        var decision = Decide(engine, verified, out _);

        Assert.NotEqual(SignatureStatus.Valid, verified.Signature);
        Assert.Equal(RouteAction.Direct, decision.Action);
    }

    [Fact]
    public void AnUnsignedApplicationIsRecognisedByItsBytesAfterAMove()
    {
        var picked = Place(UnsignedProbe, @"Tools\tool.exe");
        var engine = EngineWith(RuleFor(picked));
        var moved = Place(UnsignedProbe, @"Moved\Somewhere\tool.exe");

        var catalog = new ImageCatalog(workers: 1);
        var record = catalog.Refresh(moved);
        var claim = catalog.EvidenceFor(record, null, engine.Snapshot.NeedsProductName);
        var held = Decide(engine, claim, out _);
        var verified = catalog.VerifyNow(record, held.Needs);
        var decision = Decide(engine, verified, out _);

        Assert.Equal(EvidenceNeeds.Hash, held.Needs);
        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(RouteReasonKind.FileHashRule, decision.Reason);
    }

    [Fact]
    public async Task TheEngineMigratesASchemaOneFileInTheBackgroundAndLeavesItForARollback()
    {
        // The rule names a build the updater has since removed; the new build sits in a sibling
        // hash directory. The publisher is stored the way schema 1 stored it.
        var removed = Path.Combine(_root, @"Vendor\bin\1a2b3c4d5e6f7a8b\probe.exe");
        var current = Place(SignedProbe, @"Vendor\bin\9f8e7d6c5b4a3921\probe.exe");
        var unsigned = Place(UnsignedProbe, @"Tools\tool.exe");
        var signer = WindowsImageInspector.Read(current, computeSha256: false)!.SignerName!;

        var legacy = Path.Combine(_root, "configuration.json");
        var v2 = Path.Combine(_root, "configuration.v2.json");
        await File.WriteAllTextAsync(legacy, ConfigurationCodec.EncodeToJson(new RuntimeConfiguration
        {
            Version = new ConfigurationVersion(ConfigurationVersion.PathSchema, 4),
            Rules =
            [
                new AppRule
                {
                    Identity = new AppIdentity { ExecutablePath = removed, DisplayName = "probe", Publisher = signer },
                },
                new AppRule
                {
                    Identity = new AppIdentity { ExecutablePath = unsigned, DisplayName = "tool" },
                },
            ],
        }));
        var legacyHash = SHA256.HashData(await File.ReadAllBytesAsync(legacy));

        var store = new ConfigurationStore(v2, Path.Combine(_root, "credential.bin"), legacy);
        await using var runtime = new EngineRuntime(store, new EngineOptions(EnableDivert: false));

        runtime.LoadConfiguration();
        Assert.Equal(IdentityKind.Path, runtime.Configuration.Rules[0].Identity.Kind);

        await runtime.Migration.WaitAsync(TimeSpan.FromSeconds(60));
        var rules = runtime.Configuration.Rules;

        Assert.Equal(IdentityKind.Signed, rules[0].Identity.Kind);
        Assert.Equal(RuleStatus.Active, rules[0].Status);
        Assert.Contains("9f8e7d6c5b4a3921", rules[0].Identity.ExecutablePath, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(IdentityKind.Unsigned, rules[1].Identity.Kind);
        Assert.Equal(MatchMode.Exact, rules[1].MatchMode);

        Assert.True(File.Exists(v2));
        Assert.Equal(2, ConfigurationCodec.DecodeFromJson(await File.ReadAllTextAsync(v2)).Version.SchemaVersion);
        Assert.Equal(legacyHash, SHA256.HashData(await File.ReadAllBytesAsync(legacy)));
        Assert.Equal(v2, store.SourcePath);
    }

    [Fact]
    public async Task AVerifiedIdentityDecisionIsRelayedThroughTheProxy()
    {
        var picked = Place(SignedProbe, @"Vendor\bin\1a2b3c4d5e6f7a8b\probe.exe");
        var engine = EngineWith(RuleFor(picked) with { Identity = RuleFor(picked).Identity with { DisplayName = "Probe App" } });
        var updated = Place(SignedProbe, @"Vendor\bin\9f8e7d6c5b4a3921\probe.exe");
        using var process = Run(updated);

        var catalog = new ImageCatalog(workers: 1);
        var info = new ProcessResolver(images: catalog).ResolveInfo((uint)process.Id);
        var verified = catalog.VerifyNow(info.Image!, EvidenceNeeds.Signature);
        var decision = Decide(engine, verified, out var rule);
        Assert.Equal(RouteAction.Proxy, decision.Action);

        using var echo = new TcpListener(IPAddress.Loopback, 0);
        echo.Start();
        var echoPort = (ushort)((IPEndPoint)echo.LocalEndpoint).Port;
        var serving = Task.Run(async () =>
        {
            using var accepted = await echo.AcceptSocketAsync();
            var buffer = new byte[64];
            var read = await accepted.ReceiveAsync(buffer, SocketFlags.None);
            await accepted.SendAsync(buffer.AsMemory(0, read), SocketFlags.None);
        });

        await using var proxy = new Socks5TestServer();
        var nat = new NatTable();
        var statistics = new EngineStatistics();
        await using var listener = new RedirectListener(
            nat,
            statistics,
            () => ProxyConfiguration.Default with
            {
                Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = proxy.Port },
                HandshakeTimeoutMilliseconds = 5000,
            },
            () => null);
        listener.Start(0);

        // What the socket pump records for a proxied connection, keyed on the source port - the state
        // the packet rewrite then relies on.
        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var sourcePort = (ushort)((IPEndPoint)client.LocalEndPoint!).Port;
        nat.Record(sourcePort, NatTable.EntryFor(
            IPAddress.Loopback, IPAddress.Loopback, echoPort, (uint)process.Id, info.ExecutablePath, rule,
            hostname: null, DateTimeOffset.UtcNow));

        await client.ConnectAsync(new IPEndPoint(IPAddress.Loopback, listener.Port));
        await client.SendAsync(Encoding.ASCII.GetBytes("ping"), SocketFlags.None);
        var reply = new byte[16];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var received = await client.ReceiveAsync(reply, SocketFlags.None, timeout.Token);
        await serving.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal("ping", Encoding.ASCII.GetString(reply, 0, received));
        Assert.Equal(1, proxy.AcceptedConnections);
        Assert.Equal(echoPort, proxy.LastRequestedPort);
        Assert.Contains(statistics.RecentActivity(10), activity => activity.ApplicationName == "Probe App");
        _output.WriteLine($"{info.ExecutablePath} -> rule '{rule!.Identity.DisplayName}' -> SOCKS5 127.0.0.1:{proxy.Port} -> 127.0.0.1:{echoPort}");
    }

    public void Dispose()
    {
        foreach (var process in _processes)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                    process.WaitForExit(5000);
                }
            }
            catch (InvalidOperationException)
            {
            }

            process.Dispose();
        }

        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Directory.Delete(_root, recursive: true);
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(200);
            }
        }
    }
}
