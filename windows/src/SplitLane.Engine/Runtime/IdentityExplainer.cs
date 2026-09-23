using System.Diagnostics;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Flows;
using SplitLane.Platform;

namespace SplitLane.Engine.Runtime;

/// <summary>
/// <c>--explain</c>: which rule matches which running process, how, and what the engine would do.
/// </summary>
/// <remarks>
/// <para>
/// The question a support engineer asks first about a machine that is "not routing" an application,
/// answered without elevation, without the driver, and without touching the running service: the
/// configuration is read and migrated in memory, every running process is resolved with the same
/// calls the socket pump makes, its image verified the way the engine verifies it, and a connection to
/// a TEST-NET address decided for it.
/// </para>
/// <para>
/// Nothing is written. A schema 1 configuration is shown both ways - as the previous build decided it,
/// by path, and as this build decides it, by identity - so the effect of the migration can be read
/// straight off the output.
/// </para>
/// </remarks>
internal static class IdentityExplainer
{
    /// <summary>The destination every probe decision is made for. TEST-NET-3: routes nowhere.</summary>
    private const string ProbeAddress = "203.0.113.10";

    public static int Run(IReadOnlyList<string> args, TextWriter output)
    {
        var configPath = ValueAfter(args, "--config");
        var showAll = args.Contains("--all", StringComparer.OrdinalIgnoreCase);
        var onlyPid = uint.TryParse(ValueAfter(args, "--pid"), out var pid) ? pid : (uint?)null;

        var store = configPath is null
            ? new ConfigurationStore()
            : new ConfigurationStore(configPath, Path.Combine(Path.GetTempPath(), "splitlane-explain-no-credential.bin"));

        RuntimeConfiguration loaded;
        try
        {
            loaded = store.Load();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                       or ConfigurationValidationException or System.Text.Json.JsonException)
        {
            output.WriteLine($"Could not read {store.SourcePath}: {ex.Message}");
            return 1;
        }

        output.WriteLine($"Configuration: {store.SourcePath} (schema {loaded.Version.SchemaVersion}, " +
                         $"generation {loaded.Version.Generation}, {loaded.Rules.Count} rules)");

        var current = loaded;
        RuleEngine? before = null;

        if (ConfigurationMigrator.NeedsMigration(loaded))
        {
            output.WriteLine();
            output.WriteLine("Migration to schema 2 (in memory; nothing is written):");

            var watch = Stopwatch.StartNew();
            var result = ConfigurationMigrator.Migrate(loaded, WindowsImageInspector.Instance);
            watch.Stop();

            for (var index = 0; index < result.Rules.Count; index++)
            {
                var migration = result.Rules[index];
                var rule = result.Configuration.Rules[index];
                output.WriteLine($"  [{migration.Outcome}] {migration.RulePath}");
                output.WriteLine($"      -> {Describe(rule)}");
                if (migration.Detail.Length > 0)
                {
                    output.WriteLine($"      {migration.Detail}");
                }
            }

            output.WriteLine($"  ({watch.ElapsedMilliseconds} ms)");
            before = new RuleEngine(loaded);
            current = ConfigurationValidator.Sanitize(result.Configuration);
        }

        // The managed policy, judged exactly as the service judges it: an untrusted file is reported
        // and not applied.
        var policyPath = ValueAfter(args, "--policy");
        var policyStore = policyPath is null
            ? new PolicyStore()
            : new PolicyStore(policyPath, args.Contains("--trust-policy", StringComparer.OrdinalIgnoreCase)
                ? (_, _) => null
                : PolicyFileTrust.Problem);
        var policy = policyStore.Load();

        output.WriteLine();
        output.WriteLine($"Managed policy: {policy.State} - {policy.Detail}");

        // The policy folder is readable by administrators only, so to anyone else a policy that is
        // there looks exactly like one that is not.
        if (policy.State == PolicyState.None && Directory.Exists(Path.GetDirectoryName(policyStore.PolicyPath)) &&
            !new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
        {
            output.WriteLine("  The policy folder exists and is readable by administrators only; run --explain from " +
                             "an elevated prompt to see whether it holds a policy.");
        }

        var merged = PolicyMerger.Merge(current, policy.Policy);
        foreach (var note in merged.Notes)
        {
            output.WriteLine($"  {note}");
        }

        current = merged.Effective;
        var engine = new RuleEngine(current);

        output.WriteLine();
        output.WriteLine($"Rules in force ({engine.Snapshot.ActiveRuleCount} active, " +
                         $"{engine.Snapshot.IdentityRuleCount} by identity, {engine.Snapshot.ManagedRuleCount} managed" +
                         (merged.UserRulesDropped > 0 ? $", {merged.UserRulesDropped} user rules set aside by policy" : string.Empty) +
                         "):");
        foreach (var rule in current.Rules)
        {
            output.WriteLine($"  {rule.Identity.DisplayName}: {Describe(rule)}");
        }

        output.WriteLine();
        output.WriteLine($"Running processes, each deciding a TCP connection to {ProbeAddress}:443" +
                         (showAll ? string.Empty : " (only those a rule involves; --all for every one)") + ":");

        var catalog = new ImageCatalog(workers: 1);
        var resolver = new ProcessResolver(images: catalog);
        var rows = new Dictionary<string, Row>(ExecutablePath.Comparer);

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                var processId = (uint)process.Id;
                if (onlyPid is { } wanted && processId != wanted)
                {
                    continue;
                }

                var info = resolver.ResolveInfo(processId);
                if (info.IsUnknown || info.Image is null)
                {
                    continue;
                }

                var key = $"{info.ExecutablePath}|{info.PackageFamilyName}";
                if (rows.TryGetValue(key, out var existing))
                {
                    existing.Pids.Add(processId);
                    continue;
                }

                var evidence = catalog.EvidenceFor(info.Image, info.PackageFamilyName, needsProductName: true);
                var flow = new FlowDescriptor(processId, info.ExecutablePath, ProbeAddress, 443, FlowProtocol.Tcp, Image: evidence);
                var decision = engine.Decide(flow, out var rule);
                var held = decision.Reason == RouteReasonKind.IdentityPending;
                var verifyMs = 0L;

                if (held)
                {
                    var watch = Stopwatch.StartNew();
                    catalog.VerifyNow(info.Image, decision.Needs);
                    verifyMs = watch.ElapsedMilliseconds;
                    evidence = catalog.EvidenceFor(info.Image, info.PackageFamilyName, needsProductName: true);
                    flow = flow with { Image = evidence };
                    decision = engine.Decide(flow, out rule);
                }

                var previous = before?.Decide(flow with { Image = null });
                var involved = held || decision.Reason != RouteReasonKind.NoMatchingRule ||
                               previous is { Reason: not RouteReasonKind.NoMatchingRule };

                if (!involved && !showAll)
                {
                    continue;
                }

                rows[key] = new Row(info.ExecutablePath, evidence, held, verifyMs, previous, decision, rule, [processId]);
            }
        }

        if (rows.Count == 0)
        {
            output.WriteLine("  none");
        }

        foreach (var row in rows.Values.OrderBy(row => row.Decision.Action).ThenBy(row => row.Path, StringComparer.OrdinalIgnoreCase))
        {
            output.WriteLine();
            output.WriteLine($"  {row.Path}");
            output.WriteLine($"      pid {string.Join(", ", row.Pids.Order())}");
            output.WriteLine($"      evidence: {Evidence(row.Evidence)}" +
                             (row.Held ? $" (verified on demand, {row.VerifyMilliseconds} ms)" : string.Empty));
            if (row.Previous is { } previous)
            {
                output.WriteLine($"      schema 1 : {previous.Action,-6} {previous.Explain()}");
            }

            output.WriteLine($"      now      : {row.Decision.Action,-6} {row.Decision.Explain()}" +
                             (row.Rule is not null ? $" [rule '{row.Rule.Identity.DisplayName}']" : string.Empty));
        }

        return 0;
    }

    /// <summary>
    /// <c>--describe &lt;exe&gt;</c>: the identity a rule for this file would record, as JSON.
    /// </summary>
    /// <remarks>
    /// The same code the app runs when someone picks an application, so what this prints is exactly
    /// what a rule made on this machine would contain. It is how a rule is authored for machines the
    /// author is not sitting at: the identity carries no path that has to be the same everywhere.
    /// </remarks>
    public static int DescribeFile(IReadOnlyList<string> args, TextWriter output)
    {
        var path = ValueAfter(args, "--describe");
        if (string.IsNullOrWhiteSpace(path))
        {
            output.WriteLine("usage: SplitLane.Engine.exe --describe <path to an .exe>");
            return 2;
        }

        var evidence = WindowsImageInspector.Read(path, computeSha256: true);
        if (evidence is null)
        {
            output.WriteLine($"{path} could not be read.");
            return 1;
        }

        var (product, _, description) = ImageFile.ReadVersion(path);
        var identity = ConfigurationMigrator.IdentityFor(
            path, product ?? description ?? ExecutablePath.FileName(path), evidence, description);

        if (identity is null)
        {
            output.WriteLine($"{path}: the signature does not verify, so no rule can safely be made for it.");
            return 1;
        }

        output.WriteLine(System.Text.Json.JsonSerializer.Serialize(identity, ConfigurationCodec.FileOptions));
        return 0;
    }

    private static string Describe(AppRule rule)
    {
        var identity = rule.Identity;
        var what = identity.Kind switch
        {
            IdentityKind.Signed => $"signed by {identity.Publisher ?? PublisherName.CommonNameOf(identity.SignerSubject)}, " +
                                   $"{identity.BinaryName}" +
                                   (identity.ProductName is { } product ? $", product '{product}'" : ", no product name"),
            IdentityKind.Package => $"package {identity.PackageFamilyName}" +
                                    (rule.MatchMode == MatchMode.Exact ? $", {identity.BinaryName} only" : ", every binary"),
            IdentityKind.Unsigned => $"unsigned, sha256 {identity.FileSha256?[..Math.Min(12, identity.FileSha256.Length)]}...",
            _ => $"path {identity.ExecutablePath}",
        };

        var scope = rule.UsesFamilyMatching ? "with family" : rule.UsesPackageMatching ? string.Empty : "exact";
        var state = rule.Status == RuleStatus.NeedsReselection ? " - NEEDS RESELECTION, routes nothing" :
                    !rule.IsEnabled ? " - disabled" : string.Empty;
        var origin = rule.IsManaged ? "MANAGED | " : string.Empty;

        return $"{origin}{rule.Action} | {identity.Kind} | {what}{(scope.Length > 0 ? " | " + scope : string.Empty)}{state}";
    }

    private static string Evidence(ImageEvidence evidence)
    {
        var parts = new List<string>();

        if (evidence.PackageFamilyName is { } family)
        {
            parts.Add($"package {family} (from the process token)");
        }

        parts.Add(evidence.Signature switch
        {
            SignatureStatus.Valid => $"signed by {evidence.SignerName}",
            SignatureStatus.Unsigned => "unsigned",
            SignatureStatus.Invalid => "signature does not verify",
            _ => "signature not checked (no rule needed it)",
        });

        if (evidence.HasVersionInfo)
        {
            parts.Add(evidence.ProductName is { } product ? $"product '{product}'" : "no product name");
        }

        return string.Join(", ", parts);
    }

    private static string? ValueAfter(IReadOnlyList<string> args, string name)
    {
        for (var index = 0; index < args.Count - 1; index++)
        {
            if (args[index].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return args[index + 1];
            }
        }

        return null;
    }

    private sealed record Row(
        string Path,
        ImageEvidence Evidence,
        bool Held,
        long VerifyMilliseconds,
        RouteDecision? Previous,
        RouteDecision Decision,
        AppRule? Rule,
        List<uint> Pids);
}
