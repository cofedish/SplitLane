using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Configuration;

/// <summary>
/// Reads the facts about files on disk that identity is made from.
/// </summary>
/// <remarks>
/// An interface so that migration and identity capture stay in the pure core and can be tested with
/// a fake: the real implementation verifies Authenticode signatures and hashes files, which is
/// Windows-specific and slow.
/// </remarks>
public interface IImageInspector
{
    /// <summary>
    /// Everything about a file: signature verdict and signer, version resource, size, and the SHA-256
    /// when asked for. Null when the file does not exist or cannot be read.
    /// </summary>
    ImageEvidence? Inspect(string executablePath, bool computeSha256);

    /// <summary>The immediate subdirectories of a directory, or empty. Never throws.</summary>
    IReadOnlyList<string> ChildDirectories(string directory);
}

/// <summary>What migration did with one rule.</summary>
public enum MigrationOutcome
{
    /// <summary>Already had an identity; nothing to do.</summary>
    Unchanged,

    /// <summary>The file was where the rule said, and its identity was read from it.</summary>
    Verified,

    /// <summary>
    /// The file was gone, and a newer build of the same publisher's application was found in its
    /// place under the same install directory; its identity was read from that.
    /// </summary>
    Reanchored,

    /// <summary>Verified, and the rule covers less than before: an unsigned application lost its family.</summary>
    Narrowed,

    /// <summary>What the rule meant could not be established. It routes nothing until re-selected.</summary>
    NeedsReselection,
}

/// <summary>The migration of one rule.</summary>
/// <param name="RulePath">The path the rule named before migration.</param>
/// <param name="Outcome">What happened.</param>
/// <param name="Detail">Why, in words that can be shown to the user and written to the log.</param>
public sealed record RuleMigration(string RulePath, MigrationOutcome Outcome, string Detail);

/// <summary>A migrated configuration and an account of every rule.</summary>
public sealed record MigrationResult(RuntimeConfiguration Configuration, IReadOnlyList<RuleMigration> Rules)
{
    /// <summary>Whether anything changed.</summary>
    public bool Changed => Rules.Any(rule => rule.Outcome != MigrationOutcome.Unchanged);
}

/// <summary>
/// Turns schema 1 path rules into identity rules, and builds identities for newly picked applications.
/// </summary>
/// <remarks>
/// <para>
/// The one rule this type lives by: a rule is never quietly given to a different application. Every
/// path rule becomes the identity of the file it names - verified from the file itself - or, when that
/// file is gone, of a newer build found where an update would have put it and signed by the same
/// publisher the rule recorded. Anything short of that is marked
/// <see cref="RuleStatus.NeedsReselection"/> and routes nothing, with the reason written on the rule.
/// </para>
/// <para>
/// The publisher recorded by schema 1 was never verified - it was read from the certificate without
/// checking that the signature covered the file - so it is used only to refuse a migration, never to
/// grant one: a verified signer that does not match it stops the migration, and a missing one stops a
/// re-anchoring.
/// </para>
/// </remarks>
public static class ConfigurationMigrator
{
    /// <summary>How many sibling directories are examined when looking for a moved-on build.</summary>
    private const int MaxSiblings = 32;

    /// <summary>Whether a configuration still has rules that recognise an application by path.</summary>
    public static bool NeedsMigration(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return configuration.Rules.Any(rule =>
            rule.Identity.Kind == IdentityKind.Path && rule.Status == RuleStatus.Active);
    }

    /// <summary>Migrates every path rule, leaving everything else as it is.</summary>
    public static MigrationResult Migrate(RuntimeConfiguration configuration, IImageInspector inspector)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(inspector);

        var rules = new List<AppRule>(configuration.Rules.Count);
        var report = new List<RuleMigration>(configuration.Rules.Count);

        foreach (var rule in configuration.Rules)
        {
            if (rule.Identity.Kind != IdentityKind.Path || rule.Status != RuleStatus.Active)
            {
                rules.Add(rule);
                report.Add(new RuleMigration(rule.Identity.ExecutablePath, MigrationOutcome.Unchanged, string.Empty));
                continue;
            }

            var (migrated, outcome) = MigrateRule(rule, inspector);
            rules.Add(migrated);
            report.Add(new RuleMigration(rule.Identity.ExecutablePath, outcome, migrated.StatusDetail ?? string.Empty));
        }

        var result = configuration with
        {
            Rules = rules,
            Version = new ConfigurationVersion(ConfigurationVersion.CurrentSchema, configuration.Version.Generation),
        };

        return new MigrationResult(result, report);
    }

    /// <summary>
    /// The identity to record for a file the user picked, from its evidence.
    /// </summary>
    /// <param name="executablePath">The file.</param>
    /// <param name="displayName">Name to show.</param>
    /// <param name="evidence">
    /// What the inspector read from the file. For an unsigned file it must include the SHA-256.
    /// </param>
    /// <param name="fileDescription">Version resource description, for display.</param>
    /// <returns>The identity, or null when the file cannot be recognised safely (an invalid signature).</returns>
    public static AppIdentity? IdentityFor(
        string executablePath, string displayName, ImageEvidence evidence, string? fileDescription = null)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        var path = ExecutablePath.Normalize(executablePath);
        var basis = new AppIdentity
        {
            ExecutablePath = path,
            DisplayName = displayName,
            FileDescription = fileDescription,
        };

        if (!string.IsNullOrEmpty(evidence.PackageFamilyName) || PackagePath.Family(path).Length > 0)
        {
            return basis with
            {
                Kind = IdentityKind.Package,
                PackageFamilyName = !string.IsNullOrEmpty(evidence.PackageFamilyName)
                    ? evidence.PackageFamilyName
                    : PackagePath.Family(path),
                BinaryName = ExecutablePath.FileName(path),
                Publisher = evidence.SignerName,
            };
        }

        switch (evidence.Signature)
        {
            case SignatureStatus.Valid when !string.IsNullOrEmpty(evidence.SignerSubject):
                return basis with
                {
                    Kind = IdentityKind.Signed,
                    SignerSubject = evidence.SignerSubject,
                    Publisher = evidence.SignerName,
                    ProductName = evidence.HasVersionInfo ? evidence.ProductName : null,
                    OriginalFileName = evidence.HasVersionInfo ? evidence.OriginalFileName : null,
                    DebugName = evidence.DebugName,
                    BinaryName = ExecutablePath.FileName(path),
                };

            case SignatureStatus.Unsigned when !string.IsNullOrEmpty(evidence.Sha256):
                return basis with
                {
                    Kind = IdentityKind.Unsigned,
                    FileSha256 = evidence.Sha256.ToLowerInvariant(),
                    FileSize = evidence.FileSize > 0 ? evidence.FileSize : null,
                };

            default:
                // An invalid signature is a file that claims a publisher it cannot prove. Recording it
                // as unsigned would let anyone with the same broken bytes in; recording the claimed
                // publisher would be worse. It is not a rule anyone can safely make.
                return null;
        }
    }

    private static (AppRule Rule, MigrationOutcome Outcome) MigrateRule(AppRule rule, IImageInspector inspector)
    {
        var path = ExecutablePath.Normalize(rule.Identity.ExecutablePath);

        // A packaged path names its package in the path itself, and WindowsApps is writable only by
        // the system, so the family read from it is the application the rule was made for.
        var package = PackagePath.Family(path);
        if (package.Length > 0)
        {
            var identity = rule.Identity with
            {
                Kind = IdentityKind.Package,
                PackageFamilyName = package,
                BinaryName = ExecutablePath.FileName(path),
            };

            return (rule with { Identity = identity, StatusDetail = null }, MigrationOutcome.Verified);
        }

        var evidence = inspector.Inspect(path, computeSha256: false);
        if (evidence is null)
        {
            return Reanchor(rule, path, inspector);
        }

        return Adopt(rule, path, evidence, inspector, MigrationOutcome.Verified, detail: null);
    }

    /// <summary>
    /// Builds the migrated rule from the evidence of the file it should now recognise.
    /// </summary>
    private static (AppRule Rule, MigrationOutcome Outcome) Adopt(
        AppRule rule,
        string path,
        ImageEvidence evidence,
        IImageInspector inspector,
        MigrationOutcome outcome,
        string? detail)
    {
        var legacyPublisher = rule.Identity.Publisher;

        switch (evidence.Signature)
        {
            case SignatureStatus.Valid:
                if (legacyPublisher is not null &&
                    !PublisherName.MatchesLegacyPublisher(legacyPublisher, evidence.SignerName))
                {
                    return NeedsReselection(
                        rule,
                        $"The rule was made for a program signed by {legacyPublisher}, but {path} is now " +
                        $"signed by {evidence.SignerName}. Select the application again to confirm it.");
                }

                // Nothing was recorded to compare the signer with. The program there when the rule was
                // made was either unsigned or signed only through a catalog, which schema 1 could not
                // read - and adopting whatever is signed there now could hand the rule to a different
                // application, one the family scope would then follow to every install of it.
                if (legacyPublisher is null)
                {
                    return NeedsReselection(
                        rule,
                        $"When this rule was made SplitLane did not record who published {path}; it is " +
                        $"now signed by {evidence.SignerName}. Select the application again to confirm it " +
                        "is the one you meant.");
                }

                var signed = ConfigurationMigrator.IdentityFor(path, rule.Identity.DisplayName, evidence, rule.Identity.FileDescription)!;
                return (rule with
                {
                    Identity = signed with { CapturedAt = rule.Identity.CapturedAt },
                    StatusDetail = detail,
                }, outcome);

            case SignatureStatus.Unsigned:
                if (legacyPublisher is not null)
                {
                    return NeedsReselection(
                        rule,
                        $"The rule was made for a program signed by {legacyPublisher}, but {path} is not " +
                        "signed. Select the application again to confirm it.");
                }

                var hashed = evidence.Sha256 is null ? inspector.Inspect(path, computeSha256: true) : evidence;
                if (hashed?.Sha256 is null)
                {
                    return NeedsReselection(rule, $"{path} could not be read to record which file it is.");
                }

                var unsigned = ConfigurationMigrator.IdentityFor(path, rule.Identity.DisplayName, hashed, rule.Identity.FileDescription)!;
                var narrowed = rule.MatchMode != MatchMode.Exact;
                return (rule with
                {
                    Identity = unsigned with { CapturedAt = rule.Identity.CapturedAt },
                    MatchMode = MatchMode.Exact,
                    StatusDetail = narrowed
                        ? "This application is not signed, so SplitLane recognises it by its exact contents " +
                          "and no longer includes other files in its folder. It will need selecting again " +
                          "after it updates."
                        : detail,
                }, narrowed ? MigrationOutcome.Narrowed : outcome);

            default:
                return NeedsReselection(
                    rule,
                    $"The signature on {path} does not verify, so SplitLane cannot tell which program it is.");
        }
    }

    /// <summary>
    /// Looks for the build an update would have put where the missing one was.
    /// </summary>
    /// <remarks>
    /// Only one place is looked in: the same path with the nearest version or hash directory replaced
    /// by a sibling of the same shape - <c>Codex\bin\*\codex.exe</c> for
    /// <c>Codex\bin\247581e40ee272fb\codex.exe</c>. A candidate is accepted only if it is validly
    /// signed by the publisher the rule recorded, and all candidates agree on what the application is.
    /// </remarks>
    private static (AppRule Rule, MigrationOutcome Outcome) Reanchor(AppRule rule, string path, IImageInspector inspector)
    {
        if (string.IsNullOrWhiteSpace(rule.Identity.Publisher))
        {
            return NeedsReselection(
                rule,
                $"{path} no longer exists, and the rule does not record who published it, so a newer " +
                "copy cannot be recognised. Select the application again.");
        }

        if (!ExecutablePath.TrySplitAtVolatileDirectory(path, out var root, out var old, out var rest) ||
            !ExecutablePath.IsSafeFamilyRoot(root))
        {
            return NeedsReselection(
                rule,
                $"{path} no longer exists. The application has probably been updated or moved; select it again.");
        }

        ImageEvidence? chosen = null;
        string? chosenPath = null;
        var identities = new HashSet<string>(StringComparer.Ordinal);

        foreach (var sibling in inspector.ChildDirectories(root).Take(MaxSiblings))
        {
            var name = ExecutablePath.FileName(sibling);
            if (name.Equals(old, StringComparison.OrdinalIgnoreCase) || !ExecutablePath.IsVolatileDirectory(name))
            {
                continue;
            }

            var candidate = ExecutablePath.Normalize($@"{root}\{name}\{rest}");
            var evidence = inspector.Inspect(candidate, computeSha256: false);

            if (evidence is not { Signature: SignatureStatus.Valid } ||
                !PublisherName.MatchesLegacyPublisher(rule.Identity.Publisher, evidence.SignerName))
            {
                continue;
            }

            identities.Add($"{evidence.SignerSubject}|{ProductFamily.Normalize(evidence.ProductName)}");
            chosen ??= evidence;
            chosenPath ??= candidate;
        }

        if (chosen is null || chosenPath is null)
        {
            return NeedsReselection(
                rule,
                $"{path} no longer exists, and no copy signed by {rule.Identity.Publisher} was found in its " +
                $"place under {root}. Select the application again.");
        }

        if (identities.Count > 1)
        {
            return NeedsReselection(
                rule,
                $"{path} no longer exists, and the copies found under {root} do not agree on what they are. " +
                "Select the application again.");
        }

        return Adopt(
            rule with { Identity = rule.Identity with { ExecutablePath = chosenPath } },
            chosenPath,
            chosen,
            inspector,
            MigrationOutcome.Reanchored,
            $"Updated from {path}, which no longer exists, to {chosenPath}: the same application, " +
            $"signed by {chosen.SignerName}.");
    }

    private static (AppRule Rule, MigrationOutcome Outcome) NeedsReselection(AppRule rule, string detail) =>
        (rule with { Status = RuleStatus.NeedsReselection, StatusDetail = detail }, MigrationOutcome.NeedsReselection);
}
