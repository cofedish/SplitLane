using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.App.ViewModels;

/// <summary>How much a rule's row needs the user.</summary>
public enum RuleAttention
{
    /// <summary>Nothing to say.</summary>
    None,

    /// <summary>Something happened that is worth knowing; the rule works.</summary>
    Note,

    /// <summary>The rule works now and will not keep working, or needs confirming.</summary>
    Warning,

    /// <summary>The rule matches nothing, or its application's connections are being refused.</summary>
    Stopped,
}

/// <summary>What, if anything, is wrong with a rule. In order of importance.</summary>
public enum RuleProblem
{
    /// <summary>Nothing.</summary>
    None,

    /// <summary>Migration could not tell which application the rule means. It routes nothing.</summary>
    NeedsReselection,

    /// <summary>The file at the rule's recorded location is no longer its application.</summary>
    IdentityChanged,

    /// <summary>Migration changed the rule, and wrote down what it did.</summary>
    MigrationNote,

    /// <summary>A schema 1 rule whose executable is gone and which nothing else keeps matching.</summary>
    PathMissing,

    /// <summary>A schema 1 rule on a packaged application, matched only at this version's path.</summary>
    PackagedPath,

    /// <summary>A schema 1 rule that still works, until the application moves.</summary>
    PathOnly,
}

/// <summary>What the page found out about a rule's files, which the rule itself cannot know.</summary>
/// <param name="ExecutableIsMissing">Nothing is at the recorded path.</param>
/// <param name="FamilyRootExists">The directory a schema 1 family rule is rooted at is still there.</param>
/// <param name="IdentityChanged">
/// A file is at the recorded path and it is not the application: different signer, or different bytes.
/// </param>
public readonly record struct RuleObservation(bool ExecutableIsMissing, bool FamilyRootExists, bool IdentityChanged)
{
    /// <summary>Nothing checked yet, or nothing could be read. Assumes the rule is fine.</summary>
    public static RuleObservation Unknown => new(false, true, false);
}

/// <summary>The one thing a rule's row should say about it.</summary>
/// <param name="Attention">How loudly.</param>
/// <param name="Problem">Which condition produced it.</param>
/// <param name="Text">The sentence, for the row.</param>
public sealed record RuleAdvice(RuleAttention Attention, RuleProblem Problem, string Text)
{
    /// <summary>Nothing to say.</summary>
    public static RuleAdvice None { get; } = new(RuleAttention.None, RuleProblem.None, string.Empty);

    /// <summary>
    /// Whether picking the application again is the remedy, so the row offers it.
    /// </summary>
    /// <remarks>
    /// Every schema 1 condition counts: the advice for each of them ends in "select it again", and a
    /// sentence telling someone to do something the row gives them no way to do is only half an answer.
    /// </remarks>
    public bool CanReselect => Problem is RuleProblem.NeedsReselection or RuleProblem.IdentityChanged
        or RuleProblem.PathMissing or RuleProblem.PackagedPath or RuleProblem.PathOnly;
}

/// <summary>
/// Everything the Applications page says about a rule, as pure functions of the rule and what was
/// observed on disk.
/// </summary>
/// <remarks>
/// <para>
/// Kept out of the view models so the wording can be tested without WPF, and so it asks the rule the
/// same questions the engine does - <see cref="AppRule.UsesPackageMatching"/>,
/// <see cref="AppRule.UsesFamilyMatching"/>, <see cref="AppRule.ParticipatesInRouting"/> - rather than
/// re-deriving them. A second copy of that reasoning here disagreed with the engine once, and the
/// visible form of the disagreement was a warning telling someone to remove a rule that was working:
/// after a packaged application updated, the page said "its traffic is going DIRECT" while the engine
/// went on matching it by package family.
/// </para>
/// </remarks>
public static class RulePresentation
{
    /// <summary>The most important thing to say about a rule, or nothing.</summary>
    /// <remarks>
    /// A missing file at the recorded path is a fault only for a schema 1 rule. A signed, packaged or
    /// unsigned rule recognises its application wherever it is; the file being gone from where it was
    /// picked means it updated or moved, and the rule followed it.
    /// </remarks>
    public static RuleAdvice Advise(AppRule rule, RuleObservation observed)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var identity = rule.Identity;

        if (rule.Status == RuleStatus.NeedsReselection)
        {
            var detail = string.IsNullOrWhiteSpace(rule.StatusDetail)
                ? "SplitLane could not tell which application this rule is for."
                : rule.StatusDetail.Trim();

            var ask = detail.Contains("select", StringComparison.OrdinalIgnoreCase)
                ? string.Empty
                : " Select the application again.";

            // The engine refuses a process started from exactly the path the rule names, and routes
            // nothing else by it: a copy of the application anywhere else goes DIRECT until re-selected.
            var atPath = rule.EffectiveAction == RouteAction.Direct
                ? string.Empty
                : $" A program started from {identity.ExecutablePath} is blocked meanwhile, rather than let out DIRECT.";

            return new RuleAdvice(
                RuleAttention.Stopped,
                RuleProblem.NeedsReselection,
                $"{detail}{ask} Until then the rule matches nothing elsewhere{Consequence(rule)}.{atPath}");
        }

        if (observed.IdentityChanged && identity.Kind is IdentityKind.Signed or IdentityKind.Unsigned)
        {
            var what = identity.Kind == IdentityKind.Signed
                ? $"The file at {identity.ExecutablePath} is no longer signed by {PublisherOf(identity)}, " +
                  "so it is not the application this rule was made for."
                : $"The file at {identity.ExecutablePath} has changed since it was selected. It is not " +
                  "signed, so SplitLane recognises it only by its exact contents.";

            // Mirrors the engine: a mismatch at the recorded location is refused only when the rule would
            // have done something to the application. A rule that sends it DIRECT, or is switched off,
            // protects nothing by refusing whatever now sits in its place.
            return rule.ParticipatesInRouting && rule.EffectiveAction != RouteAction.Direct
                ? new RuleAdvice(
                    RuleAttention.Stopped,
                    RuleProblem.IdentityChanged,
                    $"{what} Connections from it are refused until you select it again.")
                : new RuleAdvice(
                    RuleAttention.Warning,
                    RuleProblem.IdentityChanged,
                    $"{what} Select it again to confirm which program this rule is for.");
        }

        if (!string.IsNullOrWhiteSpace(rule.StatusDetail))
        {
            return new RuleAdvice(RuleAttention.Note, RuleProblem.MigrationNote, rule.StatusDetail.Trim());
        }

        if (identity.Kind != IdentityKind.Path)
        {
            return RuleAdvice.None;
        }

        // A schema 1 rule still matching something without its file: a family rule whose folder is
        // still there, which a self-updating application runs from, or a package rule, which never
        // needed the file at all.
        var stillMatches = rule.UsesPackageMatching || (rule.UsesFamilyMatching && observed.FamilyRootExists);

        if (observed.ExecutableIsMissing && !stillMatches)
        {
            return new RuleAdvice(
                RuleAttention.Stopped,
                RuleProblem.PathMissing,
                identity.IsPackaged
                    ? "This executable is gone — the app has almost certainly been updated into a new " +
                      $"versioned folder — and the rule matches nothing{Consequence(rule)}. Select the " +
                      "application again; the new rule follows it through updates."
                    : $"This executable is no longer on disk and the rule matches nothing{Consequence(rule)}. " +
                      "Select the application again.");
        }

        if (identity.IsPackaged && !rule.UsesPackageMatching)
        {
            return new RuleAdvice(
                RuleAttention.Warning,
                RuleProblem.PackagedPath,
                identity.SupportsPackageMatching
                    ? "Packaged app: the path contains a version, so this rule matches only the version " +
                      "installed now. Turn on Include folder, or select it again, to match it by package " +
                      "instead, which survives its updates."
                    : identity.VersionedSegment is { } segment
                        ? $"Packaged app: the path contains a version ({segment}), so it will change on the " +
                          "next update and this rule will silently stop matching. Select it again."
                        : "Packaged app: its install path contains a version, so it will change on the next " +
                          "update and this rule will silently stop matching. Select it again.");
        }

        return new RuleAdvice(
            RuleAttention.Warning,
            RuleProblem.PathOnly,
            "Recognised by path only — an older rule. Select it again so it keeps working after the " +
            "application updates or moves.");
    }

    /// <summary>
    /// Whether the file now at a rule's recorded location is still the rule's application.
    /// </summary>
    /// <returns>
    /// Null when there is nothing to judge: no evidence, a kind with no location pin, or an unsigned
    /// file whose hash was not read. The same comparisons the engine makes at that location.
    /// </returns>
    public static bool? StillSameApplication(AppIdentity identity, ImageEvidence? evidence)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (evidence is null)
        {
            return null;
        }

        return identity.Kind switch
        {
            IdentityKind.Signed =>
                evidence.Signature == SignatureStatus.Valid &&
                !string.IsNullOrEmpty(evidence.SignerSubject) &&
                string.Equals(evidence.SignerSubject, identity.SignerSubject, StringComparison.Ordinal),
            IdentityKind.Unsigned when evidence.Sha256 is not null =>
                string.Equals(evidence.Sha256, identity.FileSha256, StringComparison.OrdinalIgnoreCase),
            _ => null,
        };
    }

    /// <summary>Whether the engine pins this rule to its recorded location, so the page should look there.</summary>
    public static bool HasLocationPin(AppRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        return rule.Status == RuleStatus.Active && rule.Identity.Kind is IdentityKind.Signed or IdentityKind.Unsigned;
    }

    /// <summary>One line saying how the application is recognised.</summary>
    public static string IdentitySummary(AppIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        return identity.Kind switch
        {
            IdentityKind.Signed =>
                $"Signed by {PublisherOf(identity)} · {BinaryOf(identity)} · any folder, any version",
            IdentityKind.Package =>
                $"Package {identity.PackageFamilyName} · every version",
            IdentityKind.Unsigned =>
                "Unsigned · pinned to these exact bytes — select again after it updates",
            _ => "Path only (old rule)",
        };
    }

    /// <summary>The identity in full, for the summary's tooltip.</summary>
    public static string IdentityDetail(AppIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        return identity.Kind switch
        {
            IdentityKind.Signed =>
                "Recognised by its verified signature, wherever it is installed and whatever version it is." +
                $"\nPublisher: {identity.SignerSubject}" +
                (string.IsNullOrEmpty(identity.ProductName) ? string.Empty : $"\nProduct: {identity.ProductName}") +
                $"\nFile name: {BinaryOf(identity)}",
            IdentityKind.Package =>
                "Recognised by its package, in every version and on any drive." +
                $"\nPackage family: {identity.PackageFamilyName}" +
                $"\nFile name: {BinaryOf(identity)}",
            IdentityKind.Unsigned =>
                "Not signed, so recognised only by its exact contents. An update changes them, and the rule " +
                "stops matching until the application is selected again." +
                $"\nSHA-256: {identity.FileSha256}" +
                (identity.FileSize is { } size ? $"\nSize: {size:N0} bytes" : string.Empty),
            _ =>
                "Recognised by this path only — all that rules made before identity matching recorded. An " +
                "update that moves the application leaves the rule behind.",
        };
    }

    /// <summary>One line saying what the rule covers.</summary>
    public static string MatchSummary(AppRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var identity = rule.Identity;

        return identity.Kind switch
        {
            IdentityKind.Package => rule.UsesPackageMatching
                ? "Every version of this packaged application"
                : $"Only {BinaryOf(identity)}, in every version of this package",
            IdentityKind.Signed => rule.UsesFamilyMatching
                ? $"This program and its publisher's other programs {SignedReach(identity, shortRoot: true)}"
                : $"Only {BinaryOf(identity)}, wherever it is installed",
            IdentityKind.Unsigned => "Only this exact file",
            _ => rule.UsesPackageMatching
                ? "Every version of this packaged application"
                : rule.UsesFamilyMatching
                    ? $"This executable and everything under {ShortRoot(identity.FamilyRoot)}"
                    : "This executable only",
        };
    }

    /// <summary>Whether the helpers control can be turned on at all.</summary>
    /// <remarks>
    /// Never for an unsigned application: a family of unsigned files is a folder anyone who can write to
    /// it can join, which is how a dropped-in file inherited a rule before schema 2.
    /// </remarks>
    public static bool CanIncludeFamily(AppIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return identity.Kind != IdentityKind.Unsigned &&
               (identity.SupportsFamilyMatching || identity.SupportsPackageMatching);
    }

    /// <summary>Explains the helpers control, whether or not it is available.</summary>
    public static string MatchTooltip(AppIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (identity.Kind == IdentityKind.Unsigned)
        {
            return "Not available: this program is not signed, so anything dropped into its folder could " +
                   "join it.";
        }

        if (identity.SupportsPackageMatching)
        {
            return "Also route this application's other processes, and keep routing it after it updates. " +
                   "A packaged application installs each version in a new folder, so matching the folder " +
                   "alone would stop working at the next update.";
        }

        if (identity.Kind == IdentityKind.Signed)
        {
            return identity.SupportsFamilyMatching
                ? $"Also route this publisher's other programs {SignedReach(identity, shortRoot: false)}. A " +
                  "program there that is unsigned, or signed by someone else, is never included."
                : $"Not available: {identity.InstallRoot} is shared with unrelated programs and this " +
                  "program's product name is missing or shared too, so including its folder would take in " +
                  $"every other program {PublisherOf(identity)} installed there.";
        }

        return identity.SupportsFamilyMatching
            ? $"Also route anything else installed under {identity.FamilyRoot}."
            : $"{identity.FamilyRoot} is shared with unrelated programs, so family matching is not " +
              "available for this application — it would put every program in that folder into the proxy lane.";
    }

    /// <summary>
    /// How much of an application a new rule covers: as much as is both possible and safe.
    /// </summary>
    /// <remarks>
    /// A packaged application gets its package: an exact rule on its path would stop matching at the
    /// next update, and its folder's parent is shared with every other packaged application (ADR
    /// W-0003). A signed one gets its helpers where its folder or product name is its own. An unsigned
    /// one gets only itself.
    /// </remarks>
    public static MatchMode DefaultMode(AppIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        return identity.Kind switch
        {
            IdentityKind.Package => MatchMode.PackageFamily,
            IdentityKind.Signed => identity.SupportsFamilyMatching ? MatchMode.ExecutableFamily : MatchMode.Exact,
            IdentityKind.Unsigned => MatchMode.Exact,
            _ => identity.SupportsPackageMatching
                ? MatchMode.PackageFamily
                : identity.SupportsFamilyMatching ? MatchMode.ExecutableFamily : MatchMode.Exact,
        };
    }

    /// <summary>
    /// The mode a re-selected rule keeps: the user's choice, translated to what the new identity can
    /// honour.
    /// </summary>
    /// <remarks>
    /// "Only this program" stays exact. "Include helpers" becomes whichever mechanism means that for
    /// the application as it is now - the same translation the checkbox makes - and exact where
    /// nothing safe can.
    /// </remarks>
    public static MatchMode ModeFor(AppIdentity identity, MatchMode requested) =>
        requested == MatchMode.Exact ? MatchMode.Exact : DefaultMode(identity);

    /// <summary>What to say after adding an application.</summary>
    public static string AddedMessage(AppIdentity identity, MatchMode mode)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var name = identity.DisplayName;

        return identity.Kind switch
        {
            IdentityKind.Package =>
                $"{name} added. It is a packaged app, so it is recognised by its package — the rule survives " +
                "its updates.",
            IdentityKind.Signed when mode == MatchMode.Exact =>
                $"{name} added. It is recognised by its publisher's signature, so the rule follows it through " +
                "updates. Its folder is shared with other programs, so only this program is included.",
            IdentityKind.Signed =>
                $"{name} added to the proxy lane. It is recognised by its publisher's signature, so the rule " +
                "follows it through updates and moves.",
            IdentityKind.Unsigned =>
                $"{name} added. It is not signed, so SplitLane recognises it by its exact contents — it will " +
                "need selecting again after it updates.",
            _ => $"{name} added to the proxy lane.",
        };
    }

    /// <summary>What the banner over the list says about rules that route nothing, or empty.</summary>
    /// <param name="needsReselection">Rules migration could not resolve.</param>
    /// <param name="identityChanged">Rules whose recorded file is now something else, and refused.</param>
    /// <param name="pathMissing">Schema 1 rules whose executable is gone.</param>
    public static string StaleSummary(int needsReselection, int identityChanged, int pathMissing)
    {
        var parts = new List<string>(3);

        if (needsReselection > 0)
        {
            parts.Add(needsReselection == 1
                ? "One rule needs its application selected again and matches nothing until then."
                : $"{needsReselection} rules need their applications selected again and match nothing until then.");
        }

        if (identityChanged > 0)
        {
            parts.Add(identityChanged == 1
                ? "One rule's recorded file is no longer the application it was made for, so connections " +
                  "from it are refused."
                : $"{identityChanged} rules' recorded files are no longer the applications they were made " +
                  "for, so connections from them are refused.");
        }

        if (pathMissing > 0)
        {
            parts.Add(pathMissing == 1
                ? "One older rule names an executable that is no longer on disk, so it matches nothing."
                : $"{pathMissing} older rules name executables that are no longer on disk, so they match nothing.");
        }

        return parts.Count == 0 ? string.Empty : string.Join(" ", parts) + " Select again fixes each one.";
    }

    /// <summary>What to say once the rules on screen have been migrated, or null when nothing changed.</summary>
    public static string? MigrationSummary(MigrationResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var converted = result.Rules.Count(rule =>
            rule.Outcome is MigrationOutcome.Verified or MigrationOutcome.Reanchored or MigrationOutcome.Narrowed);
        var unresolved = result.Rules.Count(rule => rule.Outcome == MigrationOutcome.NeedsReselection);

        if (converted == 0 && unresolved == 0)
        {
            return null;
        }

        var text = converted switch
        {
            0 => string.Empty,
            1 => "One rule recorded by path now recognises its application by signature, package or " +
                 "contents instead, so it keeps working when the application moves. ",
            _ => $"{converted} rules recorded by path now recognise their applications by signature, " +
                 "package or contents instead, so they keep working when the applications move. ",
        };

        text += unresolved switch
        {
            0 => string.Empty,
            1 => "One could not be matched to an application and needs selecting again. ",
            _ => $"{unresolved} could not be matched to an application and need selecting again. ",
        };

        // Said because the Save button stays off: the user did not make this change. Without the second
        // half it would read as though the conversion were lost unless they found a way to save it.
        return text + "Nothing has been written yet: the engine makes the same change itself, and your " +
               "next save records it.";
    }

    private static string Consequence(AppRule rule) => rule.EffectiveAction switch
    {
        RouteAction.Proxy => ", so this application's traffic is going DIRECT",
        RouteAction.Block => ", so this application is not being blocked",
        _ => string.Empty,
    };

    /// <summary>
    /// The publisher's name for display: the verified common name in full, or failing that the one
    /// inside the canonical key.
    /// </summary>
    private static string PublisherOf(AppIdentity identity) =>
        identity.Publisher
        ?? PublisherName.CommonNameOf(identity.SignerSubject)
        ?? "its publisher";

    private static string BinaryOf(AppIdentity identity) =>
        identity.BinaryName ?? ExecutablePath.FileName(identity.ExecutablePath);

    /// <summary>
    /// What a signed family takes in beyond the program itself, in the terms the engine uses: the same
    /// product name where that is specific to the publisher, the install directory where that is not
    /// shared.
    /// </summary>
    private static string SignedReach(AppIdentity identity, bool shortRoot)
    {
        var root = identity.InstallRoot;
        var byRoot = !string.IsNullOrEmpty(root) && ExecutablePath.IsSafeFamilyRoot(root);
        var byProduct = ProductFamily.CanRootFamily(identity.ProductName, identity.SignerSubject);
        var shown = shortRoot ? ShortRoot(root) : root;

        return (byProduct, byRoot) switch
        {
            (true, true) => $"of the same product, or installed under {shown}",
            (true, false) => $"of the same product ({identity.ProductName})",
            _ => $"installed under {shown}",
        };
    }

    /// <summary>
    /// A directory shortened to its last three folders, so the part that names the application stays
    /// readable.
    /// </summary>
    /// <remarks>
    /// By folder, not by character count. Cutting at a fixed length kept
    /// <c>…sers\JohnSmith\AppData\Loc</c> of a user-profile path - and the line's own ellipsis then
    /// trimmed away the <c>OpenAI\Codex\bin</c> that said which application it was.
    /// </remarks>
    private static string ShortRoot(string root)
    {
        var segments = root.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        return segments.Length <= 4 ? root : "…\\" + string.Join('\\', segments[^3..]);
    }
}
