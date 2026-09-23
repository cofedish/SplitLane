using SplitLane.Core.Models;

namespace SplitLane.Core.Rules;

/// <summary>How a rule came to match a process. Diagnostic, and the basis of the route reason.</summary>
public enum MatchKind
{
    /// <summary>Nothing matched.</summary>
    None = 0,

    /// <summary>A schema 1 rule on this exact path.</summary>
    PathExact,

    /// <summary>A schema 1 rule on an ancestor directory of this path.</summary>
    PathFamily,

    /// <summary>A schema 1 rule on a packaged path, matched by the family read from the path.</summary>
    PathPackage,

    /// <summary>A package rule for this file name, matched on the token's package family.</summary>
    PackageBinary,

    /// <summary>A package rule for the whole package, matched on the token's package family.</summary>
    PackageFamily,

    /// <summary>The file at a signed rule's recorded location, still signed by the same publisher.</summary>
    SignedPinned,

    /// <summary>The same publisher, product and file name, anywhere.</summary>
    SignedExact,

    /// <summary>The same publisher, under the rule's install directory.</summary>
    SignedLocation,

    /// <summary>The same publisher and product name.</summary>
    SignedProduct,

    /// <summary>The same bytes as a pinned unsigned file.</summary>
    UnsignedHash,
}

/// <summary>The outcome of looking a process up in a snapshot.</summary>
/// <param name="Rule">The rule that matched, or for a pending lookup the rule the claim points at.</param>
/// <param name="Kind">How it matched.</param>
/// <param name="Needs">What must be read before the lookup can finish. Not <c>None</c> means pending.</param>
/// <param name="Mismatched">
/// A rule whose recorded location holds a file that is no longer its application.
/// </param>
public readonly record struct RuleMatch(
    AppRule? Rule,
    MatchKind Kind,
    EvidenceNeeds Needs = EvidenceNeeds.None,
    AppRule? Mismatched = null)
{
    /// <summary>No rule is involved.</summary>
    public static readonly RuleMatch None = new(null, MatchKind.None);

    /// <summary>Whether a rule matched.</summary>
    public bool IsMatch => Rule is not null && Needs == EvidenceNeeds.None && Mismatched is null;

    /// <summary>Whether the match is for this one executable rather than a family around it.</summary>
    public bool IsExact => Kind is MatchKind.PathExact or MatchKind.PackageBinary or MatchKind.SignedPinned
        or MatchKind.SignedExact or MatchKind.UnsignedHash;
}

/// <summary>
/// Precomputed, immutable lookup tables for one configuration generation.
/// </summary>
/// <remarks>
/// <para>
/// Built once per reload, read on every flow. The engine is consulted for <i>every</i> connection on
/// the system, including the overwhelming majority it will wave straight through, so the lookup must
/// not touch disk and must not verify a signature. It works on the evidence it is handed, and when a
/// rule depends on a fact the evidence does not have yet, it says which one
/// (<see cref="RuleMatch.Needs"/>) instead of guessing.
/// </para>
/// <para>
/// Two families of table live here. The schema 1 tables key on the path, exactly as they always have,
/// so a configuration that has not been migrated keeps its meaning. The identity tables key on what
/// survives an update or a move: the package family from the process token, and for signed
/// applications the file name, the product name and the install directory - each of which is only a
/// claim until the signature confirms the publisher.
/// </para>
/// </remarks>
public sealed class RuleSnapshot
{
    // Schema 1: keyed on where the application was.
    private readonly Dictionary<string, AppRule> _exactRules = new(ExecutablePath.Comparer);
    private readonly Dictionary<string, AppRule> _familyRules = new(ExecutablePath.Comparer);
    private readonly Dictionary<string, AppRule> _packageRules = new(StringComparer.OrdinalIgnoreCase);

    // The machine's managed policy, consulted before any of the user's own rules.
    private readonly RuleSnapshot? _managed;

    // Schema 2: keyed on what the application is.
    private readonly Dictionary<string, List<AppRule>> _packageIdentities = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<AppRule>> _signedByBinary = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<AppRule>> _signedByProduct = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<ScopedRule>> _signedByRoot = new(ExecutablePath.Comparer);
    private readonly Dictionary<string, AppRule> _pins = new(ExecutablePath.Comparer);
    private readonly Dictionary<long, List<AppRule>> _unsignedBySize = [];

    // Rules waiting to be selected again, by the path they name: a process still started from there is
    // refused rather than let out DIRECT.
    private readonly Dictionary<string, AppRule> _stalePins = new(ExecutablePath.Comparer);

    /// <summary>Builds a snapshot from a configuration.</summary>
    public RuleSnapshot(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        // Managed rules get tables of their own, looked up first. Precedence by construction rather
        // than by specificity: a user's exact rule would otherwise beat a managed family rule for the
        // same binary, which is exactly the override a policy exists to rule out.
        var managed = configuration.Rules.Where(rule => rule.IsManaged).ToList();
        if (managed.Count > 0)
        {
            _managed = new RuleSnapshot(managed);
        }

        AddRules(configuration.Rules.Where(rule => !rule.IsManaged));

        Proxy = configuration.Proxy;
        Version = configuration.Version;
        IsRoutingEnabled = configuration.IsRoutingEnabled;
        LogsDirectFlows = configuration.LogsDirectFlows;
        ProxiesUdp = configuration.ProxiesUdp;
    }

    /// <summary>Tables for one tier of rules, with no settings of their own.</summary>
    private RuleSnapshot(IEnumerable<AppRule> rules)
    {
        _isManagedTier = true;
        AddRules(rules);
        Proxy = ProxyConfiguration.Default;
    }

    /// <summary>
    /// Whether these are the managed policy's tables. Two things differ for them: a claim on a rule
    /// that sends its application DIRECT is still verified, because a managed DIRECT has to shadow the
    /// user's rules rather than step aside for them; and nothing is pinned to a location, because the
    /// path in a managed rule was recorded on whatever machine the administrator described it on.
    /// </summary>
    private readonly bool _isManagedTier;

    private void AddRules(IEnumerable<AppRule> rules)
    {
        foreach (var rule in rules)
        {
            // A rule waiting to be re-selected routes nothing to the proxy - what it meant could not be
            // established. But the file it names, if a process still runs from exactly there, is refused:
            // that is the selected application or whatever replaced it, and neither should go out DIRECT
            // on the strength of a rule the user has not yet re-confirmed.
            if (rule.IsEnabled && rule.Status == RuleStatus.NeedsReselection && rule.Action != RouteAction.Direct &&
                !_isManagedTier)
            {
                var stale = ExecutablePath.Normalize(rule.Identity.ExecutablePath);
                if (stale.Length > 0)
                {
                    _stalePins[stale] = rule;
                }

                continue;
            }

            // A disabled rule routes nothing, which is what makes turning a rule off mean exactly "as if
            // it were not there".
            if (!rule.ParticipatesInRouting)
            {
                continue;
            }

            var key = ExecutablePath.Normalize(rule.Identity.ExecutablePath);

            // The validator rejects empty paths, but the snapshot is the last line before the hot
            // path: an empty key here would match every flow whose process could not be resolved.
            if (string.IsNullOrEmpty(key))
            {
                continue;
            }

            switch (rule.Identity.Kind)
            {
                case IdentityKind.Package:
                    AddPackage(rule);
                    break;

                case IdentityKind.Signed:
                    AddSigned(rule, key);
                    break;

                case IdentityKind.Unsigned:
                    AddUnsigned(rule, key);
                    break;

                default:
                    AddPath(rule, key);
                    break;
            }
        }
    }

    /// <summary>The upstream the PROXY lane points at for this generation.</summary>
    public ProxyConfiguration Proxy { get; }

    /// <summary>Schema and generation stamp of the configuration this was built from.</summary>
    public ConfigurationVersion Version { get; }

    /// <summary>Master switch.</summary>
    public bool IsRoutingEnabled { get; }

    /// <summary>Whether DIRECT decisions should be logged individually.</summary>
    public bool LogsDirectFlows { get; }

    /// <summary>Whether a selected application's UDP is relayed rather than refused.</summary>
    public bool ProxiesUdp { get; }

    /// <summary>An engine with no rules at all. Every flow goes DIRECT.</summary>
    public static readonly RuleSnapshot Empty = new(RuntimeConfiguration.Empty);

    /// <summary>Number of rules that can route traffic, managed ones included. Diagnostic only.</summary>
    public int ActiveRuleCount => _activeRules + (_managed?.ActiveRuleCount ?? 0);

    /// <summary>Number of managed rules in force. Diagnostic only.</summary>
    public int ManagedRuleCount => _managed?.ActiveRuleCount ?? 0;

    /// <summary>Number of schema 1 rules participating in family matching. Diagnostic only.</summary>
    public int FamilyRuleCount => _familyRules.Count;

    /// <summary>How many rules match a packaged application across its versions.</summary>
    public int PackageRuleCount => _packageRuleCount + (_managed?.PackageRuleCount ?? 0);

    /// <summary>How many rules recognise an application by identity rather than by path.</summary>
    public int IdentityRuleCount => _identityRules + (_managed?.IdentityRuleCount ?? 0);

    /// <summary>
    /// Whether some rule can only be claimed through the product name, so the caller must read the
    /// version resource of a new executable before asking.
    /// </summary>
    public bool NeedsProductName => _signedByProduct.Count > 0 || (_managed?.NeedsProductName ?? false);

    /// <summary>Whether some rule pins an unsigned file, so the caller must supply file sizes.</summary>
    public bool NeedsFileSize => _unsignedBySize.Count > 0 || (_managed?.NeedsFileSize ?? false);

    private int _activeRules;
    private int _identityRules;
    private int _packageRuleCount;

    /// <summary>
    /// Finds the rule for a process, or says what has to be read about it first.
    /// </summary>
    /// <remarks>
    /// Order, and why:
    /// <list type="number">
    /// <item>Package family from the token. Authoritative and already known, so it needs nothing.</item>
    /// <item>Identity rules. A claim - the file name, product name or install directory a signed rule
    /// names, the size or location of a pinned unsigned file - makes the answer depend on the signature
    /// or the hash. Without it the answer is "pending", never a guess in either direction.</item>
    /// <item>Schema 1 path rules, exactly as they always matched.</item>
    /// </list>
    /// All of it for the managed policy's rules first; the user's rules are consulted only when no
    /// managed rule is involved at all - not matched, not pending, not refused at its location.
    /// </remarks>
    public RuleMatch Match(ImageEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        if (_managed is not null)
        {
            var managed = _managed.Match(evidence);
            if (managed.Rule is not null || managed.Needs != EvidenceNeeds.None || managed.Mismatched is not null)
            {
                return managed;
            }
        }

        var path = evidence.ExecutablePath;
        if (string.IsNullOrEmpty(path))
        {
            return RuleMatch.None;
        }

        if (_packageIdentities.Count > 0 &&
            !string.IsNullOrEmpty(evidence.PackageFamilyName) &&
            _packageIdentities.TryGetValue(evidence.PackageFamilyName, out var packaged))
        {
            var packageMatch = MatchPackage(packaged, evidence);
            if (packageMatch.IsMatch)
            {
                return packageMatch;
            }
        }

        // This tier's own count, not the property that includes the managed tier: otherwise one managed
        // rule would send every connection on the machine through the identity lookup of a user tier
        // that has no identity rules at all.
        if (_identityRules > PackageIdentityCount)
        {
            var identity = MatchIdentity(evidence);
            if (identity.Kind != MatchKind.None || identity.Needs != EvidenceNeeds.None || identity.Mismatched is not null)
            {
                return identity;
            }
        }

        var byPath = MatchPath(path);
        if (byPath.Kind != MatchKind.None || _stalePins.Count == 0 || !_stalePins.TryGetValue(path, out var waiting))
        {
            return byPath;
        }

        return new RuleMatch(null, MatchKind.None, Mismatched: waiting);
    }

    /// <summary>
    /// Finds the most specific rule matching an executable path, as a schema 1 lookup.
    /// </summary>
    /// <remarks>
    /// The path is all the caller has, so identity rules can only answer through their location pin
    /// and will usually report nothing. Kept for callers that only need to know whether a path is
    /// covered by a path rule; routing goes through <see cref="Match"/>.
    /// </remarks>
    public bool TryGetRule(string executablePath, out AppRule rule, out bool isExact)
    {
        var match = Match(ImageEvidence.FromPath(executablePath));
        rule = match.IsMatch ? match.Rule! : null!;
        isExact = match.IsMatch && match.IsExact;
        return match.IsMatch;
    }

    private int PackageIdentityCount { get; set; }


    private static RuleMatch MatchPackage(List<AppRule> rules, ImageEvidence evidence)
    {
        AppRule? wholePackage = null;

        foreach (var rule in rules)
        {
            if (rule.MatchMode == MatchMode.Exact)
            {
                if (string.Equals(rule.Identity.BinaryName, evidence.FileName, StringComparison.OrdinalIgnoreCase))
                {
                    return new RuleMatch(rule, MatchKind.PackageBinary);
                }
            }
            else
            {
                wholePackage ??= rule;
            }
        }

        return wholePackage is null ? RuleMatch.None : new RuleMatch(wholePackage, MatchKind.PackageFamily);
    }

    private RuleMatch MatchIdentity(ImageEvidence evidence)
    {
        var path = evidence.ExecutablePath;

        _pins.TryGetValue(path, out var pin);
        _signedByBinary.TryGetValue(evidence.FileName, out var byBinary);

        List<AppRule>? byProduct = null;
        if (_signedByProduct.Count > 0 && evidence.HasVersionInfo)
        {
            _signedByProduct.TryGetValue(evidence.NormalizedProductName, out byProduct);
        }

        var byRoot = _signedByRoot.Count > 0 ? FindScopedFamily(path) : null;

        List<AppRule>? bySize = null;
        if (_unsignedBySize.Count > 0 && evidence.FileSize > 0)
        {
            _unsignedBySize.TryGetValue(evidence.FileSize, out bySize);
        }

        if (pin is null && byBinary is null && byProduct is null && byRoot is null && bySize is null)
        {
            return RuleMatch.None;
        }

        var signedClaim = pin?.Identity.Kind == IdentityKind.Signed || byBinary is not null ||
                          byProduct is not null || byRoot is not null;
        var unsignedClaim = pin?.Identity.Kind == IdentityKind.Unsigned || bySize is not null;
        var claimed = pin ?? First(byBinary) ?? First(byRoot) ?? First(byProduct) ?? First(bySize);

        // Every rule the claim could lead to sends the application DIRECT, which is also what happens
        // when nothing matches. There is nothing to wait for, and no reason to hold a connection an
        // application the user deliberately left alone is trying to make.
        if (!_isManagedTier && AllDirect(pin, byBinary, byProduct, byRoot, bySize))
        {
            return RuleMatch.None;
        }

        var needs = EvidenceNeeds.None;
        if (signedClaim && !evidence.HasSignatureVerdict)
        {
            needs |= EvidenceNeeds.Signature;
        }

        if (unsignedClaim && evidence.Sha256 is null)
        {
            needs |= EvidenceNeeds.Hash;
        }

        if (needs != EvidenceNeeds.None)
        {
            return new RuleMatch(claimed, MatchKind.None, needs);
        }

        // The recorded location first. Whatever is there now either is the application - same
        // publisher, or same bytes - or it is something that took its place, and neither routing the
        // replacement nor letting the application's traffic out DIRECT is acceptable.
        if (pin is not null)
        {
            if (pin.Identity.Kind == IdentityKind.Signed)
            {
                return SignedBy(evidence, pin)
                    ? new RuleMatch(pin, MatchKind.SignedPinned)
                    : new RuleMatch(null, MatchKind.None, Mismatched: pin);
            }

            return SameBytes(evidence, pin)
                ? new RuleMatch(pin, MatchKind.UnsignedHash)
                : new RuleMatch(null, MatchKind.None, Mismatched: pin);
        }

        if (evidence.Signature == SignatureStatus.Valid)
        {
            foreach (var rule in byBinary ?? [])
            {
                if (SignedBy(evidence, rule) && SameProduct(evidence, rule) && SameOriginalName(evidence, rule))
                {
                    return new RuleMatch(rule, MatchKind.SignedExact);
                }
            }

            foreach (var rule in byRoot ?? [])
            {
                if (SignedBy(evidence, rule))
                {
                    return new RuleMatch(rule, MatchKind.SignedLocation);
                }
            }

            foreach (var rule in byProduct ?? [])
            {
                if (SignedBy(evidence, rule))
                {
                    return new RuleMatch(rule, MatchKind.SignedProduct);
                }
            }
        }

        foreach (var rule in bySize ?? [])
        {
            if (SameBytes(evidence, rule))
            {
                return new RuleMatch(rule, MatchKind.UnsignedHash);
            }
        }

        // The claim did not hold up: same file name or folder or size, different publisher or bytes.
        // That is somebody else's program, and it is treated exactly like one.
        return RuleMatch.None;
    }

    /// <summary>
    /// The signed family rules whose folder contains a path, nearest root first.
    /// </summary>
    /// <remarks>
    /// Walks the ancestors as spans of the path rather than as new strings. This runs for every
    /// connection on the machine once any signed family rule exists, most of them from applications no
    /// rule is about; allocating a string per ancestor cost about a kilobyte of garbage per connection,
    /// measured, for nothing.
    /// </remarks>
    private List<AppRule>? FindScopedFamily(string path)
    {
        var lookup = _signedByRoot.GetAlternateLookup<ReadOnlySpan<char>>();
        var ancestor = path.AsSpan();
        List<AppRule>? found = null;

        for (var step = 0; step < ExecutablePath.AncestorWalkLimit; step++)
        {
            var separator = ancestor.LastIndexOf('\\');

            // A drive or share root is never a family root (ADR W-0003), so the walk stops above it.
            if (separator <= 2)
            {
                break;
            }

            ancestor = ancestor[..separator];
            if (!lookup.TryGetValue(ancestor, out var root, out var scoped))
            {
                continue;
            }

            foreach (var candidate in scoped)
            {
                if (ExecutablePath.IsInFamilyScope(path, root, candidate.Below))
                {
                    (found ??= []).Add(candidate.Rule);
                }
            }

            if (found is not null)
            {
                return found;
            }
        }

        return null;
    }

    private RuleMatch MatchPath(string executablePath)
    {
        if (_exactRules.TryGetValue(executablePath, out var exact))
        {
            return new RuleMatch(exact, MatchKind.PathExact);
        }

        // Before the ancestor walk: a packaged application's ancestors are WindowsApps and above,
        // which no rule may ever be rooted at, so walking them for it would always come up empty.
        if (_packageRules.Count > 0)
        {
            var family = PackagePath.Family(executablePath);

            if (family.Length > 0 && _packageRules.TryGetValue(family, out var packaged))
            {
                return new RuleMatch(packaged, MatchKind.PathPackage);
            }
        }

        if (_familyRules.Count == 0)
        {
            return RuleMatch.None;
        }

        foreach (var ancestor in ExecutablePath.Ancestors(executablePath))
        {
            if (_familyRules.TryGetValue(ancestor, out var family))
            {
                return new RuleMatch(family, MatchKind.PathFamily);
            }
        }

        return RuleMatch.None;
    }

    private static bool SignedBy(ImageEvidence evidence, AppRule rule) =>
        evidence.Signature == SignatureStatus.Valid &&
        !string.IsNullOrEmpty(evidence.SignerSubject) &&
        string.Equals(evidence.SignerSubject, rule.Identity.SignerSubject, StringComparison.Ordinal);

    /// <summary>
    /// Whether the product matches, where the rule names one. A rule captured from a binary with no
    /// version resource names none and accepts any; a publisher that adds one in an update keeps its
    /// rule.
    /// </summary>
    private static bool SameProduct(ImageEvidence evidence, AppRule rule) =>
        string.IsNullOrEmpty(rule.Identity.ProductName) ||
        ProductFamily.Same(rule.Identity.ProductName, evidence.ProductName);

    /// <summary>
    /// Whether the name the binary was built with matches: the signed original file name where the rule
    /// recorded one, otherwise the program database name. A copy renamed to the selected binary's name
    /// keeps both of the names it was built with.
    /// </summary>
    private static bool SameOriginalName(ImageEvidence evidence, AppRule rule)
    {
        if (!string.IsNullOrEmpty(rule.Identity.OriginalFileName))
        {
            return string.Equals(rule.Identity.OriginalFileName, evidence.OriginalFileName, StringComparison.OrdinalIgnoreCase);
        }

        return string.IsNullOrEmpty(rule.Identity.DebugName) ||
               string.Equals(rule.Identity.DebugName, evidence.DebugName, StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameBytes(ImageEvidence evidence, AppRule rule) =>
        !string.IsNullOrEmpty(evidence.Sha256) &&
        string.Equals(evidence.Sha256, rule.Identity.FileSha256, StringComparison.OrdinalIgnoreCase);

    private static AppRule? First(List<AppRule>? rules) => rules is { Count: > 0 } ? rules[0] : null;

    private static bool AllDirect(AppRule? pin, params List<AppRule>?[] groups)
    {
        if (pin is not null && pin.EffectiveAction != RouteAction.Direct)
        {
            return false;
        }

        foreach (var group in groups)
        {
            foreach (var rule in group ?? [])
            {
                if (rule.EffectiveAction != RouteAction.Direct)
                {
                    return false;
                }
            }
        }

        return true;
    }

    private void AddPath(AppRule rule, string key)
    {
        _activeRules++;
        _exactRules[key] = rule;

        // Packaged applications are keyed on what survives their updates rather than on the
        // path they happened to be installed at when the rule was made.
        if (rule.UsesPackageMatching)
        {
            _packageRules[rule.Identity.PackageFamily] = rule;
            _packageRuleCount++;
            return;
        }

        if (!rule.UsesFamilyMatching)
        {
            return;
        }

        var root = ExecutablePath.FamilyRoot(key);

        // Belt and braces. `UsesFamilyMatching` already consults `IsSafeFamilyRoot`; repeating
        // it here means no future edit to that property can put `C:\Windows\System32` into the
        // family table, which would proxy the operating system.
        if (!string.IsNullOrEmpty(root) && ExecutablePath.IsSafeFamilyRoot(root))
        {
            _familyRules[root] = rule;
        }
    }

    private void AddPackage(AppRule rule)
    {
        var family = rule.Identity.PackageFamilyName;
        if (string.IsNullOrWhiteSpace(family))
        {
            return;
        }

        _activeRules++;
        _identityRules++;
        PackageIdentityCount++;
        _packageRuleCount++;
        Append(_packageIdentities, family.Trim(), rule);
    }

    private void AddSigned(AppRule rule, string key)
    {
        var identity = rule.Identity;

        // A signed identity with no publisher would match any valid signature. The validator marks such
        // a rule for re-selection; this refuses it again at the last point before the hot path.
        if (string.IsNullOrEmpty(identity.SignerSubject) || string.IsNullOrEmpty(identity.BinaryName))
        {
            return;
        }

        _activeRules++;
        _identityRules++;
        if (!_isManagedTier)
        {
            _pins[key] = rule;
        }
        Append(_signedByBinary, identity.BinaryName, rule);

        if (!rule.UsesFamilyMatching)
        {
            return;
        }

        var (root, below) = ExecutablePath.FamilyScope(key);

        // The same guard as a path family, for the same reason: a signed family rooted at System32
        // would be every binary Microsoft signs there.
        if (!string.IsNullOrEmpty(root) && ExecutablePath.IsSafeFamilyRoot(root))
        {
            if (!_signedByRoot.TryGetValue(root, out var scoped))
            {
                scoped = [];
                _signedByRoot[root] = scoped;
            }

            scoped.Add(new ScopedRule(rule, below));
        }

        if (ProductFamily.CanRootFamily(identity.ProductName, identity.SignerSubject))
        {
            Append(_signedByProduct, ProductFamily.Normalize(identity.ProductName), rule);
        }
    }

    private void AddUnsigned(AppRule rule, string key)
    {
        if (string.IsNullOrEmpty(rule.Identity.FileSha256))
        {
            return;
        }

        _activeRules++;
        _identityRules++;
        if (!_isManagedTier)
        {
            _pins[key] = rule;
        }

        if (rule.Identity.FileSize is > 0 and var size)
        {
            Append(_unsignedBySize, size, rule);
        }
    }

    /// <summary>A signed family rule and the part of its install root it covers.</summary>
    private readonly record struct ScopedRule(AppRule Rule, string? Below);

    private static void Append<TKey>(Dictionary<TKey, List<AppRule>> table, TKey key, AppRule rule)
        where TKey : notnull
    {
        if (!table.TryGetValue(key, out var list))
        {
            list = [];
            table[key] = list;
        }

        list.Add(rule);
    }
}

/// <summary>
/// Decides which lane a flow belongs in.
/// </summary>
/// <remarks>
/// Pure and synchronous by design: no I/O, no locking, no async. Concurrency is handled one level up
/// by the engine runtime, which swaps whole snapshots; this type only ever reads one.
/// </remarks>
public sealed class RuleEngine
{
    /// <summary>Builds an engine over a prepared snapshot.</summary>
    public RuleEngine(RuleSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        Snapshot = snapshot;
    }

    /// <summary>Builds an engine over a configuration, preparing the snapshot.</summary>
    public RuleEngine(RuntimeConfiguration configuration)
        : this(new RuleSnapshot(configuration))
    {
    }

    /// <summary>The tables this engine reads.</summary>
    public RuleSnapshot Snapshot { get; }

    /// <summary>The routing decision for a flow.</summary>
    public RouteDecision Decide(in FlowDescriptor flow) => Decide(flow, out _);

    /// <summary>
    /// The routing decision for a flow, and the rule behind it.
    /// </summary>
    /// <remarks>
    /// Order matters, and each early return encodes a rule from the threat model:
    /// <list type="number">
    /// <item>Engine's own traffic goes DIRECT, always. Without this the upstream connection would be
    /// re-diverted into the engine and loop, which is the one failure mode that takes the machine's
    /// networking with it.</item>
    /// <item>Routing disabled goes DIRECT. A paused SplitLane must be inert, not half-active.</item>
    /// <item>Local destination goes DIRECT, for every app. Second layer of loop defence.</item>
    /// <item>Unidentified source goes DIRECT. A process that could not be resolved is not a
    /// selected app.</item>
    /// <item>A process that claims to be a selected application, while the claim is being verified, is
    /// BLOCKED - held, not refused for good: the engine re-decides when the answer arrives.</item>
    /// <item>A file at a rule's recorded location that is no longer that application is BLOCKED.</item>
    /// <item>No rule goes DIRECT. The product's default.</item>
    /// <item>A rule's lane applies: DIRECT, BLOCK, or PROXY - with UDP refused rather than proxied when
    /// UDP relaying is off, and never sent DIRECT instead.</item>
    /// </list>
    /// </remarks>
    public RouteDecision Decide(in FlowDescriptor flow, out AppRule? matchedRule)
    {
        matchedRule = null;

        if (flow.IsEngineTraffic)
        {
            return new RouteDecision(RouteAction.Direct, RouteReasonKind.EngineSelfTraffic);
        }

        if (!Snapshot.IsRoutingEnabled)
        {
            return new RouteDecision(RouteAction.Direct, RouteReasonKind.RoutingDisabled);
        }

        if (flow.HasLocalDestination)
        {
            return new RouteDecision(RouteAction.Direct, RouteReasonKind.LocalDestination);
        }

        var path = flow.ExecutablePath;
        if (string.IsNullOrEmpty(path))
        {
            return new RouteDecision(RouteAction.Direct, RouteReasonKind.UnidentifiedSource);
        }

        var evidence = flow.Image ?? ImageEvidence.FromPath(path);
        var match = Snapshot.Match(evidence);

        if (match.Needs != EvidenceNeeds.None)
        {
            return new RouteDecision(
                RouteAction.Block, RouteReasonKind.IdentityPending, match.Rule?.Id, path, match.Needs);
        }

        if (match.Mismatched is { } stale)
        {
            matchedRule = stale;

            // A rule that sends its application DIRECT asks for nothing to be done to it, so there is
            // nothing to protect by refusing whatever now sits in its place.
            var refused = stale.EffectiveAction == RouteAction.Direct ? RouteAction.Direct : RouteAction.Block;
            return new RouteDecision(refused, RouteReasonKind.IdentityMismatch, stale.Id, path);
        }

        if (match.Rule is not { } rule)
        {
            return RouteDecision.DirectDefault;
        }

        matchedRule = rule;

        var reason = match.Kind switch
        {
            MatchKind.PathExact => RouteReasonKind.ExactRule,
            MatchKind.PathFamily or MatchKind.PathPackage => RouteReasonKind.ExecutableFamilyRule,
            MatchKind.PackageBinary or MatchKind.PackageFamily => RouteReasonKind.PackageRule,
            MatchKind.SignedExact or MatchKind.SignedPinned => RouteReasonKind.SignedIdentityRule,
            MatchKind.SignedLocation or MatchKind.SignedProduct => RouteReasonKind.SignedFamilyRule,
            MatchKind.UnsignedHash => RouteReasonKind.FileHashRule,
            _ => RouteReasonKind.ExactRule,
        };

        var ruleKey = rule.Identity.ExecutablePath;

        switch (rule.EffectiveAction)
        {
            case RouteAction.Direct:
                return new RouteDecision(RouteAction.Direct, reason, ruleKey, path);

            case RouteAction.Block:
                return new RouteDecision(RouteAction.Block, reason, ruleKey, path);

            case RouteAction.Proxy:
                // A selected app's UDP goes through the proxy when the proxy will carry it, and is
                // refused when it will not. What it never does is go out unproxied: returning DIRECT
                // here would be the silent bypass the whole design exists to prevent.
                //
                // Refusing used to be the only answer, on the reasoning that QUIC fails closed and
                // falls back to TCP. True for QUIC, and no help at all to anything with no TCP path -
                // Discord voice waits on "Connecting to RTC" forever, because there is no second way
                // for it to try.
                if (flow.Protocol == FlowProtocol.Udp && !Snapshot.ProxiesUdp)
                {
                    return new RouteDecision(
                        RouteAction.Block, RouteReasonKind.UdpNotSupported, ruleKey, path);
                }

                return new RouteDecision(RouteAction.Proxy, reason, ruleKey, path);

            default:
                return RouteDecision.DirectDefault;
        }
    }
}
