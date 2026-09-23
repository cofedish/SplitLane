using SplitLane.App.Infrastructure;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.App.ViewModels;

/// <summary>One row in the Applications list.</summary>
public sealed class AppRuleViewModel : ObservableObject
{
    private readonly Action _changed;
    private AppIdentity _identity;
    private RouteAction _action;
    private MatchMode _matchMode;
    private bool _isEnabled;
    private RuleStatus _status;
    private string? _statusDetail;
    private bool _familyRootExists = true;
    private bool _executableIsMissing;
    private bool _identityChanged;

    /// <summary>Wraps a stored rule.</summary>
    public AppRuleViewModel(AppRule rule, Action changed)
    {
        ArgumentNullException.ThrowIfNull(rule);

        _identity = rule.Identity;
        _action = rule.Action;
        _matchMode = rule.MatchMode;
        _isEnabled = rule.IsEnabled;
        _status = rule.Status;
        _statusDetail = rule.StatusDetail;
        Note = rule.Note;
        _changed = changed ?? throw new ArgumentNullException(nameof(changed));
    }

    /// <summary>The application this rule is about.</summary>
    /// <remarks>Replaced only by <see cref="Reselect"/> and <see cref="AdoptMigrated"/>.</remarks>
    public AppIdentity Identity => _identity;

    /// <summary>Name shown in the list.</summary>
    public string DisplayName => Identity.DisplayName;

    /// <summary>Full path, shown underneath.</summary>
    public string ExecutablePath => Identity.ExecutablePath;

    /// <summary>The user's note. Not edited here, and carried through every save.</summary>
    public string? Note { get; }

    /// <summary>Whether the rule can route, or is waiting to be selected again.</summary>
    public RuleStatus Status => _status;

    /// <summary>Why it is waiting, or what migration changed; plain language.</summary>
    public string? StatusDetail => _statusDetail;

    /// <summary>
    /// Whether nothing is at the path this rule was picked from.
    /// </summary>
    /// <remarks>
    /// Set by the page when it loads, not computed here: the check is file I/O and a view model
    /// property is read repeatedly by the binding engine. Only a schema 1 rule treats this as a fault;
    /// every other kind recognises its application wherever it went.
    /// </remarks>
    public bool ExecutableIsMissing
    {
        get => _executableIsMissing;
        set
        {
            if (Set(ref _executableIsMissing, value))
            {
                RaiseAdvice();
            }
        }
    }

    /// <summary>
    /// Whether the directory a schema 1 family rule is rooted at still exists.
    /// </summary>
    /// <remarks>
    /// Set by the page alongside <see cref="ExecutableIsMissing"/>, and it changes what a missing
    /// executable means. A self-updating application leaves its old build behind and runs from a new
    /// directory beside it; a family rule follows it there, so the named executable being gone is
    /// not a fault, and saying it is would send someone to fix a rule that is working.
    /// </remarks>
    public bool FamilyRootExists
    {
        get => _familyRootExists;
        set
        {
            if (Set(ref _familyRootExists, value))
            {
                RaiseAdvice();
            }
        }
    }

    /// <summary>
    /// Whether the file at the recorded path is there and is no longer this rule's application.
    /// </summary>
    /// <remarks>
    /// Set by the page after it has read the file, off the UI thread. The engine refuses such a file's
    /// connections rather than routing them either way (<see cref="RouteReasonKind.IdentityMismatch"/>),
    /// and a refusal nobody can see from here looks exactly like a broken proxy.
    /// </remarks>
    public bool IdentityChanged
    {
        get => _identityChanged;
        set
        {
            if (Set(ref _identityChanged, value))
            {
                RaiseAdvice();
            }
        }
    }

    /// <summary>The one thing this row should say, worked out from the rule and what the page observed.</summary>
    public RuleAdvice Advice =>
        RulePresentation.Advise(ToRule(), new RuleObservation(ExecutableIsMissing, FamilyRootExists, IdentityChanged));

    /// <summary>How loudly <see cref="AdviceText"/> should be shown.</summary>
    public RuleAttention Attention => Advice.Attention;

    /// <summary>What is wrong, or worth knowing, in the order that matters.</summary>
    public string AdviceText => Advice.Text;

    /// <summary>Whether there is anything to say at all.</summary>
    public bool HasAdvice => Advice.Attention != RuleAttention.None;

    /// <summary>Whether this row needs the user's attention, as opposed to only informing them.</summary>
    public bool HasWarning => Advice.Attention is RuleAttention.Warning or RuleAttention.Stopped;

    /// <summary>
    /// Whether this rule now matches nothing, or its application's connections are being refused.
    /// </summary>
    /// <remarks>
    /// The condition the product's central promise turns on: a selected application whose rule no
    /// longer matches is going DIRECT, and nothing else in the interface would say so.
    /// </remarks>
    public bool HasStoppedMatching => Advice.Attention == RuleAttention.Stopped;

    /// <summary>Which condition the advice is about, so the page can count them separately.</summary>
    public RuleProblem Problem => Advice.Problem;

    /// <summary>Whether the row offers to pick the application again.</summary>
    public bool CanReselect => Advice.CanReselect;

    /// <summary>
    /// Whether this rule is matched by package family, and so survives the application's updates.
    /// </summary>
    /// <remarks>
    /// Asked of the rule itself rather than re-derived from the mode. The engine decides this by
    /// calling <see cref="AppRule.UsesPackageMatching"/>; a second copy of the reasoning here could
    /// disagree with it, and the visible form of that disagreement is a warning telling somebody to
    /// fix a rule that is already working - which is exactly what happened.
    /// </remarks>
    public bool MatchesByPackage => ToRule().UsesPackageMatching;

    /// <summary>How the application is recognised, in one line.</summary>
    public string IdentitySummary => RulePresentation.IdentitySummary(Identity);

    /// <summary>The identity in full, for the summary's tooltip.</summary>
    public string IdentityDetail => RulePresentation.IdentityDetail(Identity);

    /// <summary>The lane.</summary>
    public RouteAction Action
    {
        get => _action;
        set
        {
            if (Set(ref _action, value))
            {
                Raise(nameof(LaneLabel));
                Raise(nameof(IsProxied));
                RaiseAdvice();
                _changed();
            }
        }
    }

    /// <summary>How much of the application the rule covers.</summary>
    public MatchMode MatchMode
    {
        get => _matchMode;
        set
        {
            if (Set(ref _matchMode, value))
            {
                Raise(nameof(IncludesFamily));
                Raise(nameof(MatchesByPackage));
                Raise(nameof(MatchSummary));
                RaiseAdvice();
                _changed();
            }
        }
    }

    /// <summary>Whether the rule participates in routing.</summary>
    public bool IsEnabled
    {
        get => _isEnabled;
        set
        {
            if (Set(ref _isEnabled, value))
            {
                Raise(nameof(LaneLabel));
                Raise(nameof(IsProxied));
                RaiseAdvice();
                _changed();
            }
        }
    }

    /// <summary>
    /// Whether the helpers control can be turned on at all.
    /// </summary>
    /// <remarks>
    /// Several mechanisms sit behind one checkbox, because to the person using it they are one idea:
    /// cover the rest of this application, not only the file I picked. A signed application gets the
    /// same publisher's programs of its product or in its install directory; a packaged one gets its
    /// package; an older path rule gets its folder. False for an unsigned application, whose folder
    /// anyone could drop a file into, and for one whose folder is shared (ADR W-0003) - and the control
    /// is disabled rather than hidden, with the reason in its tooltip.
    /// </remarks>
    public bool SupportsFamilyMatching => RulePresentation.CanIncludeFamily(Identity);

    /// <summary>Explains the family-matching control, whether or not it is available.</summary>
    public string MatchTooltip => RulePresentation.MatchTooltip(Identity);

    /// <summary>The word that says which lane this is, which is the thing to read.</summary>
    /// <remarks>
    /// A rule waiting to be selected again reads OFF whatever its lane, because that is what it does:
    /// the engine routes nothing by it. Showing PROXY there would say the opposite of the warning below.
    /// </remarks>
    public string LaneLabel => !IsEnabled || _status == RuleStatus.NeedsReselection ? "OFF" : Action switch
    {
        RouteAction.Proxy => "PROXY",
        RouteAction.Block => "BLOCKED",
        _ => "DIRECT",
    };

    /// <summary>Whether the row should read as being in the proxy lane.</summary>
    public bool IsProxied => IsEnabled && _status == RuleStatus.Active && Action == RouteAction.Proxy;

    /// <summary>One line describing what the rule covers.</summary>
    public string MatchSummary => RulePresentation.MatchSummary(ToRule());

    /// <summary>Whether the rule covers more than the one executable it names.</summary>
    /// <remarks>
    /// Which mechanism that means depends on the application: a packaged one is matched by package
    /// family, everything else by publisher and folder. The checkbox does not ask the user to know the
    /// difference, and picking the wrong one for them would be the difference between a rule that
    /// survives an update and one that does not.
    /// </remarks>
    public bool IncludesFamily
    {
        get => MatchMode is MatchMode.ExecutableFamily or MatchMode.PackageFamily;
        set => MatchMode = value
            ? Identity.SupportsPackageMatching ? MatchMode.PackageFamily : MatchMode.ExecutableFamily
            : MatchMode.Exact;
    }

    /// <summary>
    /// Replaces the application this rule is about with a freshly picked one, keeping everything the
    /// user chose about it.
    /// </summary>
    /// <remarks>
    /// Lane, enabled state and note carry over unchanged. The match mode carries over as the user's
    /// intent - exact stays exact, "include helpers" becomes whatever means that for the new identity
    /// (<see cref="RulePresentation.ModeFor"/>) - because an unsigned file cannot have helpers at all,
    /// and a mode the validator would silently downgrade on the next load is a checkbox that lies.
    /// </remarks>
    public void Reselect(AppIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        _identity = identity;
        _matchMode = RulePresentation.ModeFor(identity, _matchMode);
        _status = RuleStatus.Active;
        _statusDetail = null;
        _identityChanged = false;
        _executableIsMissing = false;
        _familyRootExists = true;

        // Everything on the row is a function of the identity.
        Raise(string.Empty);
        _changed();
    }

    /// <summary>
    /// Takes the identity migration worked out for this row, without counting it as an edit.
    /// </summary>
    /// <remarks>
    /// Only the parts migration decides: identity, status, the note on what it did, and the mode when it
    /// had to narrow one (an unsigned application loses its family). Lane, enabled state and any
    /// edits the user made while migration ran stay as the user left them.
    /// </remarks>
    public void AdoptMigrated(AppRule migrated)
    {
        ArgumentNullException.ThrowIfNull(migrated);

        _identity = migrated.Identity;
        _status = migrated.Status;
        _statusDetail = migrated.StatusDetail;
        _identityChanged = false;

        // Narrowing is the only change migration makes to a mode, and only for an unsigned application.
        // Copying its mode across wholesale would undo a checkbox the user ticked while it ran.
        if (migrated.Identity.Kind == IdentityKind.Unsigned)
        {
            _matchMode = MatchMode.Exact;
        }

        Raise(string.Empty);
    }

    /// <summary>Builds the stored form.</summary>
    public AppRule ToRule() => new()
    {
        Identity = Identity,
        Action = Action,
        MatchMode = MatchMode,
        IsEnabled = IsEnabled,
        Note = Note,
        Status = Status,
        StatusDetail = StatusDetail,
    };

    private void RaiseAdvice()
    {
        Raise(nameof(Advice));
        Raise(nameof(Attention));
        Raise(nameof(AdviceText));
        Raise(nameof(HasAdvice));
        Raise(nameof(HasWarning));
        Raise(nameof(HasStoppedMatching));
        Raise(nameof(Problem));
        Raise(nameof(CanReselect));
    }
}
