using SplitLane.App.Infrastructure;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.App.ViewModels;

/// <summary>One row in the Applications list.</summary>
public sealed class AppRuleViewModel : ObservableObject
{
    private readonly Action _changed;
    private RouteAction _action;
    private MatchMode _matchMode;
    private bool _familyRootExists = true;
    private bool _isEnabled;
    private bool _executableIsMissing;

    /// <summary>Wraps a stored rule.</summary>
    public AppRuleViewModel(AppRule rule, Action changed)
    {
        ArgumentNullException.ThrowIfNull(rule);

        Identity = rule.Identity;
        _action = rule.Action;
        _matchMode = rule.MatchMode;
        _isEnabled = rule.IsEnabled;
        _changed = changed ?? throw new ArgumentNullException(nameof(changed));
    }

    /// <summary>The application this rule is about.</summary>
    public AppIdentity Identity { get; }

    /// <summary>Name shown in the list.</summary>
    public string DisplayName => Identity.DisplayName;

    /// <summary>Full path, shown underneath.</summary>
    public string ExecutablePath => Identity.ExecutablePath;

    /// <summary>Publisher, or a plain statement that there is none.</summary>
    public string PublisherLabel => Identity.Publisher ?? "Unsigned";

    /// <summary>
    /// Whether the executable this rule names is no longer on disk.
    /// </summary>
    /// <remarks>
    /// Set by the page when it loads, not computed here: the check is file I/O and a view model
    /// property is read repeatedly by the binding engine.
    /// </remarks>
    public bool ExecutableIsMissing
    {
        get => _executableIsMissing;
        set
        {
            if (Set(ref _executableIsMissing, value))
            {
                Raise(nameof(HasWarning));
                Raise(nameof(HasStoppedMatching));
                Raise(nameof(WarningText));
            }
        }
    }

    /// <summary>
    /// Whether the family this rule covers still exists, when it matches by family.
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
                Raise(nameof(HasWarning));
                Raise(nameof(HasStoppedMatching));
                Raise(nameof(WarningText));
            }
        }
    }

    private bool StillMatchesByFamily =>
        MatchMode == MatchMode.ExecutableFamily && SupportsFamilyMatching && FamilyRootExists;

    /// <summary>
    /// Whether this rule now matches nothing at all.
    /// </summary>
    /// <remarks>
    /// The condition the product's central promise turns on: a selected application whose rule no
    /// longer matches is going DIRECT, and nothing else in the interface would say so.
    /// </remarks>
    public bool HasStoppedMatching => ExecutableIsMissing && !StillMatchesByFamily;

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

    /// <summary>Whether this rule needs the user's attention.</summary>
    /// <remarks>
    /// A packaged application used to warn unconditionally, because an exact rule on one was
    /// guaranteed to stop matching at its next update. Matched by package family it survives them,
    /// so there is nothing left to warn about - and a warning that stays after its cause is fixed
    /// teaches people to ignore warnings.
    /// </remarks>
    public bool HasWarning => HasStoppedMatching || (Identity.IsPackaged && !MatchesByPackage);

    /// <summary>
    /// What is wrong, in the order that matters.
    /// </summary>
    /// <remarks>
    /// A missing executable is reported before the packaged-path caveat, because for a packaged
    /// application the missing file is usually the caveat having already come true.
    /// </remarks>
    public string WarningText
    {
        get
        {
            if (ExecutableIsMissing && !StillMatchesByFamily)
            {
                return Identity.IsPackaged
                    ? "This executable is gone — the app has almost certainly been updated and now " +
                      "lives at a new versioned path. Its traffic is going DIRECT. Remove this rule " +
                      "and add the application again."
                    : "This executable is no longer on disk, so the rule matches nothing and its " +
                      "traffic is going DIRECT.";
            }

            if (Identity.SupportsPackageMatching)
            {
                return "Packaged app: the path contains a version, so this rule matches only the " +
                       "version installed now. Turn on Include folder to match it by package " +
                       "instead, which survives its updates.";
            }


            return Identity.VersionedSegment is { } segment
                ? $"Packaged app: the path contains a version ({segment}), so it will change on the " +
                  "next update and this rule will silently stop matching."
                : "Packaged app: its install path contains a version, so it will change on the next " +
                  "update and this rule will silently stop matching.";
        }
    }

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
                _changed();
            }
        }
    }

    /// <summary>How the path is matched.</summary>
    public MatchMode MatchMode
    {
        get => _matchMode;
        set
        {
            if (Set(ref _matchMode, value))
            {
                Raise(nameof(MatchesByPackage));
                Raise(nameof(HasWarning));
                Raise(nameof(WarningText));
                Raise(nameof(MatchSummary));
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
                _changed();
            }
        }
    }

    /// <summary>
    /// Whether the helpers control can be turned on at all.
    /// </summary>
    /// <remarks>
    /// Two different mechanisms sit behind one checkbox, because to the person using it they are one
    /// idea: cover the rest of this application, not only the file I picked. An ordinary application
    /// gets its install directory; a packaged one gets its package family, since its directory is
    /// shared with every other packaged application on the machine. False only for an application
    /// that can have neither - one installed loose in a shared folder (ADR W-0003) - and the control
    /// is disabled rather than hidden, with the reason in its tooltip.
    /// </remarks>
    public bool SupportsFamilyMatching =>
        Identity.SupportsFamilyMatching || Identity.SupportsPackageMatching;

    /// <summary>Explains the family-matching control, whether or not it is available.</summary>
    public string MatchTooltip => Identity.SupportsPackageMatching
        ? "Also route this application's other processes, and keep routing it after it updates. " +
          "A packaged application installs each version in a new folder, so matching the folder " +
          "alone would stop working at the next update."
        : SupportsFamilyMatching
            ? $"Also route anything else installed under {Identity.FamilyRoot}."
            : $"{Identity.FamilyRoot} is shared with unrelated programs, so family matching is not " +
              "available for this application — it would put every program in that folder into the proxy lane.";

    /// <summary>The word that says which lane this is, which is the thing to read.</summary>
    public string LaneLabel => !IsEnabled ? "OFF" : Action switch
    {
        RouteAction.Proxy => "PROXY",
        RouteAction.Block => "BLOCKED",
        _ => "DIRECT",
    };

    /// <summary>Whether the row should read as being in the proxy lane.</summary>
    public bool IsProxied => IsEnabled && Action == RouteAction.Proxy;

    /// <summary>One line describing what the rule covers.</summary>
    public string MatchSummary =>
        MatchesByPackage ? "Every version of this packaged application"
        : MatchMode == MatchMode.ExecutableFamily && Identity.SupportsFamilyMatching
            ? $"This executable and everything under {ExecutablePathHelper.FamilyRootDisplay(Identity)}"
            : "This executable only";

    /// <summary>Whether the rule covers more than the one executable it names.</summary>
    /// <remarks>
    /// Which mechanism that means depends on the application: a packaged one is matched by package
    /// family, everything else by install directory. The checkbox does not ask the user to know the
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

    /// <summary>Builds the stored form.</summary>
    public AppRule ToRule() => new()
    {
        Identity = Identity,
        Action = Action,
        MatchMode = MatchMode,
        IsEnabled = IsEnabled,
    };
}

/// <summary>Presentation helpers for paths, kept out of the view model proper.</summary>
internal static class ExecutablePathHelper
{
    /// <summary>The family root, shortened to its last segment when the full path is long.</summary>
    public static string FamilyRootDisplay(AppIdentity identity)
    {
        var root = identity.FamilyRoot;
        return root.Length <= 48 ? root : "…" + root[^47..];
    }

    /// <summary>Shortens a path from the left so the file name stays readable.</summary>
    public static string Shorten(string path, int maxLength = 64)
    {
        var normalized = ExecutablePath.Normalize(path);
        return normalized.Length <= maxLength ? normalized : "…" + normalized[^(maxLength - 1)..];
    }
}
