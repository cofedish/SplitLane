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
                Raise(nameof(WarningText));
            }
        }
    }

    /// <summary>Whether this rule needs the user's attention.</summary>
    public bool HasWarning => ExecutableIsMissing || Identity.IsPackaged;

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
            if (ExecutableIsMissing)
            {
                return Identity.IsPackaged
                    ? "This executable is gone — the app has almost certainly been updated and now " +
                      "lives at a new versioned path. Its traffic is going DIRECT. Remove this rule " +
                      "and add the application again."
                    : "This executable is no longer on disk, so the rule matches nothing and its " +
                      "traffic is going DIRECT.";
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

    /// <summary>Whether this application can use family matching at all.</summary>
    /// <remarks>
    /// False for anything installed in a shared directory. The control is disabled rather than
    /// hidden, with the reason in its tooltip, because "why can I not turn this on" is a question
    /// worth answering in place (ADR W-0003).
    /// </remarks>
    public bool SupportsFamilyMatching => Identity.SupportsFamilyMatching;

    /// <summary>Explains the family-matching control, whether or not it is available.</summary>
    public string MatchTooltip => SupportsFamilyMatching
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
    public string MatchSummary => MatchMode == MatchMode.ExecutableFamily && SupportsFamilyMatching
        ? $"This executable and everything under {ExecutablePathHelper.FamilyRootDisplay(Identity)}"
        : "This executable only";

    /// <summary>Whether family matching is on.</summary>
    public bool IncludesFamily
    {
        get => MatchMode == MatchMode.ExecutableFamily;
        set => MatchMode = value ? MatchMode.ExecutableFamily : MatchMode.Exact;
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
