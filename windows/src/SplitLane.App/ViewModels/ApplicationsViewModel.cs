using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using SplitLane.App.Infrastructure;
using SplitLane.App.Services;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;

namespace SplitLane.App.ViewModels;

/// <summary>The Applications page: which programs are in the proxy lane.</summary>
public sealed class ApplicationsViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private string _filter = string.Empty;
    private bool _isPickerOpen;
    private bool _isScanning;
    private string _pickerFilter = string.Empty;

    /// <summary>Builds the page.</summary>
    public ApplicationsViewModel(MainViewModel main)
    {
        _main = main ?? throw new ArgumentNullException(nameof(main));

        OpenPickerCommand = new AsyncRelayCommand(OpenPickerAsync);
        ClosePickerCommand = new RelayCommand(() => IsPickerOpen = false);
        BrowseCommand = new RelayCommand(Browse);
        AddCandidateCommand = new RelayCommand(parameter =>
        {
            if (parameter is ApplicationCandidate candidate)
            {
                // Re-describe with the signature, which the bulk scan skipped for speed.
                Add(ApplicationInspector.Describe(candidate.Identity.ExecutablePath, candidate.DisplayName));

                // The picker stays open so several can be added in one go, which only works if what
                // was just added stops being offered.
                Raise(nameof(VisibleCandidates));
            }
        });
        RemoveCommand = new RelayCommand(parameter =>
        {
            if (parameter is AppRuleViewModel rule)
            {
                Rules.Remove(rule);
                _main.MarkDirty();
                RaiseCounts();
            }
        });
    }

    /// <summary>The configured rules.</summary>
    public ObservableCollection<AppRuleViewModel> Rules { get; } = [];

    /// <summary>Rules matching the search box.</summary>
    public IEnumerable<AppRuleViewModel> VisibleRules => string.IsNullOrWhiteSpace(Filter)
        ? Rules
        : Rules.Where(rule =>
            rule.DisplayName.Contains(Filter, StringComparison.OrdinalIgnoreCase) ||
            rule.ExecutablePath.Contains(Filter, StringComparison.OrdinalIgnoreCase));

    /// <summary>Running applications offered by the picker.</summary>
    public ObservableCollection<ApplicationCandidate> Candidates { get; } = [];

    /// <summary>
    /// Candidates matching the picker's search box, minus anything already routed.
    /// </summary>
    /// <remarks>
    /// Offering an application that is already in the list invites a second click that can only
    /// produce "it is already in the list", and leaves the picker looking like it did nothing. What
    /// counts as already routed includes being covered by somebody else's family rule: an Electron
    /// application's helpers all sit under one root, and listing five of them under a rule that
    /// already matches all five is noise.
    /// </remarks>
    public IEnumerable<ApplicationCandidate> VisibleCandidates =>
        Candidates.Where(candidate => !IsAlreadyRouted(candidate) &&
            (string.IsNullOrWhiteSpace(PickerFilter) ||
             candidate.DisplayName.Contains(PickerFilter, StringComparison.OrdinalIgnoreCase) ||
             candidate.Path.Contains(PickerFilter, StringComparison.OrdinalIgnoreCase)));

    private bool IsAlreadyRouted(ApplicationCandidate candidate)
    {
        var path = candidate.Identity.ExecutablePath;

        foreach (var rule in Rules)
        {
            if (ExecutablePath.Comparer.Equals(rule.ExecutablePath, path))
            {
                return true;
            }

            if (rule.MatchMode == MatchMode.ExecutableFamily &&
                rule.SupportsFamilyMatching &&
                ExecutablePath.IsUnderFamilyRoot(path, rule.Identity.FamilyRoot))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Opens the running-applications picker.</summary>
    public AsyncRelayCommand OpenPickerCommand { get; }

    /// <summary>Closes the picker.</summary>
    public RelayCommand ClosePickerCommand { get; }

    /// <summary>Picks an executable from disk.</summary>
    public RelayCommand BrowseCommand { get; }

    /// <summary>Adds a candidate from the picker.</summary>
    public RelayCommand AddCandidateCommand { get; }

    /// <summary>Removes a rule.</summary>
    public RelayCommand RemoveCommand { get; }

    /// <summary>Search text for the rule list.</summary>
    public string Filter
    {
        get => _filter;
        set
        {
            if (Set(ref _filter, value))
            {
                Raise(nameof(VisibleRules));
                Raise(nameof(IsEmpty));
            }
        }
    }

    /// <summary>Search text for the picker.</summary>
    public string PickerFilter
    {
        get => _pickerFilter;
        set
        {
            if (Set(ref _pickerFilter, value))
            {
                Raise(nameof(VisibleCandidates));
            }
        }
    }

    /// <summary>Whether the picker overlay is showing.</summary>
    public bool IsPickerOpen
    {
        get => _isPickerOpen;
        set => Set(ref _isPickerOpen, value);
    }

    /// <summary>Whether the running-process scan is in flight.</summary>
    public bool IsScanning
    {
        get => _isScanning;
        private set => Set(ref _isScanning, value);
    }

    /// <summary>True when there is nothing to show, so the empty state can be shown instead.</summary>
    public bool IsEmpty => !VisibleRules.Any();

    /// <summary>How many rules currently route to the proxy.</summary>
    public int ProxiedCount => Rules.Count(rule => rule.IsProxied);

    /// <summary>Summary line above the list.</summary>
    public string Summary => Rules.Count == 0
        ? "No applications selected — everything on this machine is DIRECT."
        : $"{ProxiedCount} of {Rules.Count} in the proxy lane. Everything else is DIRECT.";

    /// <summary>
    /// How many rules have actually stopped matching anything.
    /// </summary>
    /// <remarks>
    /// Not simply "the executable is gone". A self-updating application deletes the build it was
    /// selected in and runs from a new directory beside it, which a family rule follows - the named
    /// file is missing and the rule is working. Counting those raised a banner telling the user to
    /// go and repair rules that were routing traffic correctly.
    /// </remarks>
    public int StaleCount => Rules.Count(rule => rule.HasStoppedMatching);

    /// <summary>Whether to raise the banner about rules that have stopped matching.</summary>
    public bool HasStaleRules => StaleCount > 0;

    /// <summary>What the stale-rule banner says.</summary>
    public string StaleSummary => StaleCount == 1
        ? "One rule names an executable that is no longer on disk. It matches nothing, so that application is going DIRECT."
        : $"{StaleCount} rules name executables that are no longer on disk. They match nothing, so those applications are going DIRECT.";

    /// <summary>Rebuilds the list from a configuration.</summary>
    /// <remarks>
    /// Each rule's executable is checked against the disk here, once per load. A rule whose binary
    /// has gone matches nothing, so the application it names is quietly going DIRECT — the failure
    /// this product exists to prevent, and one nothing else would report (W-4).
    /// </remarks>
    public void LoadFrom(RuntimeConfiguration configuration)
    {
        Rules.Clear();

        foreach (var rule in configuration.Rules)
        {
            var row = new AppRuleViewModel(rule, OnRuleChanged);

            try
            {
                row.ExecutableIsMissing = !File.Exists(row.ExecutablePath);

                // Asked separately, because for a self-updating application the two answers differ:
                // the named executable is gone and the family it belongs to is still there, being
                // matched, working. Reporting only the first sends someone to repair that.
                var familyRoot = row.Identity.FamilyRoot;
                row.FamilyRootExists = !string.IsNullOrEmpty(familyRoot) && Directory.Exists(familyRoot);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                // An unreadable path is not evidence the file is gone, and claiming it is would send
                // the user chasing a rule that works.
                row.ExecutableIsMissing = false;
                row.FamilyRootExists = true;
            }

            Rules.Add(row);
        }

        RaiseCounts();
    }

    /// <summary>Collects the rules for saving.</summary>
    public IReadOnlyList<AppRule> ToRules() => [.. Rules.Select(rule => rule.ToRule())];

    /// <summary>Adds an application, or reports that it is already listed.</summary>
    public void Add(AppIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (Rules.Any(rule => ExecutablePath.Comparer.Equals(rule.ExecutablePath, identity.ExecutablePath)))
        {
            _main.SetBanner($"{identity.DisplayName} is already in the list.");
            return;
        }

        // Broad matching is the default wherever it is both possible and safe.
        //
        // Packaged applications are checked first, and not as a special case: their install
        // directory carries a version, so an exact rule on one is guaranteed to stop matching at
        // the next update, and family matching cannot save it because the directory above is
        // shared with every other packaged application (ADR W-0003).
        var mode = identity.SupportsPackageMatching
            ? MatchMode.PackageFamily
            : identity.SupportsFamilyMatching
                ? MatchMode.ExecutableFamily
                : MatchMode.Exact;

        Rules.Add(new AppRuleViewModel(
            new AppRule { Identity = identity, Action = RouteAction.Proxy, MatchMode = mode },
            OnRuleChanged));

        _main.MarkDirty();
        RaiseCounts();

        if (mode == MatchMode.PackageFamily)
        {
            _main.SetBanner(
                $"{identity.DisplayName} added. It is a packaged app, so it is matched by package " +
                "rather than by path — the rule survives its updates.");
        }
        else if (identity.IsPackaged)
        {
            _main.SetBanner(
                $"{identity.DisplayName} added. It is a packaged app, so its install path contains a " +
                "version and will change on the next update — the rule will need re-adding then.");
        }
        else
        {
            _main.SetBanner(identity.SupportsFamilyMatching
                ? $"{identity.DisplayName} added to the proxy lane."
                : $"{identity.DisplayName} added. Its folder is shared with other programs, so it is " +
                  "matched exactly rather than by folder.");
        }
    }

    private async Task OpenPickerAsync()
    {
        IsPickerOpen = true;
        PickerFilter = string.Empty;
        IsScanning = true;

        try
        {
            // Enumerating every process and reading its version resource takes long enough to drop
            // frames on a busy machine, so it happens off the UI thread.
            var found = await Task.Run(ApplicationInspector.RunningApplications).ConfigureAwait(true);

            Candidates.Clear();
            foreach (var candidate in found)
            {
                Candidates.Add(candidate);
            }

            Raise(nameof(VisibleCandidates));
        }
        finally
        {
            IsScanning = false;
        }
    }

    private void Browse()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select an application",
            Filter = "Applications (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        };

        if (dialog.ShowDialog(Application.Current.MainWindow) == true)
        {
            Add(ApplicationInspector.Describe(dialog.FileName));
            IsPickerOpen = false;
        }
    }

    private void OnRuleChanged()
    {
        _main.MarkDirty();
        RaiseCounts();
    }

    private void RaiseCounts()
    {
        Raise(nameof(VisibleRules));
        Raise(nameof(IsEmpty));
        Raise(nameof(ProxiedCount));
        Raise(nameof(Summary));
        Raise(nameof(StaleCount));
        Raise(nameof(HasStaleRules));
        Raise(nameof(StaleSummary));
    }
}
