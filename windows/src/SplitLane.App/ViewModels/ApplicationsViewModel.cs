using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using SplitLane.App.Infrastructure;
using SplitLane.App.Services;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Platform;

namespace SplitLane.App.ViewModels;

/// <summary>The Applications page: which programs are in the proxy lane.</summary>
public sealed class ApplicationsViewModel : ObservableObject
{
    private readonly MainViewModel _main;
    private string _filter = string.Empty;
    private bool _isPickerOpen;
    private bool _isScanning;
    private bool _isMigrating;
    private string _pickerFilter = string.Empty;
    private int _loadGeneration;

    /// <summary>Builds the page.</summary>
    public ApplicationsViewModel(MainViewModel main)
    {
        _main = main ?? throw new ArgumentNullException(nameof(main));

        OpenPickerCommand = new AsyncRelayCommand(OpenPickerAsync);
        ClosePickerCommand = new RelayCommand(() => IsPickerOpen = false);
        BrowseCommand = new AsyncRelayCommand(BrowseAsync);
        AddCandidateCommand = new AsyncRelayCommand(AddCandidateAsync);
        ReselectCommand = new AsyncRelayCommand(ReselectAsync);
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
    /// counts as already routed includes being covered by another rule's family: an Electron
    /// application's helpers all sit under one root, and listing five of them under a rule that
    /// already matches all five is noise.
    /// </remarks>
    public IEnumerable<ApplicationCandidate> VisibleCandidates =>
        Candidates.Where(candidate => !IsAlreadyRouted(candidate) &&
            (string.IsNullOrWhiteSpace(PickerFilter) ||
             candidate.DisplayName.Contains(PickerFilter, StringComparison.OrdinalIgnoreCase) ||
             candidate.Path.Contains(PickerFilter, StringComparison.OrdinalIgnoreCase)));

    /// <summary>
    /// Whether a running executable is already covered by a rule, as far as can be told without
    /// verifying it.
    /// </summary>
    /// <remarks>
    /// The scan reads no signatures, so this goes by where a candidate is and which package its token
    /// names - enough to hide the new build a self-updating application is running from, which a
    /// signed rule already follows, without hiding a same-named program from somewhere else.
    /// Browsing for the file is always still possible.
    /// </remarks>
    private bool IsAlreadyRouted(ApplicationCandidate candidate)
    {
        var path = candidate.Path;
        var package = candidate.PackageFamily;
        var fileName = ExecutablePath.FileName(path);

        foreach (var row in Rules)
        {
            if (ExecutablePath.Comparer.Equals(row.ExecutablePath, path))
            {
                return true;
            }

            var rule = row.ToRule();
            var identity = rule.Identity;

            switch (identity.Kind)
            {
                case IdentityKind.Package:
                    if (package.Length > 0 &&
                        string.Equals(package, identity.PackageFamilyName, StringComparison.OrdinalIgnoreCase) &&
                        (rule.UsesPackageMatching || ExecutablePath.Comparer.Equals(fileName, identity.BinaryName)))
                    {
                        return true;
                    }

                    break;

                case IdentityKind.Signed:
                    var (root, below) = ExecutablePath.FamilyScope(identity.ExecutablePath);
                    if (ExecutablePath.IsSafeFamilyRoot(root) &&
                        ExecutablePath.IsInFamilyScope(path, root, below) &&
                        (rule.UsesFamilyMatching || ExecutablePath.Comparer.Equals(fileName, identity.BinaryName)))
                    {
                        return true;
                    }

                    break;

                case IdentityKind.Path:
                    if ((rule.UsesPackageMatching && package.Length > 0 &&
                         string.Equals(package, identity.PackageFamily, StringComparison.OrdinalIgnoreCase)) ||
                        (rule.UsesFamilyMatching && ExecutablePath.IsUnderFamilyRoot(path, identity.FamilyRoot)))
                    {
                        return true;
                    }

                    break;
            }
        }

        return false;
    }

    /// <summary>Opens the running-applications picker.</summary>
    public AsyncRelayCommand OpenPickerCommand { get; }

    /// <summary>Closes the picker.</summary>
    public RelayCommand ClosePickerCommand { get; }

    /// <summary>Picks an executable from disk.</summary>
    public AsyncRelayCommand BrowseCommand { get; }

    /// <summary>Adds a candidate from the picker.</summary>
    public AsyncRelayCommand AddCandidateCommand { get; }

    /// <summary>Picks a rule's application again, replacing the identity it recorded.</summary>
    public AsyncRelayCommand ReselectCommand { get; }

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

    /// <summary>
    /// Whether rules recorded by path are being converted to identities in the background.
    /// </summary>
    /// <remarks>
    /// Said on the page, because until it finishes the rows show the old rules with their old
    /// warnings, and a warning that disappears a few seconds later with no explanation reads as a
    /// flicker rather than as something that was fixed.
    /// </remarks>
    public bool IsMigrating
    {
        get => _isMigrating;
        set => Set(ref _isMigrating, value);
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
    /// How many rules route nothing, or have their application's connections refused.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three conditions, each of which the engine acts on: a rule migration could not resolve, which
    /// routes nothing; a rule whose recorded file is now a different program, whose connections are
    /// refused; and an older path rule whose executable is gone.
    /// </para>
    /// <para>
    /// Not simply "the executable is gone". A signed or packaged application that updates leaves the
    /// path it was picked from, and its rule follows it - the named file is missing and the rule is
    /// working. Counting those raised a banner telling the user to go and repair rules that were
    /// routing traffic correctly.
    /// </para>
    /// </remarks>
    public int StaleCount => Rules.Count(rule => rule.HasStoppedMatching);

    /// <summary>Whether to raise the banner about rules that have stopped matching.</summary>
    public bool HasStaleRules => StaleCount > 0;

    /// <summary>What the stale-rule banner says, each condition counted and named separately.</summary>
    public string StaleSummary => RulePresentation.StaleSummary(
        CountStopped(RuleProblem.NeedsReselection),
        CountStopped(RuleProblem.IdentityChanged),
        CountStopped(RuleProblem.PathMissing));

    private int CountStopped(RuleProblem problem) =>
        Rules.Count(rule => rule.HasStoppedMatching && rule.Problem == problem);

    /// <summary>Rebuilds the list from a configuration.</summary>
    /// <remarks>
    /// <para>
    /// Each rule's recorded path is checked against the disk here, once per load. For an older path
    /// rule a missing binary means it matches nothing, so the application it names is quietly going
    /// DIRECT — the failure this product exists to prevent, and one nothing else would report (W-4).
    /// </para>
    /// <para>
    /// For a signed or unsigned rule the file at the recorded path is then read in the background, to
    /// find the case the engine refuses: something is there, and it is not the application.
    /// </para>
    /// </remarks>
    public void LoadFrom(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var generation = ++_loadGeneration;
        Rules.Clear();

        foreach (var rule in configuration.Rules)
        {
            var row = new AppRuleViewModel(rule, OnRuleChanged);
            Observe(row);
            Rules.Add(row);
        }

        RaiseCounts();
        _ = CheckRecordedLocationsAsync([.. Rules], generation);
    }

    /// <summary>
    /// Gives each row still recorded by path the identity migration worked out for it.
    /// </summary>
    /// <remarks>
    /// Matched by the path each rule named before migration, and only onto a row that still names it
    /// by path. A row the user removed or selected again while migration ran is left as the user left
    /// it: that choice is newer than anything migration read.
    /// </remarks>
    public void ApplyMigration(MigrationResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var count = Math.Min(result.Rules.Count, result.Configuration.Rules.Count);
        for (var index = 0; index < count; index++)
        {
            var report = result.Rules[index];
            if (report.Outcome == MigrationOutcome.Unchanged)
            {
                continue;
            }

            var row = Rules.FirstOrDefault(candidate =>
                candidate.Identity.Kind == IdentityKind.Path &&
                candidate.Status == RuleStatus.Active &&
                ExecutablePath.Comparer.Equals(candidate.ExecutablePath, report.RulePath));

            if (row is null)
            {
                continue;
            }

            var migrated = result.Configuration.Rules[index];

            // A rule re-anchored onto a newer build takes that build's path. If another row already
            // names it, two rules would key on one path, which the validator refuses on save - so this
            // row keeps its old path and says so, rather than making the whole list unsaveable.
            if (!ExecutablePath.Comparer.Equals(migrated.Identity.ExecutablePath, row.ExecutablePath) &&
                Rules.Any(other => !ReferenceEquals(other, row) &&
                                   ExecutablePath.Comparer.Equals(other.ExecutablePath, migrated.Identity.ExecutablePath)))
            {
                continue;
            }

            row.AdoptMigrated(migrated);
            Observe(row);
        }

        RaiseCounts();
    }

    /// <summary>Collects the rules for saving.</summary>
    public IReadOnlyList<AppRule> ToRules() => [.. Rules.Select(rule => rule.ToRule())];

    /// <summary>Adds an application, or reports that it is already listed.</summary>
    public void Add(AppIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (RefuseDuplicate(identity, except: null))
        {
            return;
        }

        var mode = RulePresentation.DefaultMode(identity);

        Rules.Add(new AppRuleViewModel(
            new AppRule { Identity = identity, Action = RouteAction.Proxy, MatchMode = mode },
            OnRuleChanged));

        _main.MarkDirty();
        RaiseCounts();
        _main.SetBanner(RulePresentation.AddedMessage(identity, mode));
    }

    /// <summary>
    /// Refuses an identity that another row already covers, and says which.
    /// </summary>
    /// <remarks>
    /// By path, which the validator requires to be unique, and by <see cref="AppIdentity.MatchKey"/>:
    /// two installations of one signed application are two paths and one application, and two rules
    /// for it would leave the engine choosing between their lanes.
    /// </remarks>
    private bool RefuseDuplicate(AppIdentity identity, AppRuleViewModel? except)
    {
        foreach (var row in Rules)
        {
            if (ReferenceEquals(row, except))
            {
                continue;
            }

            if (ExecutablePath.Comparer.Equals(row.ExecutablePath, identity.ExecutablePath))
            {
                _main.SetBanner($"{identity.DisplayName} is already in the list.");
                return true;
            }

            if (string.Equals(row.Identity.MatchKey, identity.MatchKey, StringComparison.Ordinal))
            {
                _main.SetBanner(
                    $"{identity.DisplayName} is already selected — it is the same application as the one at " +
                    $"{row.ExecutablePath}.");
                return true;
            }
        }

        return false;
    }

    private async Task AddCandidateAsync(object? parameter)
    {
        if (parameter is not ApplicationCandidate candidate)
        {
            return;
        }

        // Read with the signature, which the bulk scan skipped for speed, and with the package family
        // the scan read from the process token - which a path on another drive would not reveal.
        var description = await DescribeAsync(candidate.Path, candidate.DisplayName, candidate.PackageFamilyName)
            .ConfigureAwait(true);

        if (description.Identity is { } identity)
        {
            Add(identity);
        }
        else
        {
            _main.SetBanner(description.Refusal, isError: true);
        }

        // The picker stays open so several can be added in one go, which only works if what was just
        // added stops being offered.
        Raise(nameof(VisibleCandidates));
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

    private async Task BrowseAsync()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select an application",
            Filter = "Applications (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        };

        if (dialog.ShowDialog(Application.Current.MainWindow) != true)
        {
            return;
        }

        IsPickerOpen = false;

        var description = await DescribeAsync(dialog.FileName, fallbackName: null, packageFamilyName: null)
            .ConfigureAwait(true);

        if (description.Identity is { } identity)
        {
            Add(identity);
        }
        else
        {
            _main.SetBanner(description.Refusal, isError: true);
        }
    }

    /// <summary>
    /// Picks a rule's application again and records what it is now.
    /// </summary>
    /// <remarks>
    /// The dialog opens where the application was, with its file name filled in, because the usual
    /// answer is the same file after an update and that should be one click. The pick is refused on
    /// the same terms as adding: an invalid signature, or an application another row already covers.
    /// </remarks>
    private async Task ReselectAsync(object? parameter)
    {
        if (parameter is not AppRuleViewModel row || !Rules.Contains(row))
        {
            return;
        }

        var folder = ExecutablePath.Parent(row.ExecutablePath);
        var folderExists = folder.Length > 0 && Directory.Exists(folder);

        var dialog = new OpenFileDialog
        {
            Title = $"Select {row.DisplayName} again",
            Filter = "Applications (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
            InitialDirectory = folderExists ? folder : Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            FileName = folderExists && File.Exists(row.ExecutablePath) ? ExecutablePath.FileName(row.ExecutablePath) : string.Empty,
        };

        if (dialog.ShowDialog(Application.Current.MainWindow) != true)
        {
            return;
        }

        var description = await DescribeAsync(dialog.FileName, row.DisplayName, packageFamilyName: null)
            .ConfigureAwait(true);

        if (!Rules.Contains(row))
        {
            // Removed while the file was being read.
            _main.SetBanner(null);
            return;
        }

        if (description.Identity is not { } identity)
        {
            _main.SetBanner(description.Refusal, isError: true);
            return;
        }

        if (RefuseDuplicate(identity, except: row))
        {
            return;
        }

        row.Reselect(identity);
        Observe(row);
        RaiseCounts();

        _main.SetBanner(
            $"{identity.DisplayName} selected again. {RulePresentation.IdentitySummary(identity)}.");
    }

    /// <summary>Identifies a file on a worker thread, saying so while it does.</summary>
    /// <remarks>
    /// Verifying a signature and hashing the file is a full read each; for a large executable that is
    /// long enough to look like a hang if the window stops painting for it.
    /// </remarks>
    private async Task<ApplicationDescription> DescribeAsync(string path, string? fallbackName, string? packageFamilyName)
    {
        _main.SetBanner($"Reading {fallbackName ?? ExecutablePath.FileName(path)} to check its signature…");

        try
        {
            return await Task.Run(() => ApplicationInspector.Describe(path, fallbackName, packageFamilyName))
                .ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            var normalized = ExecutablePath.Normalize(path);
            var name = fallbackName ?? ExecutablePath.FileName(normalized);
            return new ApplicationDescription(normalized, name, null, $"{name} could not be read: {ex.Message}");
        }
    }

    /// <summary>Records what is at a row's recorded path. Cheap: existence checks only.</summary>
    private static void Observe(AppRuleViewModel row)
    {
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
    }

    /// <summary>
    /// Reads the file at each pinned rule's recorded path and marks the rows where it is no longer the
    /// rule's application.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same comparison the engine makes there: a signed rule's file must still verify and name the
    /// same publisher, an unsigned rule's must have the same bytes. When it does not, the engine refuses
    /// the file's connections, and a refusal this page did not explain would look exactly like a
    /// broken proxy.
    /// </para>
    /// <para>
    /// One file at a time, off the UI thread: each is a full read, and several large executables read at
    /// once would compete for the disk with whatever the user opened SplitLane to do. A file that cannot
    /// be read is not marked - locked mid-update is not evidence of anything.
    /// </para>
    /// </remarks>
    private async Task CheckRecordedLocationsAsync(IReadOnlyList<AppRuleViewModel> rows, int generation)
    {
        foreach (var row in rows)
        {
            if (!RulePresentation.HasLocationPin(row.ToRule()) || row.ExecutableIsMissing)
            {
                continue;
            }

            var identity = row.Identity;
            ImageEvidence? evidence;

            try
            {
                evidence = await Task.Run(() => WindowsImageInspector.Read(
                        identity.ExecutablePath, computeSha256: identity.Kind == IdentityKind.Unsigned))
                    .ConfigureAwait(true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                continue;
            }

            // A reload replaced every row; a re-selection replaced this one's identity. Either way what
            // was read describes something no longer on screen.
            if (generation != _loadGeneration)
            {
                return;
            }

            if (!ReferenceEquals(row.Identity, identity) || !Rules.Contains(row))
            {
                continue;
            }

            var changed = RulePresentation.StillSameApplication(identity, evidence) == false;
            if (row.IdentityChanged != changed)
            {
                row.IdentityChanged = changed;
                RaiseCounts();
            }
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
