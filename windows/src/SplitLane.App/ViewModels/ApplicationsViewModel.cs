using System.Collections.ObjectModel;
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

    /// <summary>Candidates matching the picker's search box.</summary>
    public IEnumerable<ApplicationCandidate> VisibleCandidates => string.IsNullOrWhiteSpace(PickerFilter)
        ? Candidates
        : Candidates.Where(candidate =>
            candidate.DisplayName.Contains(PickerFilter, StringComparison.OrdinalIgnoreCase) ||
            candidate.Path.Contains(PickerFilter, StringComparison.OrdinalIgnoreCase));

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

    /// <summary>Rebuilds the list from a configuration.</summary>
    public void LoadFrom(RuntimeConfiguration configuration)
    {
        Rules.Clear();

        foreach (var rule in configuration.Rules)
        {
            Rules.Add(new AppRuleViewModel(rule, OnRuleChanged));
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

        // Family matching is the default only where it is safe. For a program installed in a shared
        // directory it would mean routing every unrelated binary beside it (ADR W-0003).
        var mode = identity.SupportsFamilyMatching ? MatchMode.ExecutableFamily : MatchMode.Exact;

        Rules.Add(new AppRuleViewModel(
            new AppRule { Identity = identity, Action = RouteAction.Proxy, MatchMode = mode },
            OnRuleChanged));

        _main.MarkDirty();
        RaiseCounts();

        _main.SetBanner(identity.SupportsFamilyMatching
            ? $"{identity.DisplayName} added to the proxy lane."
            : $"{identity.DisplayName} added. Its folder is shared with other programs, so it is " +
              "matched exactly rather than by folder.");
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
    }
}
