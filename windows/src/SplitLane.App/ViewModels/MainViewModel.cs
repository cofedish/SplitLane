using System.IO;
using System.Windows.Threading;
using SplitLane.App.Infrastructure;
using SplitLane.App.Services;
using SplitLane.Core.Configuration;
using SplitLane.Core.Ipc;
using SplitLane.Core.Models;

namespace SplitLane.App.ViewModels;

/// <summary>Which screen is showing.</summary>
public enum AppPage
{
    /// <summary>State, counters, and the master switch.</summary>
    Overview,

    /// <summary>Rules.</summary>
    Applications,

    /// <summary>Upstream proxy.</summary>
    Proxy,

    /// <summary>Recent connections.</summary>
    Activity,

    /// <summary>Diagnostics and paths.</summary>
    Settings,
}

/// <summary>
/// The window's view model: owns the configuration, the engine connection, and the poll timer.
/// </summary>
/// <remarks>
/// <para>
/// One place holds the configuration and every page edits it through this object, because the
/// alternative — each page owning a copy — means five chances for the file on disk and the screen to
/// disagree.
/// </para>
/// <para>
/// Status is polled rather than pushed. A push channel would need the elevated engine to hold a
/// callback for an unprivileged process, and the thing being displayed changes once a second at most.
/// </para>
/// </remarks>
public sealed class MainViewModel : ObservableObject
{
    private readonly EngineClient _engine = new();
    private readonly DispatcherTimer _timer;

    private AppPage _page = AppPage.Overview;
    private RuntimeConfiguration _configuration;
    private EngineStatus? _status;
    private string? _engineMessage;
    private bool _engineConnected;
    private bool _hasUnsavedChanges;
    private string? _banner;
    private bool _bannerIsError;
    private bool _suppressDirty;
    private int _loadGeneration;
    private MigrationResult? _lastMigration;

    /// <summary>Builds the view model and loads what is on disk.</summary>
    public MainViewModel()
    {
        Store = new ConfigurationService();
        _configuration = Store.Load(out var loadError);

        if (loadError is not null)
        {
            SetBanner($"Configuration could not be read: {loadError}", isError: true);
        }

        Overview = new OverviewViewModel(this);
        Applications = new ApplicationsViewModel(this);
        Proxy = new ProxyViewModel(this);
        Activity = new ActivityViewModel(this);
        Settings = new SettingsViewModel(this);

        Applications.LoadFrom(_configuration);
        Proxy.LoadFrom(_configuration);
        Settings.LoadFrom(_configuration);
        BeginMigration(_configuration);

        GoToCommand = new RelayCommand(parameter =>
        {
            if (parameter is AppPage target)
            {
                Page = target;
            }
        });

        SaveCommand = new AsyncRelayCommand(SaveAsync, () => HasUnsavedChanges);
        DiscardCommand = new RelayCommand(Reload, () => HasUnsavedChanges);

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
    }

    /// <summary>Configuration storage, shared with the engine.</summary>
    public ConfigurationService Store { get; }

    /// <summary>The engine's control channel.</summary>
    public EngineClient Engine => _engine;

    /// <summary>The Overview page.</summary>
    public OverviewViewModel Overview { get; }

    /// <summary>The Applications page.</summary>
    public ApplicationsViewModel Applications { get; }

    /// <summary>The Proxy page.</summary>
    public ProxyViewModel Proxy { get; }

    /// <summary>The Activity page.</summary>
    public ActivityViewModel Activity { get; }

    /// <summary>The Settings page.</summary>
    public SettingsViewModel Settings { get; }

    /// <summary>Navigates.</summary>
    public RelayCommand GoToCommand { get; }

    /// <summary>Writes pending edits to disk and tells the engine.</summary>
    public AsyncRelayCommand SaveCommand { get; }

    /// <summary>Throws pending edits away and re-reads from disk.</summary>
    public RelayCommand DiscardCommand { get; }

    /// <summary>Which screen is showing.</summary>
    public AppPage Page
    {
        get => _page;
        set
        {
            if (Set(ref _page, value))
            {
                Raise(nameof(IsOverview));
                Raise(nameof(IsApplications));
                Raise(nameof(IsProxy));
                Raise(nameof(IsActivity));
                Raise(nameof(IsSettings));
                Raise(nameof(PageTitle));
                Raise(nameof(PageSubtitle));
                Raise(nameof(CurrentPage));
            }
        }
    }

    /// <summary>
    /// The view model for the page currently showing.
    /// </summary>
    /// <remarks>
    /// The window hosts one page at a time and cross-fades between them, rather than stacking five
    /// views and toggling visibility. Only the visible page's bindings are live, which matters for
    /// Activity: its list is rebuilt on every poll, and a hidden copy would keep doing that work.
    /// </remarks>
    public object CurrentPage => Page switch
    {
        AppPage.Overview => Overview,
        AppPage.Applications => Applications,
        AppPage.Proxy => Proxy,
        AppPage.Activity => Activity,
        _ => Settings,
    };

    /// <summary>True when the Overview page is showing.</summary>
    public bool IsOverview => Page == AppPage.Overview;

    /// <summary>True when the Applications page is showing.</summary>
    public bool IsApplications => Page == AppPage.Applications;

    /// <summary>True when the Proxy page is showing.</summary>
    public bool IsProxy => Page == AppPage.Proxy;

    /// <summary>True when the Activity page is showing.</summary>
    public bool IsActivity => Page == AppPage.Activity;

    /// <summary>True when the Settings page is showing.</summary>
    public bool IsSettings => Page == AppPage.Settings;

    /// <summary>Heading for the current page.</summary>
    public string PageTitle => Page switch
    {
        AppPage.Overview => "Overview",
        AppPage.Applications => "Applications",
        AppPage.Proxy => "Proxy",
        AppPage.Activity => "Activity",
        _ => "Settings",
    };

    /// <summary>Explanatory line under the heading.</summary>
    public string PageSubtitle => Page switch
    {
        AppPage.Overview =>
            "Selected applications go through the proxy. Everything else is left alone.",
        AppPage.Applications =>
            "Pick the applications that belong in the proxy lane. Anything not listed here stays DIRECT.",
        AppPage.Proxy =>
            "Where the proxy lane points. A selected application whose proxy is unreachable fails — it never falls back to DIRECT.",
        AppPage.Activity =>
            "Connections SplitLane handled. DIRECT decisions are counted, not listed.",
        _ => "Diagnostics, storage locations, and how the divert layer is doing.",
    };

    /// <summary>The configuration currently being edited.</summary>
    public RuntimeConfiguration Configuration
    {
        get => _configuration;
        private set => Set(ref _configuration, value);
    }

    /// <summary>The engine's last reported status, or null when it is not running.</summary>
    public EngineStatus? Status
    {
        get => _status;
        private set
        {
            if (Set(ref _status, value))
            {
                Overview.OnStatusChanged();
                Settings.OnStatusChanged();
            }
        }
    }

    /// <summary>Whether the engine answered the last poll.</summary>
    public bool EngineConnected
    {
        get => _engineConnected;
        private set
        {
            if (Set(ref _engineConnected, value))
            {
                Overview.OnStatusChanged();
                Settings.OnStatusChanged();
            }
        }
    }

    /// <summary>Why the engine is not answering, when it is not.</summary>
    public string? EngineMessage
    {
        get => _engineMessage;
        private set => Set(ref _engineMessage, value);
    }

    /// <summary>Whether there are edits not yet written to disk.</summary>
    public bool HasUnsavedChanges
    {
        get => _hasUnsavedChanges;
        private set => Set(ref _hasUnsavedChanges, value);
    }

    /// <summary>Transient message shown across the top of the window.</summary>
    public string? Banner
    {
        get => _banner;
        private set
        {
            if (Set(ref _banner, value))
            {
                Raise(nameof(HasBanner));
            }
        }
    }

    /// <summary>Whether the banner is reporting a problem.</summary>
    public bool BannerIsError
    {
        get => _bannerIsError;
        private set => Set(ref _bannerIsError, value);
    }

    /// <summary>Whether a banner is showing.</summary>
    public bool HasBanner => !string.IsNullOrEmpty(Banner);

    /// <summary>
    /// What converting the loaded rules from paths to identities did, rule by rule; null when the
    /// last load had nothing to convert or conversion has not finished.
    /// </summary>
    public MigrationResult? LastMigration
    {
        get => _lastMigration;
        private set => Set(ref _lastMigration, value);
    }

    /// <summary>Starts polling. Called once the window is up.</summary>
    public async Task StartAsync()
    {
        _timer.Start();
        await RefreshAsync().ConfigureAwait(true);
    }

    /// <summary>Stops polling.</summary>
    public void Stop() => _timer.Stop();

    /// <summary>Notes that something the user edited needs saving.</summary>
    public void MarkDirty()
    {
        if (!_suppressDirty)
        {
            HasUnsavedChanges = true;
        }
    }

    /// <summary>Shows a message across the top of the window.</summary>
    public void SetBanner(string? message, bool isError = false)
    {
        BannerIsError = isError;
        Banner = message;
    }

    /// <summary>Re-reads the configuration from disk, discarding edits.</summary>
    public void Reload()
    {
        _suppressDirty = true;
        try
        {
            Configuration = Store.Load(out var error);
            Applications.LoadFrom(Configuration);
            Proxy.LoadFrom(Configuration);
            Settings.LoadFrom(Configuration);
            HasUnsavedChanges = false;

            SetBanner(error is null ? null : $"Configuration could not be read: {error}", isError: error is not null);
            BeginMigration(Configuration);
        }
        finally
        {
            _suppressDirty = false;
        }
    }

    /// <summary>
    /// Converts a freshly loaded configuration's path rules to identity rules, in the background.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The window shows the rules as stored straight away and is usable throughout. Conversion
    /// verifies the signature of every file a path rule names - seconds, for large executables - and
    /// this runs at startup, where a frozen window reads as a crash.
    /// </para>
    /// <para>
    /// Not counted as an unsaved change. The user did not make it, and the engine makes the same
    /// conversion itself when it loads the document; the app shows its copy so that what is on screen
    /// is what will route, and the next save the user does make writes it.
    /// </para>
    /// </remarks>
    private void BeginMigration(RuntimeConfiguration loaded)
    {
        var generation = ++_loadGeneration;
        LastMigration = null;

        if (!ConfigurationService.NeedsMigration(loaded))
        {
            Applications.IsMigrating = false;
            return;
        }

        _ = MigrateAsync(loaded, generation);
    }

    private async Task MigrateAsync(RuntimeConfiguration loaded, int generation)
    {
        Applications.IsMigrating = true;

        try
        {
            var result = await ConfigurationService.MigrateAsync(loaded).ConfigureAwait(true);

            // Reloaded while it ran: that load has its own conversion, and this one describes rows
            // that are no longer on screen.
            if (generation != _loadGeneration)
            {
                return;
            }

            LastMigration = result;
            Applications.ApplyMigration(result);

            if (RulePresentation.MigrationSummary(result) is { } summary)
            {
                SetBanner(summary);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException
                                       or InvalidOperationException)
        {
            // The path rules stay exactly as they were, which is how they have been routing all along.
            if (generation == _loadGeneration)
            {
                SetBanner(
                    $"Rules recorded by path could not be converted: {ex.Message} They keep working as before.",
                    isError: true);
            }
        }
        finally
        {
            if (generation == _loadGeneration)
            {
                Applications.IsMigrating = false;
            }
        }
    }

    /// <summary>Collects edits from every page, writes them, and asks the engine to reload.</summary>
    public async Task SaveAsync()
    {
        try
        {
            var edited = Configuration with
            {
                Rules = Applications.ToRules(),
                Proxy = Proxy.ToProxyConfiguration(),
                IsRoutingEnabled = Overview.IsRoutingEnabled,
                LogsDirectFlows = Settings.LogsDirectFlows,
                RedirectPort = Settings.RedirectPortValue,
            };

            Proxy.PersistCredential();

            Configuration = Store.Save(edited);
            HasUnsavedChanges = false;

            var reply = await _engine.ReloadAsync(Configuration.Version.Generation).ConfigureAwait(true);

            SetBanner(
                reply.Connected
                    ? "Saved. The engine picked up the new configuration."
                    : "Saved to disk. The engine is not running, so it will pick this up when it starts.",
                isError: false);
        }
        catch (Core.Configuration.ConfigurationValidationException ex)
        {
            SetBanner(ex.Message, isError: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            SetBanner($"Could not write {Store.ConfigurationPath}: {ex.Message}", isError: true);
        }
    }

    private async Task RefreshAsync()
    {
        var reply = await _engine.StatusAsync().ConfigureAwait(true);

        EngineConnected = reply.Connected;
        EngineMessage = reply.Message;
        Status = reply.Response?.Status;

        if (IsActivity)
        {
            await Activity.RefreshAsync().ConfigureAwait(true);
        }
    }
}
