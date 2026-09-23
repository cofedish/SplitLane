using System.Diagnostics;
using SplitLane.Core.Configuration;
using SplitLane.Core.Ipc;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Relay;
using SplitLane.Engine.Update;
using SplitLane.Platform;

namespace SplitLane.Engine.Runtime;

/// <summary>How the engine was asked to run.</summary>
/// <param name="EnableDivert">
/// When false the packet layer is never opened. The relay, the rule engine, the control channel and
/// the statistics all still run, which is what makes the app developable and demonstrable on a
/// machine without the driver — and what makes it obvious in the UI that nothing is being routed.
/// </param>
/// <param name="Verbose">Whether debug-level records are emitted.</param>
/// <param name="UseLoopbackRedirect">
/// Whether a redirected connection is moved to loopback, or to the machine's own address.
///
/// Loopback is the default and the shape verified on a live machine. The switch keeps the other shape
/// available without a rebuild.
/// </param>
/// <param name="TraceRedirects">
/// Whether to sniff the redirect port and report what the stack actually carries, rather than
/// leaving the outcome to be inferred from counters.
/// </param>
public readonly record struct EngineOptions(
    bool EnableDivert = true,
    bool Verbose = false,
    bool UseLoopbackRedirect = true,
    bool TraceRedirects = false);

/// <summary>
/// The engine: one configuration generation at a time, swapped atomically.
/// </summary>
/// <remarks>
/// <para>
/// Reload replaces a whole <see cref="RuleEngine"/> reference in a single volatile store. Nothing is
/// mutated in place, so a connection that started under generation <i>n</i> keeps reading a coherent
/// generation <i>n</i> for its lifetime, and the divert threads never see a half-built table.
/// </para>
/// <para>
/// The start order matters and is not arbitrary: the redirect listener binds <b>before</b> the
/// divert filter is compiled, because the filter has to name the port the listener ended up on. Doing
/// it the other way round would mean either a fixed port or a window in which packets are redirected
/// to a port nothing is listening on — which for a selected app is a hang rather than an error.
/// </para>
/// </remarks>
public sealed class EngineRuntime : IAsyncDisposable
{
    private const string LogCategory = "engine";

    private readonly ConfigurationStore _store;
    private readonly EngineOptions _options;
    private readonly NatTable _nat = new();
    private readonly DnsObserver _dns = new();
    private readonly ImageCatalog _images;
    private readonly ProcessResolver _processes;
    private readonly EngineStatistics _statistics = new();
    private readonly UpdateService _updates = new();
    private readonly SemaphoreSlim _lifecycle = new(1, 1);

    private readonly PolicyStore? _policyStore;
    private readonly Lock _applyGate = new();

    private volatile RuleEngine _engine = new(RuleSnapshot.Empty);
    private RuntimeConfiguration _configuration = RuntimeConfiguration.Empty;
    private RuntimeConfiguration _userConfiguration = RuntimeConfiguration.Empty;
    private PolicyLoad _policy = new(null, PolicyState.None, "no policy loaded");
    private Socks5Credential? _credential;
    private RedirectListener? _listener;
    private DivertPipeline? _pipeline;
    private DivertState _state = DivertState.Stopped;
    private string? _lastError;
    private DateTimeOffset? _startedAt;
    private Timer? _sweeper;
    private Task _migration = Task.CompletedTask;
    private RuntimeConfiguration? _migrationQueued;
    private int _migrating;
    private volatile bool _routingWanted;
    private volatile bool _faultPending;
    private int _recovering;
    private int _consecutiveFaults;
    private DateTimeOffset _lastRecovery = DateTimeOffset.MinValue;
    private readonly CancellationTokenSource _stopping = new();

    /// <summary>Builds a runtime over a store, reading the managed policy from its standard place.</summary>
    public EngineRuntime(ConfigurationStore store, EngineOptions options = default)
        : this(store, options, new ImageCatalog(), WindowsImageInspector.Instance, new PolicyStore())
    {
    }

    /// <summary>Builds a runtime over explicit identity and policy sources. Used by tests.</summary>
    internal EngineRuntime(
        ConfigurationStore store,
        EngineOptions options,
        ImageCatalog images,
        IImageInspector inspector,
        PolicyStore? policy = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options;
        _images = images ?? throw new ArgumentNullException(nameof(images));
        Inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));
        _processes = new ProcessResolver(images: _images);
        _policyStore = policy;
    }

    /// <summary>What migration reads files with.</summary>
    internal IImageInspector Inspector { get; }

    /// <summary>The migration in progress, or a completed task. Tests wait on it.</summary>
    internal Task Migration => _migration;

    /// <summary>
    /// How long to wait before each attempt to bring routing back after it failed, then the last one
    /// repeated. Settable so tests do not wait minutes.
    /// </summary>
    internal TimeSpan[] RecoveryBackoff { get; set; } =
        [TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5)];

    /// <summary>How many times routing has been brought back after a failure. Diagnostic.</summary>
    internal int Recoveries { get; private set; }

    /// <summary>
    /// Raised when routing has been brought back, while the recovery is still finishing. Tests use it
    /// to fail the new pipeline at the worst moment.
    /// </summary>
    internal event Action? Recovered;

    /// <summary>The state of the divert layer, for tests.</summary>
    internal DivertState State => _state;

    /// <summary>Statistics, shared with the relay and the divert threads.</summary>
    public EngineStatistics Statistics => _statistics;

    /// <summary>Finds newer releases, and installs one when asked to.</summary>
    public UpdateService Updates => _updates;

    /// <summary>The configuration currently in force: the user's, with the managed policy applied.</summary>
    public RuntimeConfiguration Configuration => _configuration;

    /// <summary>The user's own configuration, as stored and migrated.</summary>
    public RuntimeConfiguration UserConfiguration => _userConfiguration;

    /// <summary>The managed policy, if any, and whether it is in force.</summary>
    public PolicyLoad Policy => _policy;

    /// <summary>Whether the managed policy requires routing to stay on.</summary>
    public bool IsRoutingLockedByPolicy => _policy.Policy?.ForceRoutingEnabled == true;

    /// <summary>Loads the policy and the configuration from disk and applies them without starting anything.</summary>
    public void LoadConfiguration()
    {
        if (_policyStore is not null)
        {
            SetPolicy(_policyStore.Load());
        }

        var configuration = _store.LoadOrDefault(out var error);
        _lastError = error;
        ApplyInternal(configuration);
    }

    /// <summary>
    /// Makes sure the policy folder exists with administrator-only permissions and starts watching it.
    /// Run once by the host; a failure is reported and routing carries on without a watcher.
    /// </summary>
    public void StartPolicyWatch()
    {
        if (_policyStore is null)
        {
            return;
        }

        try
        {
            _policyStore.EnsureFolder();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                       PlatformNotSupportedException or InvalidOperationException)
        {
            // Not fatal: a policy in a folder that could not be made safe is refused when read.
            SplitLaneLog.Error(PolicyLogCategory, $"the policy folder could not be made safe: {ex.Message}");
        }

        try
        {
            _policyStore.Changed += ReloadPolicy;
            _policyStore.Watch();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                                       PlatformNotSupportedException or InvalidOperationException)
        {
            SplitLaneLog.Warning(PolicyLogCategory, $"managed policy changes will be picked up only on reload: {ex.Message}");
        }

        // The first load happened before the folder was made safe; read it again now that it is.
        ReloadPolicy();
    }

    /// <summary>Re-reads the managed policy and re-applies the configuration under it.</summary>
    public void ReloadPolicy()
    {
        if (_policyStore is null)
        {
            return;
        }

        lock (_applyGate)
        {
            SetPolicy(_policyStore.Load());
            ApplyLocked(_userConfiguration);
        }

        EnsureRoutingIfForced();
    }

    /// <summary>
    /// Starts routing again when the policy requires it and something stopped it - a request made
    /// before the policy arrived, or a fault. A forced policy that leaves the engine stopped would be
    /// "routing is required" in the status and DIRECT on the wire.
    /// </summary>
    private void EnsureRoutingIfForced()
    {
        if (!IsRoutingLockedByPolicy || _state is not (DivertState.Stopped or DivertState.Faulted))
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await StartAsync().ConfigureAwait(false);
                SplitLaneLog.Info(PolicyLogCategory, "routing started because the policy requires it");
            }
            catch (Exception ex)
            {
                SplitLaneLog.Error(PolicyLogCategory, "routing is required by policy and could not be started", ex);
            }
        });
    }

    private void SetPolicy(PolicyLoad load)
    {
        var previous = _policy;

        // A policy that was in force stays in force when a later read fails. The failure is not
        // evidence of anything an administrator did: a file that cannot be opened, or opened and
        // judged, is as likely to be someone holding it open to make exactly this read fail - which,
        // if it dropped the policy, would drop forced routing with it. Only a file that reads and
        // verifies, or one that is gone, changes what is enforced.
        if ((load.State == PolicyState.Rejected || !load.AbsenceVerified) && previous.Policy is not null)
        {
            SplitLaneLog.Error(PolicyLogCategory, $"{load.Detail}; the last policy that verified stays in force");
            _policy = previous with { Detail = $"{previous.Detail} (a newer read was refused: {load.Detail})" };
            return;
        }

        _policy = load;
        _updates.DisabledByPolicy = load.Policy?.DisableSelfUpdate == true;

        if (previous.State == load.State && previous.Detail == load.Detail)
        {
            return;
        }

        switch (load.State)
        {
            case PolicyState.Rejected:
                SplitLaneLog.Error(PolicyLogCategory, load.Detail);
                break;

            case PolicyState.Applied:
                SplitLaneLog.Info(PolicyLogCategory, load.Detail);
                break;

            default:
                SplitLaneLog.Info(
                    PolicyLogCategory,
                    previous.State == PolicyState.Applied ? $"policy removed: {load.Detail}" : load.Detail);
                break;
        }
    }

    private const string PolicyLogCategory = "policy";

    /// <summary>Swaps in a configuration, rebuilding the routing tables.</summary>
    public void Apply(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ConfigurationValidator.Validate(configuration);
        ApplyInternal(ConfigurationValidator.Sanitize(configuration));
    }

    private void ApplyInternal(RuntimeConfiguration configuration)
    {
        lock (_applyGate)
        {
            ApplyLocked(configuration);
        }
    }

    /// <summary>
    /// Makes a user configuration current: the policy goes on top, and the result is what routes.
    /// </summary>
    /// <remarks>
    /// Callers hold <see cref="_applyGate"/>. Three threads apply configurations - the control channel,
    /// the migration task and the policy watcher - and each builds on what the others last applied.
    /// </remarks>
    private void ApplyLocked(RuntimeConfiguration configuration)
    {
        _userConfiguration = configuration;

        var outcome = PolicyMerger.Merge(configuration, _policy.Policy);
        foreach (var note in outcome.Notes)
        {
            SplitLaneLog.Warning(PolicyLogCategory, note);
        }

        var effective = outcome.Effective;
        _configuration = effective;
        _credential = _store.ResolveCredential(effective.Proxy);
        _engine = new RuleEngine(effective);

        SplitLaneLog.Info(
            LogCategory,
            $"configuration generation {effective.Version.Generation} applied: " +
            $"{_engine.Snapshot.ActiveRuleCount} active rules " +
            $"({_engine.Snapshot.IdentityRuleCount} by identity, {_engine.Snapshot.ManagedRuleCount} managed" +
            (outcome.UserRulesDropped > 0 ? $", {outcome.UserRulesDropped} user rules set aside by policy" : string.Empty) +
            $"), routing {(effective.IsRoutingEnabled ? "enabled" : "paused")}");

        foreach (var rule in configuration.Rules.Where(rule => rule.Status == RuleStatus.NeedsReselection))
        {
            SplitLaneLog.Warning(
                LogCategory,
                $"rule for {rule.Identity.DisplayName} routes nothing until it is selected again: {rule.StatusDetail}");
        }

        if (ConfigurationMigrator.NeedsMigration(configuration))
        {
            ScheduleMigration(configuration);
        }
    }

    /// <summary>
    /// Migrates path rules to identity rules in the background, then applies and saves the result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Not on the start path: migration verifies the signature of every file a rule names, which is
    /// seconds for a large executable, and the service control manager gives a starting service 30.
    /// Until it finishes the rules keep the meaning they had before - the same routing as the build
    /// this replaced, no better and no worse.
    /// </para>
    /// <para>
    /// The result is thrown away if the configuration changed while it ran: whatever replaced it is
    /// newer, and will be migrated itself if it needs to be.
    /// </para>
    /// </remarks>
    private void ScheduleMigration(RuntimeConfiguration basis)
    {
        // Called under _applyGate. One migration at a time: each reads and verifies every file its
        // rules name, as LocalSystem, and the configuration that asks for it can be written by any
        // user as often as they like. A request that arrives while one runs replaces whatever was
        // waiting, so the work done is bounded by the rate it can be done at, not the rate it is asked.
        _migrationQueued = basis;
        if (Interlocked.Exchange(ref _migrating, 1) == 0)
        {
            _migration = Task.Run(RunMigrations);
        }
    }

    private void RunMigrations()
    {
        while (true)
        {
            RuntimeConfiguration? basis;
            lock (_applyGate)
            {
                basis = _migrationQueued;
                _migrationQueued = null;
                if (basis is null)
                {
                    Volatile.Write(ref _migrating, 0);
                    return;
                }
            }

            MigrateOnce(basis);
        }
    }

    private void MigrateOnce(RuntimeConfiguration basis)
    {
        try
        {
            var result = ConfigurationMigrator.Migrate(basis, Inspector);

            foreach (var rule in result.Rules.Where(rule => rule.Outcome != MigrationOutcome.Unchanged))
            {
                var line = $"migrated {rule.RulePath}: {rule.Outcome}" +
                           (rule.Detail.Length > 0 ? $" - {rule.Detail}" : string.Empty);

                if (rule.Outcome == MigrationOutcome.NeedsReselection)
                {
                    SplitLaneLog.Warning(LogCategory, line);
                }
                else
                {
                    SplitLaneLog.Info(LogCategory, line);
                }
            }

            lock (_applyGate)
            {
                // The rules are what migration changed, so they are what has to be unchanged since.
                // A switch such as DIRECT logging replaces the configuration but keeps its rules.
                var current = _userConfiguration;
                if (!ReferenceEquals(current.Rules, basis.Rules))
                {
                    SplitLaneLog.Info(LogCategory, "rules changed during migration; the migrated copy was discarded");
                    return;
                }

                // Saved to the schema 2 file; the schema 1 file stays exactly as it was, for a rollback.
                var migrated = (current with
                {
                    Rules = result.Configuration.Rules,
                    Version = result.Configuration.Version,
                }).WithNextGeneration();
                _store.Save(migrated);
                ApplyLocked(ConfigurationValidator.Sanitize(migrated));
            }
        }
        catch (Exception ex)
        {
            // Whatever it was. Nothing awaits this task, so an exception not caught here would vanish,
            // and the rules would stay path rules with nothing anywhere saying why. They keep the
            // previous build's meaning meanwhile - no better and no worse than before.
            SplitLaneLog.Error(LogCategory, "configuration migration failed; rules keep their previous meaning", ex);
        }
    }

    /// <summary>Persists and applies a configuration in one step.</summary>
    public void Save(RuntimeConfiguration configuration)
    {
        _store.Save(configuration);
        ApplyInternal(ConfigurationValidator.Sanitize(configuration));
    }

    /// <summary>
    /// Starts routing: binds the listener, then opens the divert handles.
    /// </summary>
    public async Task StartAsync()
    {
        // Independent of whether the divert layer comes up. A machine that cannot load the driver is
        // a machine that most wants the release which might fix that.
        _updates.Start();

        _routingWanted = true;

        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_state is DivertState.Running or DivertState.Starting or DivertState.Paused)
            {
                return;
            }

            _state = DivertState.Starting;
            _lastError = null;
            _faultPending = false;

            _listener ??= new RedirectListener(
                _nat,
                _statistics,
                () => _configuration.Proxy,
                () => _credential)
            {
                // When redirecting to the machine's own address rather than loopback, the listener
                // has to be reachable at that address. See the property's own remarks for what that
                // costs and what still protects the port.
                AcceptOnAllAddresses = !_options.UseLoopbackRedirect,
            };

            var port = _listener.Start(_configuration.RedirectPort);

            if (_options.EnableDivert)
            {
                _pipeline ??= new DivertPipeline(_nat, _dns, _processes, _statistics, () => _engine)
                {
                    Images = _images,
                    UseLoopbackRedirect = _options.UseLoopbackRedirect,
                    TraceRedirects = _options.TraceRedirects,
                    ProxiesUdp = _configuration.ProxiesUdp,
                    Proxy = () => _configuration.Proxy,
                    Credential = () => _credential,
                };

                _pipeline.Faulted -= ReportRoutingFault;
                _pipeline.Faulted += ReportRoutingFault;
                _pipeline.Start(port);
            }
            else
            {
                SplitLaneLog.Warning(
                    LogCategory,
                    "started with the divert layer disabled — no traffic is being routed");
            }

            _sweeper ??= new Timer(_ => Sweep(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

            _startedAt = DateTimeOffset.UtcNow;

            // A divert thread can die before this line; its report has already set Faulted and must
            // not be overwritten with Running.
            if (!_faultPending)
            {
                _state = _configuration.IsRoutingEnabled ? DivertState.Running : DivertState.Paused;
            }
        }
        catch (DivertException ex)
        {
            _state = DivertState.Faulted;
            _lastError = $"{ex.Message} {ex.Remedy}";
            SplitLaneLog.Error(LogCategory, $"could not start routing: {_lastError}");
            await StopInternalAsync().ConfigureAwait(false);
            ScheduleRecovery();
            throw;
        }
        catch (Exception ex)
        {
            _state = DivertState.Faulted;
            _lastError = ex.Message;
            SplitLaneLog.Error(LogCategory, "could not start routing", ex);
            await StopInternalAsync().ConfigureAwait(false);
            ScheduleRecovery();
            throw;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    /// <summary>
    /// Records that routing stopped working while it was supposed to be on, and arranges for it to be
    /// brought back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Raised by the divert layer from its own failing thread. A process that is alive but no longer
    /// routing is the one failure the service manager's restart cannot see, and on Windows it means
    /// every selected application quietly DIRECT; so the engine restarts routing itself, with a growing
    /// pause between attempts so a driver that is gone for good is retried every few minutes rather than
    /// in a tight loop.
    /// </para>
    /// <para>
    /// Internal so tests can stand in for the divert layer, which needs a driver and elevation.
    /// </para>
    /// </remarks>
    internal void ReportRoutingFault(string reason)
    {
        // A pipeline being taken down on purpose has nothing to report.
        if (!_routingWanted)
        {
            return;
        }

        _faultPending = true;
        _state = DivertState.Faulted;
        _lastError = reason;
        ScheduleRecovery();
    }

    private void ScheduleRecovery()
    {
        if (!_routingWanted || _stopping.IsCancellationRequested || Interlocked.Exchange(ref _recovering, 1) != 0)
        {
            return;
        }

        // Faults far apart are each a first fault; faults in a burst climb the backoff.
        if (DateTimeOffset.UtcNow - _lastRecovery > TimeSpan.FromMinutes(10))
        {
            _consecutiveFaults = 0;
        }

        _ = Task.Run(RecoverAsync);
    }

    private async Task RecoverAsync()
    {
        try
        {
            while (_routingWanted && !_stopping.IsCancellationRequested)
            {
                var backoff = RecoveryBackoff;
                var delay = backoff[Math.Min(_consecutiveFaults, backoff.Length - 1)];
                _consecutiveFaults++;

                SplitLaneLog.Warning(LogCategory, $"routing will be restarted in {delay.TotalSeconds:0} s");
                await Task.Delay(delay, _stopping.Token).ConfigureAwait(false);

                if (!_routingWanted)
                {
                    return;
                }

                try
                {
                    await _lifecycle.WaitAsync(_stopping.Token).ConfigureAwait(false);
                    try
                    {
                        await StopInternalAsync().ConfigureAwait(false);
                        _state = DivertState.Stopped;
                    }
                    finally
                    {
                        _lifecycle.Release();
                    }

                    // StartAsync schedules nothing while this attempt holds the recovery slot; a
                    // failure comes back here as an exception, and a divert thread that dies straight
                    // away as _faultPending, and the loop waits longer.
                    await StartAsync().ConfigureAwait(false);

                    if (!_faultPending && _state is DivertState.Running or DivertState.Paused)
                    {
                        Recoveries++;
                        _lastRecovery = DateTimeOffset.UtcNow;
                        SplitLaneLog.Info(LogCategory, "routing restarted after a failure");
                        Recovered?.Invoke();
                        return;
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    SplitLaneLog.Error(LogCategory, $"restarting routing failed: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            Volatile.Write(ref _recovering, 0);

            // A fault reported after the check above, while this attempt still held the slot, was
            // turned away by ScheduleRecovery; without this it would leave routing dead for good.
            if (_faultPending)
            {
                ScheduleRecovery();
            }
        }
    }

    /// <summary>Stops routing, leaving the engine running and inert.</summary>
    public async Task StopAsync()
    {
        // Asked for, so not to be undone by the recovery above.
        _routingWanted = false;

        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            await StopInternalAsync().ConfigureAwait(false);
            _state = DivertState.Stopped;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    private async Task StopInternalAsync()
    {
        if (_pipeline is not null)
        {
            await _pipeline.DisposeAsync().ConfigureAwait(false);
            _pipeline = null;
        }

        if (_listener is not null)
        {
            await _listener.DisposeAsync().ConfigureAwait(false);
            _listener = null;
        }

        if (_sweeper is not null)
        {
            await _sweeper.DisposeAsync().ConfigureAwait(false);
            _sweeper = null;
        }

        _nat.Clear();
        _processes.Clear();
        _startedAt = null;
    }

    private void Sweep()
    {
        var removed = _nat.Sweep();
        if (removed > 0)
        {
            SplitLaneLog.Debug(LogCategory, $"swept {removed} expired NAT entries");
        }
    }

    /// <summary>Builds the status payload for the control channel.</summary>
    public EngineStatus Status()
    {
        var state = _state;

        // A running engine whose master switch is off reports Paused rather than Running. The two
        // look identical from the outside and mean very different things.
        if (state == DivertState.Running && !_configuration.IsRoutingEnabled)
        {
            state = DivertState.Paused;
        }

        return _statistics.ToStatus(
            state,
            _configuration.Version.Generation,
            _configuration.IsRoutingEnabled,
            _engine.Snapshot.ActiveRuleCount,
            _listener?.Port ?? 0,
            _lastError,
            _startedAt,
            _pipeline?.DriverVersion) with
        {
            EngineVersion = UpdateService.CurrentVersion.ToString(),
            UpdateState = _updates.State.ToString(),
            UpdateVersion = _updates.Available?.Version,
            UpdateNotes = _updates.Available?.Notes,
            UpdateError = _updates.LastError,
            PolicyState = _policy.State.ToString(),
            PolicyDetail = _policy.Detail,
            ManagedRuleCount = _engine.Snapshot.ManagedRuleCount,
            RoutingLockedByPolicy = IsRoutingLockedByPolicy,
        };
    }

    /// <summary>
    /// Verifies the upstream is reachable and speaks SOCKS5.
    /// </summary>
    /// <remarks>
    /// Run inside the engine rather than the app, because the app's own connection to the proxy
    /// proves nothing about the engine's: they are different processes running at different
    /// integrity levels, and on Windows a per-user proxy that only the interactive session can reach
    /// is a real and common configuration.
    /// </remarks>
    public async Task<ProxyTestResult> TestProxyAsync(CancellationToken cancellationToken)
    {
        var proxy = _configuration.Proxy;

        try
        {
            var stopwatch = Stopwatch.StartNew();

            // A CONNECT to a destination that is refused still proves reachability and
            // authentication, which is what the test is for. Only a transport or auth failure is
            // reported as a failure.
            using var tunnel = await Socks5Client.ConnectAsync(
                proxy,
                Socks5Address.FromDomain("splitlane.invalid"),
                80,
                _credential,
                cancellationToken).ConfigureAwait(false);

            stopwatch.Stop();
            return new ProxyTestResult(true, stopwatch.Elapsed.TotalMilliseconds, "Proxy reachable, handshake accepted.");
        }
        catch (Socks5Exception ex) when (ex.Code == Socks5ErrorCode.RequestRejected)
        {
            // Reached it, authenticated, and it declined the deliberately bogus destination. That is
            // a healthy proxy.
            return new ProxyTestResult(true, null, $"Proxy reachable — it refused the probe destination ({ex.ReplyCode}).");
        }
        catch (Socks5Exception ex)
        {
            _lastError = ex.Message;
            return new ProxyTestResult(false, null, ex.Message);
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            return new ProxyTestResult(false, null, ex.Message);
        }
    }

    /// <summary>Turns DIRECT-decision logging on or off without a configuration round-trip.</summary>
    public void SetDirectFlowLogging(bool enabled)
    {
        lock (_applyGate)
        {
            // Keeps the rules list itself, so a migration running meanwhile is not discarded for it.
            ApplyLocked(_userConfiguration with { LogsDirectFlows = enabled });
        }

        SplitLaneLog.MinimumLevel = enabled || _options.Verbose ? LogLevel.Debug : LogLevel.Info;
    }

    /// <summary>Zeroes the counters and empties the Activity ring.</summary>
    public void ResetStatistics() => _statistics.Reset();

    /// <summary>Recent connections, newest first.</summary>
    public IReadOnlyList<ConnectionEvent> Activity(int limit) => _statistics.RecentActivity(limit);

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        await StopAsync().ConfigureAwait(false);
        await _images.DisposeAsync().ConfigureAwait(false);
        _policyStore?.Dispose();
        _updates.Dispose();
        _lifecycle.Dispose();
    }
}
