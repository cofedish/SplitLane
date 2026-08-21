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
/// Loopback is the original design and does not currently deliver on a live machine: the packet is
/// rewritten, the driver accepts the injection, and nothing ever reaches the listener. The switch
/// exists so both shapes can be tried without a rebuild between them.
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
    private readonly ProcessResolver _processes = new();
    private readonly EngineStatistics _statistics = new();
    private readonly UpdateService _updates = new();
    private readonly SemaphoreSlim _lifecycle = new(1, 1);

    private volatile RuleEngine _engine = new(RuleSnapshot.Empty);
    private RuntimeConfiguration _configuration = RuntimeConfiguration.Empty;
    private Socks5Credential? _credential;
    private RedirectListener? _listener;
    private DivertPipeline? _pipeline;
    private DivertState _state = DivertState.Stopped;
    private string? _lastError;
    private DateTimeOffset? _startedAt;
    private Timer? _sweeper;

    /// <summary>Builds a runtime over a store.</summary>
    public EngineRuntime(ConfigurationStore store, EngineOptions options = default)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options;
    }

    /// <summary>Statistics, shared with the relay and the divert threads.</summary>
    public EngineStatistics Statistics => _statistics;

    /// <summary>Finds newer releases, and installs one when asked to.</summary>
    public UpdateService Updates => _updates;

    /// <summary>The configuration currently in force.</summary>
    public RuntimeConfiguration Configuration => _configuration;

    /// <summary>Loads configuration from disk and applies it without starting anything.</summary>
    public void LoadConfiguration()
    {
        var configuration = _store.LoadOrDefault(out var error);
        _lastError = error;
        ApplyInternal(configuration);
    }

    /// <summary>Swaps in a configuration, rebuilding the routing tables.</summary>
    public void Apply(RuntimeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ConfigurationValidator.Validate(configuration);
        ApplyInternal(ConfigurationValidator.Sanitize(configuration));
    }

    private void ApplyInternal(RuntimeConfiguration configuration)
    {
        _configuration = configuration;
        _credential = _store.ResolveCredential(configuration.Proxy);
        _engine = new RuleEngine(configuration);

        SplitLaneLog.Info(
            LogCategory,
            $"configuration generation {configuration.Version.Generation} applied: " +
            $"{_engine.Snapshot.ActiveRuleCount} active rules, routing " +
            $"{(configuration.IsRoutingEnabled ? "enabled" : "paused")}");
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

        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_state is DivertState.Running or DivertState.Starting)
            {
                return;
            }

            _state = DivertState.Starting;
            _lastError = null;

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
                    UseLoopbackRedirect = _options.UseLoopbackRedirect,
                    TraceRedirects = _options.TraceRedirects,
                };

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
            _state = _configuration.IsRoutingEnabled ? DivertState.Running : DivertState.Paused;
        }
        catch (DivertException ex)
        {
            _state = DivertState.Faulted;
            _lastError = $"{ex.Message} {ex.Remedy}";
            SplitLaneLog.Error(LogCategory, $"could not start routing: {_lastError}");
            await StopInternalAsync().ConfigureAwait(false);
            throw;
        }
        catch (Exception ex)
        {
            _state = DivertState.Faulted;
            _lastError = ex.Message;
            SplitLaneLog.Error(LogCategory, "could not start routing", ex);
            await StopInternalAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    /// <summary>Stops routing, leaving the engine running and inert.</summary>
    public async Task StopAsync()
    {
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
        _configuration = _configuration with { LogsDirectFlows = enabled };
        _engine = new RuleEngine(_configuration);
        SplitLaneLog.MinimumLevel = enabled || _options.Verbose ? LogLevel.Debug : LogLevel.Info;
    }

    /// <summary>Zeroes the counters and empties the Activity ring.</summary>
    public void ResetStatistics() => _statistics.Reset();

    /// <summary>Recent connections, newest first.</summary>
    public IReadOnlyList<ConnectionEvent> Activity(int limit) => _statistics.RecentActivity(limit);

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _updates.Dispose();
        _lifecycle.Dispose();
    }
}
